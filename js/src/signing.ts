/**
 * HTTP Signatures implementation using Ed25519.
 *
 * Implements RFC 9421 (HTTP Message Signatures) with Ed25519.
 */

import { createHash, sign, verify, generateKeyPairSync, KeyObject } from 'crypto';
import { SignatureError } from './types';

const SIGNATURE_LABEL = 'sig1';
const REQUIRED_COMPONENTS = new Set(['@method', '@target-uri', '@authority', 'date']);

function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = String(value);
  }
  return normalized;
}

function normalizeAuthority(url: URL): string {
  const hostname = url.hostname.toLowerCase();
  const scheme = url.protocol.replace(':', '').toLowerCase();
  const port = url.port ? Number.parseInt(url.port, 10) : undefined;
  const defaultPort = scheme === 'http' ? 80 : scheme === 'https' ? 443 : undefined;
  const needsPort = port !== undefined && port !== defaultPort;

  const hostValue = hostname.includes(':') ? `[${hostname}]` : hostname;
  if (needsPort) {
    return `${hostValue}:${port}`;
  }
  return hostValue;
}

function contentDigest(body: Buffer): string {
  const digest = createHash('sha256').update(body).digest('base64');
  return `sha-256=:${digest}:`;
}

function formatSignatureParams(components: string[], params: string[]): string {
  const componentsStr = components.map((c) => `"${c}"`).join(' ');
  if (params.length > 0) {
    return `(${componentsStr});${params.join(';')}`;
  }
  return `(${componentsStr})`;
}

function buildSignatureBase(
  method: string,
  url: string,
  headers: Record<string, string>,
  components: string[],
  signatureParams: string
): string {
  const parsedUrl = new URL(url);
  const headerLookup = normalizeHeaders(headers);

  const lines: string[] = [];
  for (const component of components) {
    if (component === '@method') {
      lines.push(`"@method": ${method.toUpperCase()}`);
    } else if (component === '@target-uri') {
      lines.push(`"@target-uri": ${url}`);
    } else if (component === '@authority') {
      lines.push(`"@authority": ${normalizeAuthority(parsedUrl)}`);
    } else if (component === '@scheme') {
      lines.push(`"@scheme": ${parsedUrl.protocol.replace(':', '').toLowerCase()}`);
    } else if (component === '@path') {
      lines.push(`"@path": ${parsedUrl.pathname || '/'}`);
    } else if (component === '@query') {
      lines.push(`"@query": ${parsedUrl.search ? parsedUrl.search : '?'}`);
    } else if (component.startsWith('@')) {
      throw new SignatureError(`Unsupported signature component: ${component}`);
    } else {
      const lookupKey = component.toLowerCase();
      if (!headerLookup[lookupKey]) {
        throw new SignatureError(`Missing required header for signature: ${component}`);
      }
      lines.push(`"${component}": ${headerLookup[lookupKey]}`);
    }
  }

  lines.push(`"@signature-params": ${signatureParams}`);
  return lines.join('\n');
}

function parseSignatureHeader(signatureHeader: string): { label: string; signature: Buffer } {
  const parts = signatureHeader.split(',').map((part) => part.trim()).filter(Boolean);
  for (const part of parts) {
    const match = part.match(/^([a-zA-Z0-9_-]+)=:([^:]+):$/);
    if (!match) continue;
    const [, label, signatureBase64] = match;
    try {
      return { label, signature: Buffer.from(signatureBase64, 'base64') };
    } catch {
      throw new SignatureError('Invalid signature encoding');
    }
  }
  throw new SignatureError('Invalid Signature header format');
}

function parseSignatureInput(
  signatureInput: string,
  label: string
): { components: string[]; params: string[]; created: number; alg?: string } {
  const parts = signatureInput.split(',').map((part) => part.trim()).filter(Boolean);
  const target = parts.find((part) => part.startsWith(`${label}=`));
  if (!target) {
    throw new SignatureError('Signature-Input missing matching label');
  }

  const separatorIndex = target.indexOf('=');
  const value = separatorIndex >= 0 ? target.slice(separatorIndex + 1) : '';
  if (!value.startsWith('(')) {
    throw new SignatureError('Invalid Signature-Input header format');
  }
  const closingIndex = value.indexOf(')');
  if (closingIndex === -1) {
    throw new SignatureError('Invalid Signature-Input header format');
  }

  const componentsStr = value.slice(1, closingIndex).trim();
  let paramsStr = value.slice(closingIndex + 1).trim();
  if (paramsStr.startsWith(';')) {
    paramsStr = paramsStr.slice(1);
  }

  const components = Array.from(componentsStr.matchAll(/"([^"]+)"/g)).map((m) => m[1]);
  if (components.length === 0) {
    throw new SignatureError('Signature-Input missing components');
  }

  const params = paramsStr
    ? paramsStr.split(';').map((param) => param.trim()).filter(Boolean)
    : [];
  const paramsMap: Record<string, string> = {};
  for (const param of params) {
    const [key, valuePart] = param.split('=', 2);
    paramsMap[key] = valuePart ?? '';
  }

  if (!paramsMap.created) {
    throw new SignatureError('Missing created timestamp');
  }
  const created = Number.parseInt(paramsMap.created, 10);
  if (!Number.isFinite(created)) {
    throw new SignatureError('Invalid created timestamp');
  }

  const alg = paramsMap.alg ? paramsMap.alg.replace(/"/g, '') : undefined;
  return { components, params, created, alg };
}

/**
 * Generate a new Ed25519 keypair.
 *
 * @returns Tuple of [privateKeyBase64, publicKeyBase64]
 */
export function generateKeypair(): [string, string] {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');

  const privateBytes = privateKey.export({ type: 'pkcs8', format: 'der' });
  const publicBytes = publicKey.export({ type: 'spki', format: 'der' });

  // Extract raw key bytes (skip DER headers)
  // Ed25519 private key in PKCS8: 48 bytes total, raw key starts at offset 16
  // Ed25519 public key in SPKI: 44 bytes total, raw key starts at offset 12
  const privateRaw = privateBytes.subarray(16, 48);
  const publicRaw = publicBytes.subarray(12, 44);

  return [privateRaw.toString('base64'), publicRaw.toString('base64')];
}

/**
 * Load an Ed25519 private key from base64.
 */
export function loadPrivateKey(privateKeyBase64: string): KeyObject {
  const privateRaw = Buffer.from(privateKeyBase64, 'base64');

  // Wrap raw bytes in PKCS8 DER format
  const pkcs8Header = Buffer.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8Der = Buffer.concat([pkcs8Header, privateRaw]);

  return require('crypto').createPrivateKey({
    key: pkcs8Der,
    format: 'der',
    type: 'pkcs8',
  });
}

/**
 * Load an Ed25519 public key from base64.
 */
export function loadPublicKey(publicKeyBase64: string): KeyObject {
  const publicRaw = Buffer.from(publicKeyBase64, 'base64');

  // Wrap raw bytes in SPKI DER format
  const spkiHeader = Buffer.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ]);
  const spkiDer = Buffer.concat([spkiHeader, publicRaw]);

  return require('crypto').createPublicKey({
    key: spkiDer,
    format: 'der',
    type: 'spki',
  });
}

interface SignatureComponents {
  signatureBase: string;
  signatureParams: string;
  headers: Record<string, string>;
}

/**
 * Create the signature base string and required headers.
 */
function createSignatureBase(
  method: string,
  url: string,
  headers: Record<string, string>,
  body?: Buffer,
  created?: number,
  date?: string
): SignatureComponents {
  const parsedUrl = new URL(url);
  const now = new Date();

  // Ensure required headers exist
  headers = { ...headers };
  const headerLookup = normalizeHeaders(headers);

  if (!headerLookup.host) {
    headers['Host'] = parsedUrl.host;
    headerLookup.host = parsedUrl.host;
  }

  if (!headerLookup.date) {
    headers['Date'] = date ?? now.toUTCString();
    headerLookup.date = headers['Date'];
  }

  const createdTimestamp = created ?? Math.floor(now.getTime() / 1000);

  const components = ['@method', '@target-uri', '@authority', 'date'];
  if (body && body.length > 0) {
    headers['Content-Digest'] = contentDigest(body);
    components.push('content-digest');
  }

  const signatureParams = formatSignatureParams(components, [
    `created=${createdTimestamp}`,
    'alg="ed25519"',
  ]);
  const signatureBase = buildSignatureBase(method, url, headers, components, signatureParams);

  return { signatureBase, signatureParams, headers };
}

/**
 * Sign an HTTP request.
 */
export function signRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: Buffer | undefined,
  privateKey: KeyObject,
  keyId: string,
  created?: number,
  date?: string
): Record<string, string> {
  const { signatureBase, signatureParams, headers: updatedHeaders } = createSignatureBase(
    method,
    url,
    headers,
    body,
    created,
    date
  );

  // Sign the base string
  const signature = sign(null, Buffer.from(signatureBase), privateKey);
  const signatureBase64 = signature.toString('base64');

  // Build signature headers (RFC 9421)
  updatedHeaders['Signature-Input'] = `${SIGNATURE_LABEL}=${signatureParams}`;
  updatedHeaders['Signature'] = `${SIGNATURE_LABEL}=:${signatureBase64}:`;
  updatedHeaders['X-MoltAuth-Key-Id'] = keyId;

  return updatedHeaders;
}

/**
 * Verify an HTTP request signature.
 */
export function verifySignature(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: Buffer | undefined,
  publicKey: KeyObject,
  maxAgeSeconds: number | null = 300,
  maxClockSkewSeconds: number | null = 60,
  requiredComponents: string[] = Array.from(REQUIRED_COMPONENTS),
  requireContentDigest: boolean = true
): boolean {
  const headerLookup = normalizeHeaders(headers);

  const sigInput = headerLookup['signature-input'] || '';
  const sigHeader = headerLookup['signature'] || '';

  if (!sigInput || !sigHeader) {
    throw new SignatureError('Missing Signature or Signature-Input header');
  }

  const { label, signature } = parseSignatureHeader(sigHeader);
  const { components, params, created, alg } = parseSignatureInput(sigInput, label);

  if (alg && alg !== 'ed25519') {
    throw new SignatureError(`Unsupported signature algorithm: ${alg}`);
  }

  const now = Math.floor(Date.now() / 1000);

  // Check signature age
  if (maxAgeSeconds !== null && maxAgeSeconds !== undefined && now - created > maxAgeSeconds) {
    throw new SignatureError(
      `Signature expired (age: ${now - created}s, max: ${maxAgeSeconds}s)`
    );
  }

  if (
    maxClockSkewSeconds !== null &&
    maxClockSkewSeconds !== undefined &&
    created > now + maxClockSkewSeconds
  ) {
    throw new SignatureError('Signature created in the future');
  }

  if (requiredComponents && requiredComponents.length > 0) {
    const missing = requiredComponents.filter((c) => !components.includes(c));
    if (missing.length > 0) {
      throw new SignatureError(`Signature missing required components: ${missing.join(', ')}`);
    }
  }

  if (requireContentDigest && body && body.length > 0 && !components.includes('content-digest')) {
    throw new SignatureError('Missing content-digest signature component for request body');
  }

  if (components.includes('content-digest')) {
    const digestHeader = headerLookup['content-digest'];
    if (!digestHeader) {
      throw new SignatureError('Missing Content-Digest header');
    }
    const bodyBytes = body ?? Buffer.alloc(0);
    const expectedDigest = contentDigest(bodyBytes);
    if (digestHeader !== expectedDigest) {
      throw new SignatureError('Content-Digest mismatch');
    }
  }

  const signatureParams = formatSignatureParams(components, params);
  const signatureBase = buildSignatureBase(method, url, headers, components, signatureParams);

  // Verify
  try {
    const isValid = verify(null, Buffer.from(signatureBase), publicKey, signature);
    if (!isValid) {
      throw new SignatureError('Signature verification failed');
    }
    return true;
  } catch (e) {
    if (e instanceof SignatureError) throw e;
    throw new SignatureError('Signature verification failed');
  }
}

/**
 * Extract the key ID (agent username) from request headers.
 */
export function extractKeyId(headers: Record<string, string>): string | undefined {
  const headerLookup: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    headerLookup[key.toLowerCase()] = value;
  }
  return headerLookup['x-moltauth-key-id'];
}
