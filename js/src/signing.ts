/**
 * HTTP Signatures implementation using Ed25519.
 *
 * Implements RFC 9421 (HTTP Message Signatures) with Ed25519.
 */

import { createHash, sign, verify, generateKeyPairSync, KeyObject } from 'crypto';
import { SignatureError } from './types';

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
  body?: Buffer
): SignatureComponents {
  const parsedUrl = new URL(url);
  const now = new Date();

  // Ensure required headers exist
  headers = { ...headers };

  if (!Object.keys(headers).find((k) => k.toLowerCase() === 'host')) {
    headers['Host'] = parsedUrl.host;
  }

  if (!Object.keys(headers).find((k) => k.toLowerCase() === 'date')) {
    headers['Date'] = now.toUTCString();
  }

  const created = Math.floor(now.getTime() / 1000);

  // Add content-digest for requests with body
  if (body && body.length > 0) {
    const digest = createHash('sha256').update(body).digest('base64');
    headers['Content-Digest'] = `sha-256=:${digest}:`;
  }

  // Components to sign
  const components = ['@method', '@target-uri', '@authority', 'date'];
  if (body && body.length > 0) {
    components.push('content-digest');
  }

  // Normalize header keys for lookup
  const headerLookup: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    headerLookup[key.toLowerCase()] = value;
  }

  // Build signature base
  const lines: string[] = [];
  for (const component of components) {
    if (component === '@method') {
      lines.push(`"@method": ${method.toUpperCase()}`);
    } else if (component === '@target-uri') {
      lines.push(`"@target-uri": ${url}`);
    } else if (component === '@authority') {
      lines.push(`"@authority": ${parsedUrl.host}`);
    } else if (component === 'date') {
      lines.push(`"date": ${headerLookup['date'] || ''}`);
    } else if (component === 'content-digest') {
      lines.push(`"content-digest": ${headerLookup['content-digest'] || ''}`);
    }
  }

  // Add signature params
  const componentsStr = components.map((c) => `"${c}"`).join(' ');
  lines.push(`"@signature-params": (${componentsStr});created=${created};alg="ed25519"`);

  const signatureBase = lines.join('\n');
  const signatureParams = `(${componentsStr});created=${created};alg="ed25519"`;

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
  keyId: string
): Record<string, string> {
  const { signatureBase, signatureParams, headers: updatedHeaders } = createSignatureBase(
    method,
    url,
    headers,
    body
  );

  // Sign the base string
  const signature = sign(null, Buffer.from(signatureBase), privateKey);
  const signatureBase64 = signature.toString('base64');

  // Build signature headers (RFC 9421)
  updatedHeaders['Signature-Input'] = `sig1=${signatureParams}`;
  updatedHeaders['Signature'] = `sig1=:${signatureBase64}:`;
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
  maxAgeSeconds: number = 300
): boolean {
  // Normalize header keys
  const headerLookup: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    headerLookup[key.toLowerCase()] = value;
  }

  const sigInput = headerLookup['signature-input'] || '';
  const sigHeader = headerLookup['signature'] || '';

  if (!sigInput || !sigHeader) {
    throw new SignatureError('Missing Signature or Signature-Input header');
  }

  // Parse signature
  if (!sigHeader.startsWith('sig1=:') || !sigHeader.endsWith(':')) {
    throw new SignatureError('Invalid Signature header format');
  }

  const signatureBase64 = sigHeader.slice(6, -1); // Remove "sig1=:" and ":"
  let signatureBytes: Buffer;

  try {
    signatureBytes = Buffer.from(signatureBase64, 'base64');
  } catch {
    throw new SignatureError('Invalid signature encoding');
  }

  // Parse created time
  const createdMatch = sigInput.match(/created=(\d+)/);
  if (!createdMatch) {
    throw new SignatureError('Missing created timestamp');
  }

  const created = parseInt(createdMatch[1], 10);
  const now = Math.floor(Date.now() / 1000);

  // Check signature age
  if (now - created > maxAgeSeconds) {
    throw new SignatureError(
      `Signature expired (age: ${now - created}s, max: ${maxAgeSeconds}s)`
    );
  }

  if (created > now + 60) {
    throw new SignatureError('Signature created in the future');
  }

  // Reconstruct signature base
  const { signatureBase } = createSignatureBase(method, url, headers, body);

  // Verify
  try {
    const isValid = verify(null, Buffer.from(signatureBase), publicKey, signatureBytes);
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
