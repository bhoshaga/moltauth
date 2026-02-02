import { readFileSync } from 'fs';
import { resolve } from 'path';
import { createPublicKey } from 'crypto';
import { describe, it, expect } from 'vitest';

import { loadPrivateKey, loadPublicKey, signRequest, verifySignature } from '../src/signing';

type Vector = {
  id: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  signature_input: string;
  signature: string;
  public_key_pem?: string;
  public_key_b64?: string;
  private_key_b64?: string;
  key_id?: string;
  created?: number;
};

const vectorsDir = resolve(__dirname, '../../test_vectors');
const loadVector = (name: string): Vector => {
  const raw = readFileSync(resolve(vectorsDir, name), 'utf8');
  return JSON.parse(raw) as Vector;
};

describe('RFC 9421 vectors', () => {
  it('verifies RFC 9421 ed25519 vector', () => {
    const vector = loadVector('rfc9421_b26.json');
    const headers: Record<string, string> = {
      ...vector.headers,
      'Signature-Input': vector.signature_input,
      Signature: vector.signature,
    };

    const publicKey = createPublicKey(vector.public_key_pem as string);
    const body = Buffer.from(vector.body);

    expect(() =>
      verifySignature(
        vector.method,
        vector.url,
        headers,
        body,
        publicKey,
        null,
        null,
        ['date', '@method', '@path', '@authority', 'content-type', 'content-length'],
        false
      )
    ).not.toThrow();
  });
});

describe('Interop vectors', () => {
  it('signs and verifies the interop vector deterministically', () => {
    const vector = loadVector('interop_v1.json');
    const headers: Record<string, string> = { ...vector.headers };
    const body = Buffer.from(vector.body);

    const privateKey = loadPrivateKey(vector.private_key_b64 as string);
    const signedHeaders = signRequest(
      vector.method,
      vector.url,
      headers,
      body,
      privateKey,
      vector.key_id as string,
      vector.created
    );

    expect(signedHeaders['Signature-Input']).toBe(vector.signature_input);
    expect(signedHeaders['Signature']).toBe(vector.signature);

    const publicKey = loadPublicKey(vector.public_key_b64 as string);
    expect(
      verifySignature(
        vector.method,
        vector.url,
        signedHeaders,
        body,
        publicKey,
        null,
        null
      )
    ).toBe(true);
  });
});
