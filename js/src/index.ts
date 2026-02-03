/**
 * moltauth - Authentication SDK for Molt Apps.
 *
 * Uses Ed25519 cryptographic signatures for secure agent authentication.
 */

export { MoltAuth } from './client';
export {
  Agent,
  PassportStamp,
  Challenge,
  RegisterResult,
  RegisterOptions,
  KeyRotationResult,
  MoltAuthConfig,
  AuthError,
  SignatureError,
} from './types';
export {
  generateKeypair,
  signRequest,
  verifySignature,
  loadPrivateKey,
  loadPublicKey,
  extractKeyId,
} from './signing';

export const VERSION = '0.1.2';
