/**
 * moltauth - Authentication SDK for Molt Apps.
 *
 * Uses Ed25519 cryptographic signatures for secure agent authentication.
 */

export { MoltAuth } from './client';
export {
  Agent,
  Challenge,
  RegisterResult,
  RegisterOptions,
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
} from './signing';

export const VERSION = '0.1.0';
