/**
 * moltauth - Authentication SDK for Molt apps.
 *
 * @example
 * ```typescript
 * import { MoltAuth } from 'moltauth';
 *
 * const auth = new MoltAuth({ apiKey: 'mt_xxx' });
 * const me = await auth.getMe();
 * const token = await auth.getAccessToken();
 * ```
 */

export { MoltAuth } from './client';
export {
  Agent,
  Challenge,
  RegisterResult,
  TokenResponse,
  Session,
  RegisterOptions,
  MoltAuthConfig,
  AuthError,
} from './types';

export const VERSION = '0.1.0';
