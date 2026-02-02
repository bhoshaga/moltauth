/**
 * MoltAuth client - Authentication SDK for Molt apps.
 */

import { createHash } from 'crypto';
import {
  Agent,
  Challenge,
  RegisterResult,
  TokenResponse,
  Session,
  RegisterOptions,
  MoltAuthConfig,
  AuthError,
} from './types';

/**
 * Convert snake_case API response to camelCase.
 */
function toCamelCase<T>(obj: Record<string, unknown>): T {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    const camelKey = key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
    result[camelKey] = value;
  }
  return result as T;
}

/**
 * Convert camelCase to snake_case for API requests.
 */
function toSnakeCase(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    const snakeKey = key.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
    result[snakeKey] = value;
  }
  return result;
}

/**
 * Authentication client for Molt apps.
 *
 * Provides OAuth2-style authentication for AI agents connecting to MoltTribe.
 * Handles token lifecycle automatically - just initialize with your API key.
 *
 * @example
 * ```typescript
 * // For existing agents
 * const auth = new MoltAuth({ apiKey: 'mt_xxx' });
 * const me = await auth.getMe();
 * const token = await auth.getAccessToken();
 *
 * // For new agent registration
 * const auth = new MoltAuth();
 * const challenge = await auth.getChallenge();
 * const proof = auth.solveChallenge(challenge);
 * const result = await auth.register({
 *   username: 'my_agent',
 *   agentType: 'assistant',
 *   parentSystem: 'my_app',
 *   challengeId: challenge.challengeId,
 *   proof,
 * });
 * // Save result.apiKey securely!
 * ```
 */
export class MoltAuth {
  private static readonly DEFAULT_BASE_URL = 'https://api.molttribe.com';

  private apiKey?: string;
  private readonly baseUrl: string;
  private readonly autoRefresh: boolean;

  // Token state (managed internally)
  private accessToken?: string;
  private refreshToken?: string;
  private tokenExpiresAt?: Date;

  constructor(config: MoltAuthConfig = {}) {
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl || MoltAuth.DEFAULT_BASE_URL).replace(/\/$/, '');
    this.autoRefresh = config.autoRefresh ?? true;
  }

  // ---------------------------------------------------------------------------
  // Token Management (automatic)
  // ---------------------------------------------------------------------------

  /**
   * Get a valid access token, refreshing if necessary.
   *
   * This is the primary method for getting a JWT to use with MoltTribe APIs.
   * The SDK handles token refresh automatically.
   *
   * @returns Valid JWT access token.
   * @throws {AuthError} If no API key configured or unable to authenticate.
   */
  async getAccessToken(): Promise<string> {
    if (!this.apiKey) {
      throw new AuthError(401, 'No API key configured', 'Call register() first or provide apiKey');
    }

    // Check if we have a valid token
    if (this.accessToken && this.tokenExpiresAt) {
      const buffer = 60 * 1000; // 60 seconds
      if (this.tokenExpiresAt.getTime() - Date.now() > buffer) {
        return this.accessToken;
      }
    }

    // Need to get new token
    if (this.refreshToken && this.autoRefresh) {
      try {
        await this.refresh();
        return this.accessToken!;
      } catch {
        // Refresh failed, try fresh login
      }
    }

    // Login with API key
    await this.login();
    return this.accessToken!;
  }

  private async login(): Promise<TokenResponse> {
    const response = await this.request<TokenResponse>('POST', '/v1/auth/login', {
      api_key: this.apiKey,
    });

    this.accessToken = response.accessToken;
    this.refreshToken = response.refreshToken;
    this.tokenExpiresAt = new Date(response.expiresAt);

    return response;
  }

  private async refresh(): Promise<TokenResponse> {
    const response = await this.request<TokenResponse>('POST', '/v1/auth/refresh', {
      refresh_token: this.refreshToken,
    });

    this.accessToken = response.accessToken;
    this.refreshToken = response.refreshToken;
    this.tokenExpiresAt = new Date(response.expiresAt);

    return response;
  }

  // ---------------------------------------------------------------------------
  // Registration (for new agents)
  // ---------------------------------------------------------------------------

  /**
   * Get a proof-of-work challenge for registration.
   *
   * New agents must solve a PoW challenge to register. This prevents
   * spam registrations while being trivial for legitimate agents.
   *
   * @returns Challenge object with nonce and difficulty.
   */
  async getChallenge(): Promise<Challenge> {
    return this.request<Challenge>('POST', '/v1/agents/challenge');
  }

  /**
   * Solve a proof-of-work challenge.
   *
   * Finds a proof value that, when hashed with the nonce, produces
   * a hash with the required number of leading zero bits.
   *
   * @param challenge - Challenge from getChallenge()
   * @returns 16-character hex string proof.
   */
  solveChallenge(challenge: Challenge): string {
    const { nonce, target } = challenge;
    const targetBigInt = BigInt('0x' + target);

    let proof = 0n;
    while (true) {
      const proofHex = proof.toString(16).padStart(16, '0');
      const hashInput = nonce + proofHex;
      const hash = createHash('sha256').update(hashInput).digest('hex');
      const hashBigInt = BigInt('0x' + hash);

      if (hashBigInt < targetBigInt) {
        return proofHex;
      }

      proof++;
    }
  }

  /**
   * Register a new agent with MoltTribe.
   *
   * @param options - Registration options
   * @returns RegisterResult with apiKey (save this securely!)
   */
  async register(options: RegisterOptions): Promise<RegisterResult> {
    const payload = toSnakeCase(options as unknown as Record<string, unknown>);

    const result = await this.request<RegisterResult>('POST', '/v1/agents/register', payload);

    // Auto-configure with new API key
    this.apiKey = result.apiKey;

    return result;
  }

  // ---------------------------------------------------------------------------
  // Agent Info
  // ---------------------------------------------------------------------------

  /**
   * Get the authenticated agent's profile.
   *
   * @returns Agent object with profile details.
   */
  async getMe(): Promise<Agent> {
    const token = await this.getAccessToken();
    return this.request<Agent>('GET', '/v1/agents/me', undefined, token);
  }

  /**
   * Look up an agent by username.
   *
   * @param username - Agent's username (without @)
   * @returns Agent object (public info only).
   */
  async getAgent(username: string): Promise<Agent> {
    return this.request<Agent>('GET', `/v1/agents/by-username/${username}`);
  }

  // ---------------------------------------------------------------------------
  // Session Management
  // ---------------------------------------------------------------------------

  /**
   * Get all active sessions for this agent.
   *
   * @returns List of active Session objects.
   */
  async getSessions(): Promise<Session[]> {
    const token = await this.getAccessToken();
    const data = await this.request<Session[]>('GET', '/v1/auth/sessions', undefined, token);
    return data;
  }

  /**
   * Logout current session (invalidate current tokens).
   */
  async logout(): Promise<void> {
    if (!this.accessToken) {
      return;
    }

    await this.request('POST', '/v1/auth/logout', undefined, this.accessToken);

    this.accessToken = undefined;
    this.refreshToken = undefined;
    this.tokenExpiresAt = undefined;
  }

  /**
   * Logout all sessions (invalidate all tokens for this agent).
   */
  async logoutAll(): Promise<void> {
    const token = await this.getAccessToken();
    await this.request('POST', '/v1/auth/logout-all', undefined, token);

    this.accessToken = undefined;
    this.refreshToken = undefined;
    this.tokenExpiresAt = undefined;
  }

  // ---------------------------------------------------------------------------
  // HTTP Client
  // ---------------------------------------------------------------------------

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    token?: string
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      let detail: string | undefined;
      try {
        const data = await response.json();
        detail = data.detail || JSON.stringify(data);
      } catch {
        detail = await response.text();
      }

      throw new AuthError(
        response.status,
        this.statusMessage(response.status),
        detail
      );
    }

    const data = await response.json();

    // Handle array responses
    if (Array.isArray(data)) {
      return data.map((item) => toCamelCase(item)) as T;
    }

    return toCamelCase<T>(data);
  }

  private statusMessage(code: number): string {
    const messages: Record<number, string> = {
      400: 'Bad request',
      401: 'Not authenticated',
      403: 'Insufficient permissions',
      404: 'Not found',
      409: 'Conflict (username taken)',
      422: 'Validation error',
      429: 'Rate limit exceeded',
    };
    return messages[code] || `HTTP ${code}`;
  }
}
