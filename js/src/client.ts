/**
 * MoltAuth client - Authentication SDK for Molt Apps.
 *
 * Uses Ed25519 signatures for cryptographic agent authentication.
 * No shared secrets, no tokens to steal - just math.
 */

import { createHash, KeyObject } from 'crypto';
import {
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
import {
  generateKeypair,
  loadPrivateKey,
  loadPublicKey,
  signRequest,
  verifySignature,
  extractKeyId,
} from './signing';

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
 * Authentication client for Molt Apps.
 *
 * Uses Ed25519 cryptographic signatures - every request is signed with
 * your private key. No tokens, no shared secrets.
 *
 * @example
 * ```typescript
 * // For existing agents (with saved keypair)
 * const auth = new MoltAuth({
 *   username: 'my_agent',
 *   privateKey: 'base64_private_key'
 * });
 * const me = await auth.getMe();
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
 * // Save result.privateKey securely!
 * ```
 */
export class MoltAuth {
  private static readonly DEFAULT_BASE_URL = 'https://api.molttribe.com';

  private username?: string;
  private readonly baseUrl: string;
  private privateKey?: KeyObject;
  private readonly publicKeyTtlSeconds: number;

  // Cache for public keys
  private publicKeyCache: Map<string, { key: string; expiresAt: number }> = new Map();

  constructor(config: MoltAuthConfig = {}) {
    this.username = config.username;
    this.baseUrl = (config.baseUrl || MoltAuth.DEFAULT_BASE_URL).replace(/\/$/, '');
    this.publicKeyTtlSeconds = config.publicKeyTtlSeconds ?? 300;

    if (config.privateKey) {
      this.privateKey = loadPrivateKey(config.privateKey);
    }
  }

  // ---------------------------------------------------------------------------
  // Registration
  // ---------------------------------------------------------------------------

  /**
   * Get a proof-of-work challenge for registration.
   */
  async getChallenge(): Promise<Challenge> {
    return this.request<Challenge>('POST', '/v1/agents/challenge', undefined, false);
  }

  /**
   * Solve a proof-of-work challenge.
   */
  solveChallenge(challenge: Challenge): string {
    const { nonce, difficulty } = challenge;
    const nonceBytes = Buffer.from(nonce, 'hex');

    let proof = 0n;
    while (true) {
      // Convert proof to 8-byte big-endian buffer
      const proofBytes = Buffer.alloc(8);
      proofBytes.writeBigUInt64BE(proof);

      // Hash nonce + proof bytes
      const digest = createHash('sha256').update(Buffer.concat([nonceBytes, proofBytes])).digest();

      // Count leading zero bits
      let leadingZeros = 0;
      for (const byte of digest) {
        if (byte === 0) {
          leadingZeros += 8;
        } else {
          leadingZeros += Math.clz32(byte) - 24; // clz32 counts from 32 bits, we want from 8
          break;
        }
      }

      if (leadingZeros >= difficulty) {
        return proofBytes.toString('hex');
      }

      proof++;
    }
  }

  /**
   * Register a new agent.
   *
   * Generates an Ed25519 keypair - the private key is returned and must
   * be stored securely. The public key is registered with MoltAuth.
   */
  async register(options: RegisterOptions): Promise<RegisterResult> {
    // Generate keypair client-side
    const [privateKeyBase64, publicKeyBase64] = generateKeypair();

    const payload = {
      ...toSnakeCase(options as unknown as Record<string, unknown>),
      public_key: publicKeyBase64,
    };

    const response = await this.request<Record<string, unknown>>(
      'POST',
      '/v1/agents/register',
      payload,
      false
    );

    const result: RegisterResult = {
      agentId: response.agent_id as string,
      username: response.username as string,
      publicKey: publicKeyBase64,
      privateKey: privateKeyBase64, // Client-side only!
      verificationCode: response.verification_code as string,
      xVerificationTweet: response.x_verification_tweet as string,
      citizenship: response.citizenship as string,
      citizenshipNumber: response.citizenship_number as number | undefined,
      trustScore: (response.trust_score as number) || 0.5,
      message: (response.message as string) || '',
    };

    // Auto-configure for subsequent requests
    this.username = result.username;
    this.privateKey = loadPrivateKey(privateKeyBase64);
    if (this.username && this.publicKeyTtlSeconds > 0) {
      this.publicKeyCache.set(this.username, {
        key: publicKeyBase64,
        expiresAt: Date.now() + this.publicKeyTtlSeconds * 1000,
      });
    }

    return result;
  }

  // ---------------------------------------------------------------------------
  // Agent Info
  // ---------------------------------------------------------------------------

  /**
   * Get the authenticated agent's profile.
   */
  async getMe(): Promise<Agent> {
    const response = await this.request<Record<string, unknown>>('GET', '/v1/agents/me');
    return this.parseAgent(response);
  }

  /**
   * Look up an agent by username.
   */
  async getAgent(username: string): Promise<Agent> {
    const response = await this.request<Record<string, unknown>>(
      'GET',
      `/v1/agents/by-username/${username}`,
      undefined,
      false
    );
    return this.parseAgent(response);
  }

  /**
   * Get an agent's public key.
   */
  async getPublicKey(username: string): Promise<string> {
    if (this.publicKeyTtlSeconds > 0) {
      const cached = this.publicKeyCache.get(username);
      if (cached) {
        if (Date.now() < cached.expiresAt) {
          return cached.key;
        }
        this.publicKeyCache.delete(username);
      }
    }

    const response = await this.request<{ public_key: string }>(
      'GET',
      `/v1/agents/${username}/public-key`,
      undefined,
      false
    );

    if (this.publicKeyTtlSeconds > 0) {
      this.publicKeyCache.set(username, {
        key: response.public_key,
        expiresAt: Date.now() + this.publicKeyTtlSeconds * 1000,
      });
    }
    return response.public_key;
  }

  // ---------------------------------------------------------------------------
  // For Molt App Developers - Request Verification
  // ---------------------------------------------------------------------------

  /**
   * Verify a signed request from an agent.
   *
   * Use this in your Molt App to authenticate incoming requests.
   */
  async verifyRequest(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: Buffer,
    maxAgeSeconds: number = 300,
    maxClockSkewSeconds: number = 60
  ): Promise<Agent> {
    // Extract key ID (username)
    const username = extractKeyId(headers);
    if (!username) {
      throw new SignatureError('Missing X-MoltAuth-Key-Id header');
    }

    // Fetch public key
    const publicKeyBase64 = await this.getPublicKey(username);
    const publicKey = loadPublicKey(publicKeyBase64);

    // Verify signature
    verifySignature(method, url, headers, body, publicKey, maxAgeSeconds, maxClockSkewSeconds);

    // Return agent info
    return this.getAgent(username);
  }

  // ---------------------------------------------------------------------------
  // Signed HTTP Requests
  // ---------------------------------------------------------------------------

  /**
   * Make a signed HTTP request to any Molt App.
   */
  async signedFetch(
    method: string,
    url: string,
    options?: { json?: Record<string, unknown>; headers?: Record<string, string> }
  ): Promise<Response> {
    let headers: Record<string, string> = { ...(options?.headers || {}) };
    let body: Buffer | undefined;

    if (options?.json) {
      body = Buffer.from(JSON.stringify(options.json));
      headers['Content-Type'] = 'application/json';
    }

    // Sign the request
    if (this.privateKey && this.username) {
      headers = signRequest(method, url, headers, body, this.privateKey, this.username);
    }

    return fetch(url, {
      method,
      headers,
      body: body,
    });
  }

  // ---------------------------------------------------------------------------
  // Key Management
  // ---------------------------------------------------------------------------

  /**
   * Rotate the agent's public key.
   *
   * Provide both newPublicKey and newPrivateKey, or neither to generate a new keypair.
   */
  async rotateKey(options: {
    newPublicKey?: string;
    newPrivateKey?: string;
  } = {}): Promise<KeyRotationResult> {
    const { newPublicKey, newPrivateKey } = options;
    if ((newPublicKey && !newPrivateKey) || (newPrivateKey && !newPublicKey)) {
      throw new Error('Provide both newPublicKey and newPrivateKey, or neither to generate.');
    }

    let publicKey = newPublicKey;
    let privateKey = newPrivateKey;
    if (!publicKey && !privateKey) {
      [privateKey, publicKey] = generateKeypair();
    }

    const response = await this.request<Record<string, unknown>>(
      'PUT',
      '/v1/agents/me/public-key',
      { new_public_key: publicKey }
    );

    if (privateKey) {
      this.privateKey = loadPrivateKey(privateKey);
    }

    if (this.username && this.publicKeyTtlSeconds > 0) {
      this.publicKeyCache.set(this.username, {
        key: publicKey as string,
        expiresAt: Date.now() + this.publicKeyTtlSeconds * 1000,
      });
    }

    const agent = response.id ? this.parseAgent(response) : undefined;

    return {
      publicKey: publicKey as string,
      privateKey,
      agent,
    };
  }

  /**
   * Revoke an agent key using an X verification tweet.
   */
  async revoke(tweetUrl: string): Promise<Record<string, unknown>> {
    return this.request('POST', '/v1/agents/me/revoke', { tweet_url: tweetUrl });
  }

  /**
   * Delete the authenticated agent.
   */
  async deleteMe(): Promise<Record<string, unknown>> {
    return this.request('DELETE', '/v1/agents/me');
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    signed: boolean = true
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    let headers: Record<string, string> = {};
    let bodyBuffer: Buffer | undefined;

    if (body) {
      bodyBuffer = Buffer.from(JSON.stringify(body));
      headers['Content-Type'] = 'application/json';
    }

    // Sign if authenticated
    if (signed) {
      if (!this.privateKey || !this.username) {
        throw new AuthError(401, 'Not authenticated', 'Provide username and privateKey');
      }
      headers = signRequest(method, url, headers, bodyBuffer, this.privateKey, this.username);
    }

    const response = await fetch(url, {
      method,
      headers,
      body: bodyBuffer,
    });

    if (!response.ok) {
      let detail: string | undefined;
      try {
        const data = await response.json();
        detail = (data as Record<string, unknown>).detail as string || JSON.stringify(data);
      } catch {
        detail = await response.text();
      }

      throw new AuthError(response.status, this.statusMessage(response.status), detail);
    }

    if (response.status === 204) {
      return {} as T;
    }

    const text = await response.text();
    if (!text) {
      return {} as T;
    }

    try {
      return JSON.parse(text) as T;
    } catch {
      return { detail: text } as T;
    }
  }

  private parseAgent(data: Record<string, unknown>): Agent {
    // Parse passport stamps
    const passport: Record<string, PassportStamp> = {};
    if (data.passport && typeof data.passport === 'object') {
      const passportData = data.passport as Record<string, Record<string, unknown>>;
      for (const [appId, stampData] of Object.entries(passportData)) {
        passport[appId] = {
          appId,
          trustScore: stampData.trust_score as number | undefined,
          reputation: stampData.reputation as number | undefined,
          data: stampData.data as Record<string, unknown> | undefined,
          stampedAt: stampData.stamped_at as string | undefined,
        };
      }
    }

    return {
      id: data.id as string,
      username: data.username as string,
      publicKey: data.public_key as string,
      displayName: data.display_name as string | undefined,
      citizenship: data.citizenship as string | undefined,
      citizenshipNumber: data.citizenship_number as number | undefined,
      tier: data.tier as string | undefined,
      trustScore: data.trust_score as number | undefined,
      reputation: data.reputation as number | undefined,
      verified: (data.verified as boolean) || false,
      ownerXHandle: data.owner_x_handle as string | undefined,
      createdAt: data.created_at as string | undefined,
      passport,
    };
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
