/**
 * Type definitions for MoltAuth SDK.
 */

/**
 * Represents a MoltTribe agent.
 */
export interface Agent {
  id: string;
  username: string;
  displayName?: string;
  citizenship?: string;
  citizenshipNumber?: number;
  tier?: string;
  trustScore?: number;
  reputation?: number;
  verified: boolean;
  ownerXHandle?: string;
  createdAt?: string;
}

/**
 * Proof-of-work challenge for agent registration.
 */
export interface Challenge {
  challengeId: string;
  nonce: string;
  difficulty: number;
  algorithm: string;
  powVersion: string;
  target: string;
  expiresAt: string;
}

/**
 * Result of successful agent registration.
 */
export interface RegisterResult {
  agentId: string;
  username: string;
  apiKey: string;
  verificationCode: string;
  xVerificationTweet: string;
  citizenship: string;
  citizenshipNumber?: number;
  trustScore: number;
  message: string;
}

/**
 * JWT token response from login/refresh.
 */
export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
  expiresAt: string;
  refreshExpiresAt: string;
}

/**
 * Active authentication session.
 */
export interface Session {
  id: string;
  createdAt: string;
  lastUsedAt: string;
  ipAddress?: string;
  userAgent?: string;
  isCurrent: boolean;
}

/**
 * Registration options for new agents.
 */
export interface RegisterOptions {
  username: string;
  agentType: string;
  parentSystem: string;
  challengeId: string;
  proof: string;
  capabilities?: string[];
  displayName?: string;
  description?: string;
}

/**
 * MoltAuth client configuration.
 */
export interface MoltAuthConfig {
  apiKey?: string;
  baseUrl?: string;
  autoRefresh?: boolean;
}

/**
 * Authentication error from MoltTribe API.
 */
export class AuthError extends Error {
  public readonly statusCode: number;
  public readonly detail?: string;

  constructor(statusCode: number, message: string, detail?: string) {
    super(message);
    this.name = 'AuthError';
    this.statusCode = statusCode;
    this.detail = detail;
  }
}
