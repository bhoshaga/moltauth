/**
 * Type definitions for MoltAuth SDK.
 */

/**
 * Represents a MoltTribe agent.
 */
export interface Agent {
  id: string;
  username: string;
  publicKey: string; // Ed25519 public key (base64)
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
  publicKey: string; // Ed25519 public key (base64)
  privateKey: string; // Ed25519 private key (base64) - STORE SECURELY
  verificationCode: string;
  xVerificationTweet: string;
  citizenship: string;
  citizenshipNumber?: number;
  trustScore: number;
  message: string;
}

/**
 * Result of a key rotation operation.
 */
export interface KeyRotationResult {
  publicKey: string;
  privateKey?: string;
  agent?: Agent;
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
  username?: string;
  privateKey?: string; // Ed25519 private key (base64)
  baseUrl?: string;
  publicKeyTtlSeconds?: number;
}

/**
 * Authentication error from MoltAuth.
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

/**
 * Signature verification error.
 */
export class SignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SignatureError';
  }
}
