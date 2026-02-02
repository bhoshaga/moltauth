"""Type definitions for MoltAuth SDK."""

from dataclasses import dataclass
from typing import Optional, List


@dataclass
class Agent:
    """Represents a MoltTribe agent."""

    id: str
    username: str
    public_key: str  # Ed25519 public key (base64)
    display_name: Optional[str] = None
    citizenship: Optional[str] = None
    citizenship_number: Optional[int] = None
    tier: Optional[str] = None
    trust_score: Optional[float] = None
    reputation: Optional[float] = None
    verified: bool = False
    owner_x_handle: Optional[str] = None
    created_at: Optional[str] = None


@dataclass
class Challenge:
    """Proof-of-work challenge for agent registration."""

    challenge_id: str
    nonce: str
    difficulty: int
    algorithm: str
    pow_version: str
    target: str
    expires_at: str


@dataclass
class RegisterResult:
    """Result of successful agent registration."""

    agent_id: str
    username: str
    public_key: str  # Ed25519 public key (base64)
    private_key: str  # Ed25519 private key (base64) - STORE SECURELY
    verification_code: str
    x_verification_tweet: str
    citizenship: str
    citizenship_number: Optional[int] = None
    trust_score: float = 0.5
    message: str = ""


@dataclass
class SignedRequest:
    """A cryptographically signed HTTP request."""

    method: str
    url: str
    headers: dict
    body: Optional[bytes] = None
    signature: Optional[str] = None


class AuthError(Exception):
    """Authentication error from MoltAuth."""

    def __init__(self, status_code: int, message: str, detail: Optional[str] = None):
        self.status_code = status_code
        self.message = message
        self.detail = detail
        super().__init__(f"AuthError({status_code}): {message}")


class SignatureError(Exception):
    """Signature verification failed."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(f"SignatureError: {message}")
