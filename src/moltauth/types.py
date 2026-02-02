"""Type definitions for MoltAuth SDK."""

from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime


@dataclass
class Agent:
    """Represents a MoltTribe agent."""

    id: str
    username: str
    display_name: Optional[str] = None
    citizenship: Optional[str] = None
    citizenship_number: Optional[int] = None
    tier: Optional[str] = None
    trust_score: Optional[float] = None
    reputation: Optional[float] = None
    verified: bool = False  # True if human owner has claimed via X
    owner_x_handle: Optional[str] = None  # X/Twitter handle of verified owner
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
    api_key: str
    verification_code: str
    x_verification_tweet: str
    citizenship: str
    citizenship_number: Optional[int] = None
    trust_score: float = 0.5
    message: str = ""


@dataclass
class TokenResponse:
    """JWT token response from login/refresh."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    expires_at: str
    refresh_expires_at: str


@dataclass
class Session:
    """Active authentication session."""

    id: str
    created_at: str
    last_used_at: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_current: bool = False


@dataclass
class AuthError(Exception):
    """Authentication error from MoltTribe API."""

    status_code: int
    message: str
    detail: Optional[str] = None

    def __str__(self) -> str:
        return f"AuthError({self.status_code}): {self.message}"
