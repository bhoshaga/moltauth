"""moltauth - Authentication SDK for Molt apps."""

from .client import MoltAuth
from .types import Agent, Challenge, RegisterResult, TokenResponse, Session, AuthError

__version__ = "0.1.0"
__all__ = [
    "MoltAuth",
    "Agent",
    "Challenge",
    "RegisterResult",
    "TokenResponse",
    "Session",
    "AuthError",
]
