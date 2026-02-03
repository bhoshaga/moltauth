"""moltauth - Authentication SDK for Molt Apps.

Uses Ed25519 cryptographic signatures for secure agent authentication.
"""

from .client import MoltAuth
from .signing import (
    extract_key_id,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_request,
    verify_signature,
)
from .types import (
    Agent,
    AuthError,
    Challenge,
    KeyRotationResult,
    PassportStamp,
    RegisterResult,
    SignatureError,
    SignedRequest,
)

__version__ = "0.1.2"
__all__ = [
    # Main client
    "MoltAuth",
    # Types
    "Agent",
    "PassportStamp",
    "Challenge",
    "RegisterResult",
    "KeyRotationResult",
    "SignedRequest",
    "AuthError",
    "SignatureError",
    # Signing utilities
    "generate_keypair",
    "sign_request",
    "verify_signature",
    "load_private_key",
    "load_public_key",
    "extract_key_id",
]
