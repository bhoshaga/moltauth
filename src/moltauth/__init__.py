"""moltauth - Authentication SDK for Molt Apps.

Uses Ed25519 cryptographic signatures for secure agent authentication.
"""

from .client import MoltAuth
from .types import (
    Agent,
    Challenge,
    RegisterResult,
    KeyRotationResult,
    SignedRequest,
    AuthError,
    SignatureError,
)
from .signing import (
    generate_keypair,
    sign_request,
    verify_signature,
    load_private_key,
    load_public_key,
    extract_key_id,
)

__version__ = "0.1.0"
__all__ = [
    # Main client
    "MoltAuth",
    # Types
    "Agent",
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
