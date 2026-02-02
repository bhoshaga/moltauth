"""HTTP Signatures implementation using Ed25519.

Implements RFC 9421 (HTTP Message Signatures) with Ed25519.
"""

import base64
import hashlib
import time
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .types import SignatureError


def generate_keypair() -> Tuple[str, str]:
    """Generate a new Ed25519 keypair.

    Returns:
        Tuple of (private_key_b64, public_key_b64)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return (
        base64.b64encode(private_bytes).decode(),
        base64.b64encode(public_bytes).decode(),
    )


def load_private_key(private_key_b64: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from base64."""
    private_bytes = base64.b64decode(private_key_b64)
    return Ed25519PrivateKey.from_private_bytes(private_bytes)


def load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from base64."""
    public_bytes = base64.b64decode(public_key_b64)
    return Ed25519PublicKey.from_public_bytes(public_bytes)


def create_signature_base(
    method: str,
    url: str,
    headers: dict,
    body: Optional[bytes] = None,
) -> Tuple[str, dict]:
    """Create the signature base string and required headers.

    Following RFC 9421 HTTP Message Signatures.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full request URL
        headers: Existing headers dict (will be modified)
        body: Request body bytes (optional)

    Returns:
        Tuple of (signature_base_string, updated_headers)
    """
    parsed = urlparse(url)

    # Ensure required headers exist
    now = datetime.now(timezone.utc)
    headers = dict(headers)  # Copy

    if "host" not in {k.lower() for k in headers}:
        headers["Host"] = parsed.netloc

    if "date" not in {k.lower() for k in headers}:
        headers["Date"] = now.strftime("%a, %d %b %Y %H:%M:%S GMT")

    # Add created timestamp (Unix epoch)
    created = int(now.timestamp())

    # Add content-digest for requests with body
    if body:
        digest = hashlib.sha256(body).digest()
        headers["Content-Digest"] = f"sha-256=:{base64.b64encode(digest).decode()}:"

    # Build the signature base (RFC 9421 format)
    # Components to sign
    components = ["@method", "@target-uri", "@authority", "date"]
    if body:
        components.append("content-digest")

    # Normalize header keys for lookup
    header_lookup = {k.lower(): v for k, v in headers.items()}

    lines = []
    for component in components:
        if component == "@method":
            lines.append(f'"@method": {method.upper()}')
        elif component == "@target-uri":
            lines.append(f'"@target-uri": {url}')
        elif component == "@authority":
            lines.append(f'"@authority": {parsed.netloc}')
        elif component == "date":
            lines.append(f'"date": {header_lookup.get("date", "")}')
        elif component == "content-digest":
            lines.append(f'"content-digest": {header_lookup.get("content-digest", "")}')

    # Add signature params
    components_str = " ".join(f'"{c}"' for c in components)
    lines.append(f'"@signature-params": ({components_str});created={created};alg="ed25519"')

    signature_base = "\n".join(lines)

    # Store params for header
    headers["_signature_params"] = f'({components_str});created={created};alg="ed25519"'

    return signature_base, headers


def sign_request(
    method: str,
    url: str,
    headers: dict,
    body: Optional[bytes],
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> dict:
    """Sign an HTTP request.

    Args:
        method: HTTP method
        url: Full request URL
        headers: Request headers
        body: Request body (optional)
        private_key: Ed25519 private key
        key_id: Key identifier (agent username)

    Returns:
        Updated headers dict with Signature and Signature-Input headers
    """
    signature_base, headers = create_signature_base(method, url, headers, body)

    # Sign the base string
    signature_bytes = private_key.sign(signature_base.encode())
    signature_b64 = base64.b64encode(signature_bytes).decode()

    # Build the signature headers (RFC 9421)
    sig_params = headers.pop("_signature_params")
    headers["Signature-Input"] = f'sig1=({sig_params.split("(")[1]}'
    headers["Signature"] = f'sig1=:{signature_b64}:'

    # Add key ID for verification lookup
    headers["X-MoltAuth-Key-Id"] = key_id

    return headers


def verify_signature(
    method: str,
    url: str,
    headers: dict,
    body: Optional[bytes],
    public_key: Ed25519PublicKey,
    max_age_seconds: int = 300,
) -> bool:
    """Verify an HTTP request signature.

    Args:
        method: HTTP method
        url: Full request URL
        headers: Request headers (must include Signature and Signature-Input)
        body: Request body (optional)
        public_key: Ed25519 public key
        max_age_seconds: Maximum age of signature (default: 5 minutes)

    Returns:
        True if signature is valid

    Raises:
        SignatureError: If signature is invalid or expired
    """
    # Normalize header keys
    header_lookup = {k.lower(): v for k, v in headers.items()}

    sig_input = header_lookup.get("signature-input", "")
    sig_header = header_lookup.get("signature", "")

    if not sig_input or not sig_header:
        raise SignatureError("Missing Signature or Signature-Input header")

    # Parse signature
    if not sig_header.startswith("sig1=:") or not sig_header.endswith(":"):
        raise SignatureError("Invalid Signature header format")

    signature_b64 = sig_header[6:-1]  # Remove "sig1=:" prefix and ":" suffix

    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception:
        raise SignatureError("Invalid signature encoding")

    # Parse signature input to get created time
    if "created=" not in sig_input:
        raise SignatureError("Missing created timestamp")

    created_str = sig_input.split("created=")[1].split(";")[0]
    try:
        created = int(created_str)
    except ValueError:
        raise SignatureError("Invalid created timestamp")

    # Check signature age
    now = int(time.time())
    if now - created > max_age_seconds:
        raise SignatureError(f"Signature expired (age: {now - created}s, max: {max_age_seconds}s)")

    if created > now + 60:  # Allow 60s clock skew
        raise SignatureError("Signature created in the future")

    # Reconstruct the signature base
    signature_base, _ = create_signature_base(method, url, headers, body)

    # Verify
    try:
        public_key.verify(signature_bytes, signature_base.encode())
        return True
    except Exception:
        raise SignatureError("Signature verification failed")


def extract_key_id(headers: dict) -> Optional[str]:
    """Extract the key ID (agent username) from request headers."""
    header_lookup = {k.lower(): v for k, v in headers.items()}
    return header_lookup.get("x-moltauth-key-id")
