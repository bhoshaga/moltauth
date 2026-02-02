"""HTTP Signatures implementation using Ed25519.

Implements RFC 9421 (HTTP Message Signatures) with Ed25519.
"""

import base64
import hashlib
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .types import SignatureError

_SIGNATURE_LABEL = "sig1"
_REQUIRED_COMPONENTS = {"@method", "@target-uri", "@authority", "date"}


def _normalize_headers(headers: dict) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _content_digest(body: bytes) -> str:
    digest = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(digest).decode()}:"


def _format_signature_params(components: List[str], params: List[str]) -> str:
    components_str = " ".join(f'"{c}"' for c in components)
    if params:
        return f"({components_str});" + ";".join(params)
    return f"({components_str})"


def _normalize_authority(parsed) -> str:
    if not parsed.hostname:
        return parsed.netloc
    host = parsed.hostname.lower()
    scheme = (parsed.scheme or "").lower()
    port = parsed.port
    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None

    if ":" in host:
        host_value = f"[{host}]"
    else:
        host_value = host

    if port and port != default_port:
        return f"{host_value}:{port}"
    return host_value


def _build_signature_base(
    method: str,
    url: str,
    headers: dict,
    components: List[str],
    signature_params: str,
) -> str:
    parsed = urlparse(url)
    header_lookup = _normalize_headers(headers)

    lines: List[str] = []
    for component in components:
        if component == "@method":
            value = method.upper()
        elif component == "@target-uri":
            value = url
        elif component == "@authority":
            value = _normalize_authority(parsed)
        elif component == "@scheme":
            value = (parsed.scheme or "").lower()
        elif component == "@path":
            value = parsed.path or "/"
        elif component == "@query":
            value = f"?{parsed.query}" if parsed.query else "?"
        elif component.startswith("@"):
            raise SignatureError(f"Unsupported signature component: {component}")
        else:
            lookup_key = component.lower()
            if lookup_key not in header_lookup:
                raise SignatureError(f"Missing required header for signature: {component}")
            value = header_lookup[lookup_key]
        lines.append(f'"{component}": {value}')

    lines.append(f'"@signature-params": {signature_params}')
    return "\n".join(lines)


def _parse_signature_header(signature_header: str) -> Tuple[str, bytes]:
    parts = [part.strip() for part in signature_header.split(",") if part.strip()]
    for part in parts:
        match = re.match(r'(?P<label>[a-zA-Z0-9_-]+)=:(?P<b64>[^:]+):', part)
        if not match:
            continue
        label = match.group("label")
        signature_b64 = match.group("b64")
        try:
            signature_bytes = base64.b64decode(signature_b64)
        except Exception:
            raise SignatureError("Invalid signature encoding")
        return label, signature_bytes
    raise SignatureError("Invalid Signature header format")


def _parse_signature_input(
    signature_input: str, label: str
) -> Tuple[List[str], List[str], int, Optional[str]]:
    parts = [part.strip() for part in signature_input.split(",") if part.strip()]
    target = None
    for part in parts:
        if part.startswith(f"{label}="):
            target = part
            break
    if not target:
        raise SignatureError("Signature-Input missing matching label")

    _, value = target.split("=", 1)
    if not value.startswith("("):
        raise SignatureError("Invalid Signature-Input header format")

    closing_index = value.find(")")
    if closing_index == -1:
        raise SignatureError("Invalid Signature-Input header format")

    components_str = value[1:closing_index].strip()
    params_str = value[closing_index + 1 :].strip()
    if params_str.startswith(";"):
        params_str = params_str[1:]

    components = re.findall(r'"([^"]+)"', components_str)
    if not components:
        raise SignatureError("Signature-Input missing components")

    if params_str:
        params = [p.strip() for p in params_str.split(";") if p.strip()]
    else:
        params = []
    params_map: Dict[str, str] = {}
    for param in params:
        if "=" in param:
            key, val = param.split("=", 1)
            params_map[key] = val
        else:
            params_map[param] = ""

    created_val = params_map.get("created")
    if created_val is None:
        raise SignatureError("Missing created timestamp")
    try:
        created = int(created_val)
    except ValueError:
        raise SignatureError("Invalid created timestamp")

    alg = params_map.get("alg")
    if alg:
        alg = alg.strip('"')

    return components, params, created, alg


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
    created: Optional[int] = None,
    date: Optional[str] = None,
) -> Tuple[str, dict, str]:
    """Create the signature base string and required headers.

    Following RFC 9421 HTTP Message Signatures.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full request URL
        headers: Existing headers dict (will be modified)
        body: Request body bytes (optional)
        created: Override created timestamp (Unix epoch)
        date: Override Date header if not already present

    Returns:
        Tuple of (signature_base_string, updated_headers, signature_params)
    """
    parsed = urlparse(url)

    # Ensure required headers exist
    now = datetime.now(timezone.utc)
    headers = dict(headers)  # Copy
    header_lookup = _normalize_headers(headers)

    if "host" not in header_lookup:
        headers["Host"] = parsed.netloc
        header_lookup["host"] = parsed.netloc

    if "date" not in header_lookup:
        if date:
            headers["Date"] = date
        else:
            headers["Date"] = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
        header_lookup["date"] = headers["Date"]

    # Add created timestamp (Unix epoch)
    if created is None:
        created = int(now.timestamp())

    # Build the signature base (RFC 9421 format)
    components = ["@method", "@target-uri", "@authority", "date"]

    if body is not None and len(body) > 0:
        headers["Content-Digest"] = _content_digest(body)
        components.append("content-digest")

    signature_params = _format_signature_params(
        components, [f"created={created}", 'alg="ed25519"']
    )

    signature_base = _build_signature_base(method, url, headers, components, signature_params)
    return signature_base, headers, signature_params


def sign_request(
    method: str,
    url: str,
    headers: dict,
    body: Optional[bytes],
    private_key: Ed25519PrivateKey,
    key_id: str,
    created: Optional[int] = None,
    date: Optional[str] = None,
) -> dict:
    """Sign an HTTP request.

    Args:
        method: HTTP method
        url: Full request URL
        headers: Request headers
        body: Request body (optional)
        private_key: Ed25519 private key
        key_id: Key identifier (agent username)
        created: Override created timestamp (Unix epoch)
        date: Override Date header if not already present

    Returns:
        Updated headers dict with Signature and Signature-Input headers
    """
    signature_base, headers, signature_params = create_signature_base(
        method, url, headers, body, created=created, date=date
    )

    # Sign the base string
    signature_bytes = private_key.sign(signature_base.encode())
    signature_b64 = base64.b64encode(signature_bytes).decode()

    # Build the signature headers (RFC 9421)
    headers["Signature-Input"] = f"{_SIGNATURE_LABEL}={signature_params}"
    headers["Signature"] = f"{_SIGNATURE_LABEL}=:{signature_b64}:"

    # Add key ID for verification lookup
    headers["X-MoltAuth-Key-Id"] = key_id

    return headers


def verify_signature(
    method: str,
    url: str,
    headers: dict,
    body: Optional[bytes],
    public_key: Ed25519PublicKey,
    max_age_seconds: Optional[int] = 300,
    max_clock_skew_seconds: Optional[int] = 60,
    required_components: Optional[set] = _REQUIRED_COMPONENTS,
    require_content_digest: bool = True,
) -> bool:
    """Verify an HTTP request signature.

    Args:
        method: HTTP method
        url: Full request URL
        headers: Request headers (must include Signature and Signature-Input)
        body: Request body (optional)
        public_key: Ed25519 public key
        max_age_seconds: Maximum age of signature (default: 5 minutes, None disables)
        max_clock_skew_seconds: Allowed clock skew for created timestamp
        required_components: Components required to be present in signature
        require_content_digest: Require content-digest when body is present

    Returns:
        True if signature is valid

    Raises:
        SignatureError: If signature is invalid or expired
    """
    header_lookup = _normalize_headers(headers)

    sig_input = header_lookup.get("signature-input", "")
    sig_header = header_lookup.get("signature", "")

    if not sig_input or not sig_header:
        raise SignatureError("Missing Signature or Signature-Input header")

    label, signature_bytes = _parse_signature_header(sig_header)
    components, params, created, alg = _parse_signature_input(sig_input, label)

    if alg and alg != "ed25519":
        raise SignatureError(f"Unsupported signature algorithm: {alg}")

    # Check signature age
    now = int(time.time())
    if max_age_seconds is not None and now - created > max_age_seconds:
        raise SignatureError(
            f"Signature expired (age: {now - created}s, max: {max_age_seconds}s)"
        )

    if max_clock_skew_seconds is not None and created > now + max_clock_skew_seconds:
        raise SignatureError("Signature created in the future")

    if required_components:
        missing = required_components - set(components)
        if missing:
            missing_list = ", ".join(sorted(missing))
            raise SignatureError(f"Signature missing required components: {missing_list}")

    if require_content_digest and body is not None and len(body) > 0:
        if "content-digest" not in components:
            raise SignatureError("Missing content-digest signature component for request body")

    if "content-digest" in components:
        digest_header = header_lookup.get("content-digest")
        if not digest_header:
            raise SignatureError("Missing Content-Digest header")
        body_bytes = body if body is not None else b""
        expected_digest = _content_digest(body_bytes)
        if digest_header != expected_digest:
            raise SignatureError("Content-Digest mismatch")

    signature_params = _format_signature_params(components, params)
    signature_base = _build_signature_base(method, url, headers, components, signature_params)

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
