"""RFC 9421 and interop test vectors."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from moltauth import load_private_key, load_public_key
from moltauth.signing import sign_request, verify_signature

VECTORS_DIR = Path(__file__).resolve().parent.parent / "test_vectors"


def load_vector(name: str) -> dict:
    path = VECTORS_DIR / name
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def test_rfc9421_ed25519_vector():
    vector = load_vector("rfc9421_b26.json")

    headers = dict(vector["headers"])
    headers["Signature-Input"] = vector["signature_input"]
    headers["Signature"] = vector["signature"]

    public_key = serialization.load_pem_public_key(vector["public_key_pem"].encode())
    body = vector["body"].encode()

    required = {
        "date",
        "@method",
        "@path",
        "@authority",
        "content-type",
        "content-length",
    }

    assert verify_signature(
        method=vector["method"],
        url=vector["url"],
        headers=headers,
        body=body,
        public_key=public_key,
        max_age_seconds=None,
        required_components=required,
        require_content_digest=False,
    )


def test_interop_vector_round_trip():
    vector = load_vector("interop_v1.json")

    private_key = load_private_key(vector["private_key_b64"])
    public_key = load_public_key(vector["public_key_b64"])

    headers = dict(vector["headers"])
    body = vector["body"].encode()

    signed_headers = sign_request(
        method=vector["method"],
        url=vector["url"],
        headers=headers,
        body=body,
        private_key=private_key,
        key_id=vector["key_id"],
        created=vector["created"],
    )

    assert signed_headers["Signature-Input"] == vector["signature_input"]
    assert signed_headers["Signature"] == vector["signature"]

    assert verify_signature(
        method=vector["method"],
        url=vector["url"],
        headers=signed_headers,
        body=body,
        public_key=public_key,
        max_age_seconds=None,
    )
