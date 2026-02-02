"""Tests for signing and verification utilities."""

import time

import pytest

from moltauth import (
    SignatureError,
    extract_key_id,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_request,
    verify_signature,
)
import moltauth.signing as signing_module


def test_sign_and_verify_round_trip():
    private_b64, public_b64 = generate_keypair()
    private_key = load_private_key(private_b64)
    public_key = load_public_key(public_b64)

    headers = {}
    body = b'{"content":"hello"}'

    signed_headers = sign_request(
        method="POST",
        url="https://moltbook.com/api/posts",
        headers=headers,
        body=body,
        private_key=private_key,
        key_id="my_agent",
    )

    assert "Signature" in signed_headers
    assert "Signature-Input" in signed_headers
    assert "Content-Digest" in signed_headers

    assert verify_signature(
        method="POST",
        url="https://moltbook.com/api/posts",
        headers=signed_headers,
        body=body,
        public_key=public_key,
    )


def test_verify_rejects_modified_body():
    private_b64, public_b64 = generate_keypair()
    private_key = load_private_key(private_b64)
    public_key = load_public_key(public_b64)

    headers = {}
    body = b'{"content":"hello"}'
    signed_headers = sign_request(
        method="POST",
        url="https://moltbook.com/api/posts",
        headers=headers,
        body=body,
        private_key=private_key,
        key_id="my_agent",
    )

    with pytest.raises(SignatureError, match="Content-Digest mismatch"):
        verify_signature(
            method="POST",
            url="https://moltbook.com/api/posts",
            headers=signed_headers,
            body=b'{"content":"tampered"}',
            public_key=public_key,
        )


def test_verify_expired_signature(monkeypatch):
    private_b64, public_b64 = generate_keypair()
    private_key = load_private_key(private_b64)
    public_key = load_public_key(public_b64)

    headers = {}
    body = b'{"content":"hello"}'
    signed_headers = sign_request(
        method="POST",
        url="https://moltbook.com/api/posts",
        headers=headers,
        body=body,
        private_key=private_key,
        key_id="my_agent",
    )

    now = int(time.time())
    monkeypatch.setattr(signing_module.time, "time", lambda: now + 1000)

    with pytest.raises(SignatureError, match="Signature expired"):
        verify_signature(
            method="POST",
            url="https://moltbook.com/api/posts",
            headers=signed_headers,
            body=body,
            public_key=public_key,
            max_age_seconds=300,
        )


def test_extract_key_id():
    headers = {"X-MoltAuth-Key-Id": "agent_123"}
    assert extract_key_id(headers) == "agent_123"
