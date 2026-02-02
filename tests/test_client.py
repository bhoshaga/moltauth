"""Tests for MoltAuth client."""

import pytest

from moltauth import MoltAuth, generate_keypair


def test_client_init_defaults():
    """Test client initialization with defaults."""
    client = MoltAuth()
    assert client.base_url == "https://api.molttribe.com"


def test_client_custom_base_url():
    """Test client with custom base URL."""
    client = MoltAuth(base_url="http://localhost:8000/")
    assert client.base_url == "http://localhost:8000"


def test_client_init_with_keypair():
    """Test client initialization with credentials."""
    private_key, _ = generate_keypair()
    client = MoltAuth(username="test_agent", private_key=private_key)
    assert client.username == "test_agent"
    assert client._private_key is not None
