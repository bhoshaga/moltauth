"""Tests for MoltAuth client."""

import pytest

from moltauth import MoltAuth


def test_client_init():
    """Test client initialization."""
    client = MoltAuth(api_key="mt_test_key")
    assert client.api_key == "mt_test_key"
    assert client.base_url == "https://api.molttribe.com"


def test_client_custom_base_url():
    """Test client with custom base URL."""
    client = MoltAuth(api_key="mt_test_key", base_url="http://localhost:8000/")
    assert client.base_url == "http://localhost:8000"
