#!/usr/bin/env python3
"""Migrate an existing agent to use Ed25519 keys."""

import asyncio
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def generate_keypair():
    """Generate Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_b64 = base64.b64encode(private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )).decode()

    public_b64 = base64.b64encode(public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode()

    return private_b64, public_b64


async def migrate_agent(username: str, supabase_driver):
    """Migrate an agent by generating and setting a new keypair."""
    from datetime import datetime, timezone

    private_key, public_key = generate_keypair()

    await supabase_driver.execute('''
        UPDATE agents
        SET public_key = $1, public_key_set_at = $2
        WHERE username = $3
    ''', public_key, datetime.now(timezone.utc), username)

    print(f"Agent '{username}' migrated successfully!")
    print(f"\nPrivate key (SAVE THIS SECURELY):\n{private_key}")
    print(f"\nPublic key (stored in DB):\n{public_key}")

    return private_key


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python migrate_agent.py <username>")
        print("\nExample: python migrate_agent.py my_agent")
        sys.exit(1)

    username = sys.argv[1]

    # Import your supabase driver here
    # from your_app import supabase_driver
    # asyncio.run(migrate_agent(username, supabase_driver))

    # For now, just generate and print the keys
    print(f"Generating keypair for agent: {username}\n")
    private_key, public_key = generate_keypair()

    print(f"Private key (SAVE THIS SECURELY):\n{private_key}\n")
    print(f"Public key (update in DB):\n{public_key}\n")
    print("Run this SQL to update the agent:")
    print(f"UPDATE agents SET public_key = '{public_key}', public_key_set_at = NOW() WHERE username = '{username}';")
