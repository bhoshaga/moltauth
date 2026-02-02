#!/usr/bin/env python3
"""Test MoltAuth SDK - register an agent and make authenticated requests."""

import asyncio
import sys
sys.path.insert(0, 'src')

from moltauth import MoltAuth


async def main():
    print("=== MoltAuth Live Test ===\n")

    async with MoltAuth() as auth:
        # 1. Get challenge
        print("1. Getting proof-of-work challenge...")
        challenge = await auth.get_challenge()
        print(f"   Challenge ID: {challenge.challenge_id[:20]}...")
        print(f"   Difficulty: {challenge.difficulty}")

        # 2. Solve challenge
        print("\n2. Solving challenge (this may take a few seconds)...")
        proof = auth.solve_challenge(challenge)
        print(f"   Proof: {proof}")

        # 3. Register agent
        print("\n3. Registering agent...")
        import random
        username = f"test_agent_{random.randint(10000, 99999)}"

        result = await auth.register(
            username=username,
            agent_type="test_assistant",
            parent_system="claude_code_test",
            challenge_id=challenge.challenge_id,
            proof=proof,
        )

        print(f"   ✓ Registered: @{result.username}")
        print(f"   ✓ Citizenship: {result.citizenship}")
        print(f"   ✓ Citizenship #: {result.citizenship_number}")
        print(f"   ✓ Trust Score: {result.trust_score}")
        print(f"   ✓ Private Key: {result.private_key[:20]}...")
        print(f"   ✓ Public Key: {result.public_key[:20]}...")

        # 4. Test authenticated request
        print("\n4. Testing authenticated request (get_me)...")
        me = await auth.get_me()
        print(f"   ✓ Username: @{me.username}")
        print(f"   ✓ Verified: {me.verified}")
        print(f"   ✓ Trust Score: {me.trust_score}")

        # 5. Get public key (used by other apps to verify signatures)
        print(f"\n5. Fetching public key...")
        public_key = await auth.get_public_key(username)
        print(f"   ✓ Public Key: {public_key[:20]}...")

        print("\n=== All tests passed! ===")
        print(f"\nAgent credentials (save these):")
        print(f"  Username: {result.username}")
        print(f"  Private Key: {result.private_key}")


if __name__ == "__main__":
    asyncio.run(main())
