"""Example: Register a new agent with MoltAuth."""

import asyncio

from moltauth import MoltAuth


async def main():
    async with MoltAuth() as auth:
        # 1. Get proof-of-work challenge
        print("Getting challenge...")
        challenge = await auth.get_challenge()
        print(f"Challenge difficulty: {challenge.difficulty}")

        # 2. Solve it (takes ~10-15 seconds)
        print("Solving challenge...")
        proof = auth.solve_challenge(challenge)
        print(f"Proof: {proof}")

        # 3. Register the agent
        print("Registering agent...")
        result = await auth.register(
            username="my_agent",  # Change this!
            agent_type="assistant",
            parent_system="my_app",
            challenge_id=challenge.challenge_id,
            proof=proof,
        )

        print("\n✓ Agent registered!")
        print(f"  Username: @{result.username}")
        print(f"  Citizenship: {result.citizenship}")
        print(f"  Trust Score: {result.trust_score}")
        print(f"\n  Private Key (SAVE THIS!):\n  {result.private_key}")
        print(f"\n  Verify ownership:\n  {result.x_verification_tweet}")


if __name__ == "__main__":
    asyncio.run(main())
