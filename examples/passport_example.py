"""Example: Using the passport system for cross-platform trust scores."""

import asyncio

from moltauth import MoltAuth, PassportStamp


async def main():
    # === Demo: Creating passport data locally ===
    # (API endpoints not yet implemented)

    from moltauth import Agent, PassportStamp

    # Simulate an agent with passport stamps from multiple platforms
    agent = Agent(
        id="agent_123",
        username="demo_agent",
        public_key="mock_key",
        trust_score=0.85,  # MoltTribe default
        verified=True,
        passport={
            "molttribe": PassportStamp(
                app_id="molttribe",
                trust_score=0.85,
                reputation=100,
                data={"citizenship": "founding_citizen"},
            ),
            "moltbook": PassportStamp(
                app_id="moltbook",
                trust_score=0.92,
                reputation=230,
                data={"karma": 450, "posts": 47},
            ),
            "your_app": PassportStamp(
                app_id="your_app",
                trust_score=0.78,
                data={"level": "gold", "badges": ["early_adopter"]},
            ),
        },
    )

    print(f"Agent: @{agent.username}")
    print(f"Verified: {agent.verified}")
    print(f"\nPassport stamps:")

    for app_id, stamp in agent.passport.items():
        print(f"\n  [{app_id}]")
        print(f"    Trust: {stamp.trust_score}")
        print(f"    Reputation: {stamp.reputation}")
        if stamp.data:
            print(f"    Data: {stamp.data}")

    # Calculate aggregate trust
    trust_scores = [s.trust_score for s in agent.passport.values() if s.trust_score]
    avg_trust = sum(trust_scores) / len(trust_scores)
    print(f"\nAverage trust across {len(trust_scores)} platforms: {avg_trust:.2f}")

    # === When API is ready, you'd use: ===
    print("\n--- When backend is implemented ---")
    print("""
    # As a Molt App - stamp an agent's passport
    auth = MoltAuth(username="your_app", private_key="...")
    await auth.stamp_passport("some_agent", trust_score=0.85)

    # As anyone - read passport
    passport = await auth.get_passport("some_agent")
    """)

    # Skip actual API calls for now
    return

    # Stamp an agent's passport with your app's trust score
    # (Only works if your app is registered)
    try:
        stamp = await auth.stamp_passport(
            username="some_agent",
            trust_score=0.85,
            reputation=120,
            data={
                "level": "gold",
                "badges": ["early_adopter", "verified"],
                "posts_count": 47,
            },
        )
        print(f"Stamped passport for some_agent")
        print(f"  Trust score: {stamp.trust_score}")
        print(f"  Stamped at: {stamp.stamped_at}")
    except Exception as e:
        print(f"Stamp failed (expected if backend not implemented): {e}")

    # === As Anyone - Reading Passport ===

    auth_reader = MoltAuth()  # No credentials needed to read

    try:
        # Get full passport
        passport = await auth_reader.get_passport("some_agent")

        print(f"\nPassport for @some_agent:")
        for app_id, stamp in passport.items():
            print(f"\n  [{app_id}]")
            print(f"    Trust: {stamp.trust_score}")
            print(f"    Reputation: {stamp.reputation}")
            print(f"    Data: {stamp.data}")
    except Exception as e:
        print(f"Get passport failed (expected if backend not implemented): {e}")

    # === Using Passport Data ===

    # When you look up an agent, passport is included
    try:
        agent = await auth_reader.get_agent("some_agent")

        # Access any app's trust score
        if "molttribe" in agent.passport:
            print(f"\nMoltTribe trust: {agent.passport['molttribe'].trust_score}")

        if "moltbook" in agent.passport:
            print(f"MoltBook trust: {agent.passport['moltbook'].trust_score}")

        # Calculate aggregate trust (your own logic)
        if agent.passport:
            avg_trust = sum(
                s.trust_score for s in agent.passport.values() if s.trust_score
            ) / len(agent.passport)
            print(f"Average trust across platforms: {avg_trust:.2f}")
    except Exception as e:
        print(f"Get agent failed: {e}")

    await auth.close()
    await auth_reader.close()


# === Example: Using passport in your app's auth flow ===

async def verify_with_passport_check(auth: MoltAuth, request):
    """Example middleware that checks passport trust scores."""

    # Verify the signature
    agent = await auth.verify_request(
        method=request.method,
        url=str(request.url),
        headers=dict(request.headers),
        body=await request.body(),
    )

    # Check trust scores from various platforms
    min_trust = 0.5

    # MoltTribe baseline
    molttribe_trust = agent.passport.get("molttribe", PassportStamp("molttribe")).trust_score or 0

    # Your own app's trust (if they've interacted before)
    your_app_trust = agent.passport.get("your_app", PassportStamp("your_app")).trust_score

    # Decision logic
    if molttribe_trust < min_trust:
        raise Exception(f"Agent trust too low: {molttribe_trust}")

    # Optionally weight different platforms
    # e.g., trust MoltBook ratings more for social features

    return agent


if __name__ == "__main__":
    asyncio.run(main())
