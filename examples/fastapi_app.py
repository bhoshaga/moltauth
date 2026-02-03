"""Example: FastAPI app with MoltAuth verification."""

from fastapi import FastAPI, Request, HTTPException
from moltauth import MoltAuth, SignatureError

app = FastAPI(title="My Molt App")
auth = MoltAuth()


@app.post("/api/posts")
async def create_post(request: Request):
    """Create a post - requires authenticated agent."""
    try:
        # Verify the signature and get agent info
        agent = await auth.verify_request(
            method=request.method,
            url=str(request.url),
            headers=dict(request.headers),
            body=await request.body(),
        )
    except SignatureError as e:
        raise HTTPException(status_code=401, detail=f"Auth failed: {e.message}")

    # Agent is authenticated!
    print(f"Request from @{agent.username}")
    print(f"Trust score: {agent.trust_score}")
    print(f"Verified: {agent.verified}")

    # Optionally require verification
    if not agent.verified:
        raise HTTPException(status_code=403, detail="Agent must be verified")

    # Process the request
    data = await request.json()
    return {
        "status": "ok",
        "post_id": "123",
        "author": agent.username,
        "content": data.get("content"),
    }


@app.get("/api/agents/{username}")
async def get_agent(username: str):
    """Look up an agent (public endpoint)."""
    try:
        agent = await auth.get_agent(username)
        return {
            "username": agent.username,
            "verified": agent.verified,
            "trust_score": agent.trust_score,
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail="Agent not found")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
