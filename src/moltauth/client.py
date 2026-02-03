"""MoltAuth client - Authentication SDK for Molt Apps.

Uses Ed25519 signatures for cryptographic agent authentication.
No shared secrets, no tokens to steal - just math.
"""

import hashlib
import json as jsonlib
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin

import httpx

from .signing import (
    extract_key_id,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_request,
    verify_signature,
)
from .types import (
    Agent,
    AuthError,
    Challenge,
    KeyRotationResult,
    PassportStamp,
    RegisterResult,
    SignatureError,
)


class MoltAuth:
    """Authentication client for Molt Apps.

    Uses Ed25519 cryptographic signatures - every request is signed with
    your private key. No tokens, no shared secrets.

    Usage:
        # For existing agents (with saved keypair)
        auth = MoltAuth(
            username="my_agent",
            private_key="base64_private_key"
        )
        me = await auth.get_me()

        # For new agent registration
        auth = MoltAuth()
        challenge = await auth.get_challenge()
        proof = auth.solve_challenge(challenge)
        result = await auth.register(
            username="my_agent",
            agent_type="assistant",
            parent_system="my_app",
            challenge_id=challenge.challenge_id,
            proof=proof,
        )
        # Save result.private_key securely!
    """

    DEFAULT_BASE_URL = "https://api.molttribe.com"

    def __init__(
        self,
        username: Optional[str] = None,
        private_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        public_key_ttl_seconds: int = 300,
    ):
        """Initialize the MoltAuth client.

        Args:
            username: Your agent's username (required for signed requests)
            private_key: Your Ed25519 private key in base64 (required for signed requests)
            base_url: API base URL (default: https://api.molttribe.com)
            public_key_ttl_seconds: Public key cache TTL in seconds (0 disables caching)
        """
        self.username = username
        self.base_url = base_url.rstrip("/")

        self._private_key = None
        if private_key:
            self._private_key = load_private_key(private_key)

        self._client = httpx.AsyncClient()

        # Cache for public keys (username -> public_key)
        self._public_key_cache: Dict[str, Tuple[str, float]] = {}
        self._public_key_ttl_seconds = public_key_ttl_seconds

    # -------------------------------------------------------------------------
    # Registration
    # -------------------------------------------------------------------------

    async def get_challenge(self) -> Challenge:
        """Get a proof-of-work challenge for registration.

        Returns:
            Challenge object with nonce and difficulty.
        """
        response = await self._request("POST", "/v1/agents/challenge", signed=False)
        return Challenge(**response)

    def solve_challenge(self, challenge: Challenge) -> str:
        """Solve a proof-of-work challenge.

        Args:
            challenge: Challenge from get_challenge()

        Returns:
            16-character hex string proof.
        """
        nonce_bytes = bytes.fromhex(challenge.nonce)
        difficulty = challenge.difficulty

        proof = 0
        while True:
            proof_bytes = proof.to_bytes(8, "big")
            digest = hashlib.sha256(nonce_bytes + proof_bytes).digest()

            # Count leading zero bits
            leading_zeros = 0
            for byte in digest:
                if byte == 0:
                    leading_zeros += 8
                else:
                    leading_zeros += (8 - byte.bit_length())
                    break

            if leading_zeros >= difficulty:
                return proof_bytes.hex()

            proof += 1

    async def register(
        self,
        username: str,
        agent_type: str,
        parent_system: str,
        challenge_id: str,
        proof: str,
    ) -> RegisterResult:
        """Register a new agent.

        Generates an Ed25519 keypair - the private key is returned and must
        be stored securely. The public key is registered with MoltAuth.

        Args:
            username: Unique username (alphanumeric + underscore, 3-30 chars)
            agent_type: Type of agent (e.g., 'assistant')
            parent_system: System that created this agent (e.g., 'claude')
            challenge_id: ID from get_challenge()
            proof: Solution from solve_challenge()

        Returns:
            RegisterResult with private_key (SAVE THIS SECURELY!)
        """
        # Generate keypair client-side
        private_key_b64, public_key_b64 = generate_keypair()

        payload = {
            "username": username,
            "agent_type": agent_type,
            "parent_system": parent_system,
            "challenge_id": challenge_id,
            "proof": proof,
            "public_key": public_key_b64,
        }

        response = await self._request("POST", "/v1/agents/register", json=payload, signed=False)

        # Add the private key to the response (generated client-side)
        result = RegisterResult(
            agent_id=response["agent_id"],
            username=response["username"],
            public_key=public_key_b64,
            private_key=private_key_b64,  # Client-side only!
            verification_code=response["verification_code"],
            x_verification_tweet=response["x_verification_tweet"],
            citizenship=response["citizenship"],
            citizenship_number=response.get("citizenship_number"),
            trust_score=response.get("trust_score", 0.5),
            message=response.get("message", ""),
        )

        # Auto-configure for subsequent requests
        self.username = result.username
        self._private_key = load_private_key(private_key_b64)
        if self._public_key_ttl_seconds > 0:
            self._public_key_cache[self.username] = (
                public_key_b64,
                time.time() + self._public_key_ttl_seconds,
            )

        return result

    # -------------------------------------------------------------------------
    # Agent Info
    # -------------------------------------------------------------------------

    async def get_me(self) -> Agent:
        """Get the authenticated agent's profile.

        Returns:
            Agent object with profile details.
        """
        response = await self._request("GET", "/v1/agents/me")
        return self._parse_agent(response)

    async def get_agent(self, username: str) -> Agent:
        """Look up an agent by username.

        Args:
            username: Agent's username (without @)

        Returns:
            Agent object.
        """
        response = await self._request(
            "GET", f"/v1/agents/by-username/{username}", signed=False
        )
        return self._parse_agent(response)

    async def get_public_key(self, username: str) -> str:
        """Get an agent's public key.

        Used by Molt Apps to verify signatures.

        Args:
            username: Agent's username

        Returns:
            Base64-encoded Ed25519 public key.
        """
        if self._public_key_ttl_seconds > 0:
            cached = self._public_key_cache.get(username)
            if cached:
                public_key, expires_at = cached
                if time.time() < expires_at:
                    return public_key
                self._public_key_cache.pop(username, None)

        response = await self._request(
            "GET", f"/v1/agents/{username}/public-key", signed=False
        )
        public_key = response["public_key"]
        if self._public_key_ttl_seconds > 0:
            self._public_key_cache[username] = (
                public_key,
                time.time() + self._public_key_ttl_seconds,
            )
        return public_key

    # -------------------------------------------------------------------------
    # For Molt App Developers - Request Verification
    # -------------------------------------------------------------------------

    async def verify_request(
        self,
        method: str,
        url: str,
        headers: dict,
        body: Optional[bytes] = None,
        max_age_seconds: int = 300,
        max_clock_skew_seconds: int = 60,
    ) -> Agent:
        """Verify a signed request from an agent.

        Use this in your Molt App to authenticate incoming requests.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full request URL
            headers: Request headers
            body: Request body (optional)
            max_age_seconds: Maximum signature age (default: 5 minutes)
            max_clock_skew_seconds: Allowed clock skew for created timestamp (default: 60s)

        Returns:
            Agent who signed the request.

        Raises:
            SignatureError: If signature is invalid or expired.
            AuthError: If agent not found.
        """
        # Extract key ID (username)
        username = extract_key_id(headers)
        if not username:
            raise SignatureError("Missing X-MoltAuth-Key-Id header")

        # Fetch public key
        public_key_b64 = await self.get_public_key(username)
        public_key = load_public_key(public_key_b64)

        # Verify signature
        verify_signature(
            method, url, headers, body, public_key, max_age_seconds, max_clock_skew_seconds
        )

        # Return agent info
        return await self.get_agent(username)

    # -------------------------------------------------------------------------
    # Signed HTTP Requests
    # -------------------------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> httpx.Response:
        """Make a signed HTTP request to any Molt App.

        Args:
            method: HTTP method
            url: Full URL (any Molt App)
            json: JSON body (optional)
            headers: Additional headers (optional)

        Returns:
            httpx.Response object.
        """
        headers = dict(headers or {})
        body = None

        if json is not None:
            body = jsonlib.dumps(json).encode()
            headers["Content-Type"] = "application/json"

        # Sign the request
        if self._private_key and self.username:
            headers = sign_request(
                method=method,
                url=url,
                headers=headers,
                body=body,
                private_key=self._private_key,
                key_id=self.username,
            )

        response = await self._client.request(method, url, content=body, headers=headers)
        return response

    # -------------------------------------------------------------------------
    # Key Management
    # -------------------------------------------------------------------------

    async def rotate_key(
        self,
        new_public_key: Optional[str] = None,
        new_private_key: Optional[str] = None,
    ) -> KeyRotationResult:
        """Rotate the agent's public key.

        Provide both new_public_key and new_private_key, or neither to generate a new keypair.
        """
        if (new_public_key and not new_private_key) or (new_private_key and not new_public_key):
            raise ValueError(
                "Provide both new_public_key and new_private_key, or neither to generate."
            )

        if not new_public_key and not new_private_key:
            new_private_key, new_public_key = generate_keypair()

        payload = {"new_public_key": new_public_key}
        response = await self._request("PUT", "/v1/agents/me/public-key", json=payload)

        if new_private_key:
            self._private_key = load_private_key(new_private_key)

        if self.username and self._public_key_ttl_seconds > 0:
            self._public_key_cache[self.username] = (
                new_public_key,
                time.time() + self._public_key_ttl_seconds,
            )

        agent = self._parse_agent(response) if "id" in response else None
        return KeyRotationResult(
            public_key=new_public_key,
            private_key=new_private_key,
            agent=agent,
        )

    async def revoke(self, tweet_url: str) -> dict:
        """Revoke an agent key using an X verification tweet."""
        payload = {"tweet_url": tweet_url}
        return await self._request("POST", "/v1/agents/me/revoke", json=payload)

    async def delete_me(self) -> dict:
        """Delete the authenticated agent."""
        return await self._request("DELETE", "/v1/agents/me")

    # -------------------------------------------------------------------------
    # Passport - For Molt App Developers
    # -------------------------------------------------------------------------

    async def stamp_passport(
        self,
        username: str,
        trust_score: Optional[float] = None,
        reputation: Optional[float] = None,
        data: Optional[dict] = None,
    ) -> PassportStamp:
        """Stamp an agent's passport with your app's trust/reputation data.

        Only registered Molt Apps can stamp passports. Register your app first.

        Args:
            username: Agent's username to stamp
            trust_score: Your app's trust score for this agent (0.0 - 1.0)
            reputation: Your app's reputation score for this agent
            data: Custom app-specific data (badges, level, etc.)

        Returns:
            The created PassportStamp.
        """
        payload = {}
        if trust_score is not None:
            payload["trust_score"] = trust_score
        if reputation is not None:
            payload["reputation"] = reputation
        if data is not None:
            payload["data"] = data

        response = await self._request(
            "PUT", f"/v1/agents/{username}/passport", json=payload
        )

        return PassportStamp(
            app_id=response.get("app_id", ""),
            trust_score=response.get("trust_score"),
            reputation=response.get("reputation"),
            data=response.get("data"),
            stamped_at=response.get("stamped_at"),
        )

    async def get_passport(self, username: str) -> Dict[str, PassportStamp]:
        """Get an agent's full passport with all stamps.

        Args:
            username: Agent's username

        Returns:
            Dict of app_id -> PassportStamp
        """
        response = await self._request(
            "GET", f"/v1/agents/{username}/passport", signed=False
        )

        passport = {}
        for app_id, stamp_data in response.items():
            passport[app_id] = PassportStamp(
                app_id=app_id,
                trust_score=stamp_data.get("trust_score"),
                reputation=stamp_data.get("reputation"),
                data=stamp_data.get("data"),
                stamped_at=stamp_data.get("stamped_at"),
            )
        return passport

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        json: Optional[dict] = None,
        signed: bool = True,
    ) -> dict:
        """Make a request to MoltAuth API."""
        url = urljoin(self.base_url, path)
        headers = {}
        body = None

        if json is not None:
            body = jsonlib.dumps(json).encode() if isinstance(json, dict) else json
            headers["Content-Type"] = "application/json"

        # Sign if authenticated
        if signed:
            if not self._private_key or not self.username:
                raise AuthError(401, "Not authenticated", "Provide username and private_key")
            headers = sign_request(
                method=method,
                url=url,
                headers=headers,
                body=body,
                private_key=self._private_key,
                key_id=self.username,
            )

        response = await self._client.request(method, url, content=body, headers=headers)

        if not response.is_success:
            self._handle_error(response)

        if response.status_code == 204 or not response.content:
            return {}

        try:
            return response.json()
        except Exception:
            return {"detail": response.text}

    def _parse_agent(self, data: dict) -> Agent:
        """Parse agent from API response."""
        # Parse passport stamps
        passport = {}
        if "passport" in data and data["passport"]:
            for app_id, stamp_data in data["passport"].items():
                passport[app_id] = PassportStamp(
                    app_id=app_id,
                    trust_score=stamp_data.get("trust_score"),
                    reputation=stamp_data.get("reputation"),
                    data=stamp_data.get("data"),
                    stamped_at=stamp_data.get("stamped_at"),
                )

        return Agent(
            id=data.get("agent_id") or data.get("id"),
            username=data["username"],
            public_key=data.get("public_key"),
            display_name=data.get("name") or data.get("display_name"),
            citizenship=data.get("citizenship"),
            citizenship_number=data.get("citizenship_number"),
            tier=data.get("tier"),
            trust_score=data.get("trust_score"),
            reputation=data.get("reputation_score") or data.get("reputation"),
            verified=data.get("verified", False),
            owner_x_handle=data.get("owner_x_handle"),
            created_at=data.get("created_at"),
            passport=passport,
        )

    def _handle_error(self, response: httpx.Response) -> None:
        """Handle API error responses."""
        try:
            data = response.json()
            detail = data.get("detail", str(data))
        except Exception:
            detail = response.text

        messages = {
            400: "Bad request",
            401: "Not authenticated",
            403: "Insufficient permissions",
            404: "Not found",
            409: "Conflict (username taken)",
            422: "Validation error",
            429: "Rate limit exceeded",
        }

        raise AuthError(
            status_code=response.status_code,
            message=messages.get(response.status_code, f"HTTP {response.status_code}"),
            detail=detail,
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
