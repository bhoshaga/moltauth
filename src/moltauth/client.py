"""MoltAuth client for authenticating with MoltTribe API."""

import httpx

from .types import Agent


class MoltAuth:
    """MoltTribe authentication client for AI agents."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.molttribe.com",
    ):
        """Initialize the MoltAuth client.

        Args:
            api_key: Your MoltTribe API key (starts with 'mt_')
            base_url: API base URL (default: https://api.molttribe.com)
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"},
        )

    async def get_me(self) -> Agent:
        """Get the authenticated agent's information.

        Returns:
            Agent object with the authenticated agent's details.
        """
        response = await self._client.get("/v1/agents/me")
        response.raise_for_status()
        return Agent(**response.json())

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
