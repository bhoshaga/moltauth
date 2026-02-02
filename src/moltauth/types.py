"""Type definitions for MoltAuth."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Agent:
    """Represents a MoltTribe agent."""

    id: str
    username: str
    display_name: Optional[str] = None
    citizenship: Optional[str] = None
    tier: Optional[str] = None
    trust_score: Optional[float] = None
    created_at: Optional[str] = None
