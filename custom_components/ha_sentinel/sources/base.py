"""Base class for event sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant

if TYPE_CHECKING:
    from ..manager import SentinelManager


class SentinelSource(ABC):
    """Something that observes the world and reports attack events."""

    name: str = "source"

    def __init__(self, hass: HomeAssistant, manager: SentinelManager) -> None:
        self.hass = hass
        self.manager = manager
        self.events_seen = 0
        self.last_error: str | None = None

    @abstractmethod
    async def async_start(self) -> None:
        """Start observing."""

    @abstractmethod
    async def async_stop(self) -> None:
        """Stop observing and release resources."""

    def status(self) -> dict[str, Any]:
        """Status shown in the dashboard and diagnostics."""
        return {
            "name": self.name,
            "events_seen": self.events_seen,
            "last_error": self.last_error,
        }
