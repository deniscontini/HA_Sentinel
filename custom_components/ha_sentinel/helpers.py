"""Shared helpers for the HA-facing modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN

if TYPE_CHECKING:
    from .coordinator import SentinelRuntimeData


def get_runtime(hass: HomeAssistant) -> SentinelRuntimeData:
    """Return runtime data of the (single) loaded config entry."""
    entries = hass.config_entries.async_loaded_entries(DOMAIN)
    if not entries:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="not_loaded",
        )
    return entries[0].runtime_data
