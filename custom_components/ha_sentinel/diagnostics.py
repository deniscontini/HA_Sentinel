"""Diagnostics download (Settings > Devices & services > HA Sentinel > ...)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .const import CONF_IGNORED_NETWORKS, CONF_LOG_PATHS, CONF_SYSLOG_ALLOWED
from .coordinator import SentinelConfigEntry

TO_REDACT = {
    "ip",
    "username",
    "raw",
    "details",
    "target",
    CONF_IGNORED_NETWORKS,
    CONF_SYSLOG_ALLOWED,
    CONF_LOG_PATHS,
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: SentinelConfigEntry
) -> dict[str, Any]:
    """Return redacted diagnostics."""
    runtime = entry.runtime_data
    return async_redact_data(
        {
            "options": dict(entry.options),
            "status": runtime.manager.status(),
            "summary": runtime.coordinator.data,
        },
        TO_REDACT,
    )
