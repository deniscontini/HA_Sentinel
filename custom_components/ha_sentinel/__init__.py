"""HA Sentinel: detect, store and visualize attack attempts against your home."""

from __future__ import annotations

import contextlib
import logging
import os
import sqlite3
from typing import Any

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.typing import ConfigType

from .const import DB_FILENAME, DOMAIN, SIGNAL_NEW_EVENTS
from .coordinator import SentinelConfigEntry, SentinelCoordinator, SentinelRuntimeData
from .manager import SentinelManager
from .panel import async_register_panel, async_register_static, async_unregister_panel
from .services import async_register_services
from .websocket_api import async_register_websocket_api

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR]
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register things that live for the whole HA run."""
    await async_register_static(hass)
    async_register_websocket_api(hass)
    async_register_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: SentinelConfigEntry) -> bool:
    """Start monitoring."""
    manager = SentinelManager(hass, entry)
    try:
        await manager.async_start()
    except (OSError, sqlite3.Error) as err:
        await manager.async_stop()
        raise ConfigEntryNotReady(f"Não foi possível abrir o banco de eventos: {err}") from err

    coordinator = SentinelCoordinator(hass, entry, manager)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = SentinelRuntimeData(manager=manager, coordinator=coordinator)

    @callback
    def _on_new_events(_events: list[dict[str, Any]]) -> None:
        entry.async_create_background_task(hass, coordinator.async_request_refresh(), "ha_sentinel_refresh")

    entry.async_on_unload(async_dispatcher_connect(hass, SIGNAL_NEW_EVENTS, _on_new_events))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    await async_register_panel(hass)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: SentinelConfigEntry) -> bool:
    """Stop monitoring."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        async_unregister_panel(hass)
        await entry.runtime_data.manager.async_stop()
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: SentinelConfigEntry) -> None:
    """Delete the event database when the integration is removed."""

    def _remove() -> None:
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(FileNotFoundError):
                os.remove(hass.config.path(DB_FILENAME + suffix))

    await hass.async_add_executor_job(_remove)
