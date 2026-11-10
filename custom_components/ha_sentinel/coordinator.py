"""Coordinator that keeps the summary used by sensors up to date."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.debounce import Debouncer
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, SUMMARY_UPDATE_SECONDS
from .manager import SentinelManager

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SentinelRuntimeData:
    """Objects stored on the config entry while it is loaded."""

    manager: SentinelManager
    coordinator: SentinelCoordinator


type SentinelConfigEntry = ConfigEntry[SentinelRuntimeData]


class SentinelCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Recomputes the summary periodically and (debounced) on new events."""

    config_entry: SentinelConfigEntry

    def __init__(self, hass: HomeAssistant, entry: SentinelConfigEntry, manager: SentinelManager) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(seconds=SUMMARY_UPDATE_SECONDS),
            request_refresh_debouncer=Debouncer(hass, _LOGGER, cooldown=3, immediate=True),
        )
        self.manager = manager

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            return await self.hass.async_add_executor_job(
                self.manager.store.summary, None, self.manager.under_attack_threshold
            )
        except Exception as err:
            raise UpdateFailed(f"Erro ao consultar o banco de eventos: {err}") from err
