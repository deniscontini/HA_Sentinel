"""Watch Home Assistant's own failed logins and IP bans.

Home Assistant reports every invalid authentication (frontend login, REST API,
websocket, webhooks with bad tokens) and every automatic IP ban through the
``homeassistant.components.http.ban`` logger. A logging handler attached to that
logger gives us those events in real time without polling or patching core.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant, callback

from ..const import HA_BAN_LOGGER
from ..engine import AttackEvent, parse_ha_auth_message
from .base import SentinelSource

_LOGGER = logging.getLogger(__name__)


class _BanLogHandler(logging.Handler):
    """Forward matching log records to the event loop (thread-safe)."""

    def __init__(self, source: HomeAssistantAuthSource) -> None:
        super().__init__(logging.WARNING)
        self._source = source

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:
            return
        parsed = parse_ha_auth_message(message)
        if parsed is None:
            return
        event = parsed.to_event("home_assistant", raw=message)
        event.timestamp = record.created
        self._source.hass.loop.call_soon_threadsafe(self._source.handle_event, event)


class HomeAssistantAuthSource(SentinelSource):
    """Failed logins / bans reported by Home Assistant core."""

    name = "home_assistant"

    def __init__(self, hass: HomeAssistant, manager: Any) -> None:
        super().__init__(hass, manager)
        self._handler = _BanLogHandler(self)
        self._logger = logging.getLogger(HA_BAN_LOGGER)
        self._original_level: int | None = None

    async def async_start(self) -> None:
        # If the user silenced warnings (e.g. ``logger: default: error``) the
        # records would never be created. Lower only this logger, and restore
        # it on unload.
        if self._logger.getEffectiveLevel() > logging.WARNING:
            self._original_level = self._logger.level
            self._logger.setLevel(logging.WARNING)
            _LOGGER.info("Lowered %s log level to WARNING so failed logins can be observed", HA_BAN_LOGGER)
        self._logger.addHandler(self._handler)

    async def async_stop(self) -> None:
        self._logger.removeHandler(self._handler)
        if self._original_level is not None:
            self._logger.setLevel(self._original_level)
            self._original_level = None

    @callback
    def handle_event(self, event: AttackEvent) -> None:
        """Receive a parsed event on the event loop."""
        self.events_seen += 1
        self.manager.async_submit(event)
