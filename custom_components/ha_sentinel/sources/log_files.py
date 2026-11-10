"""Tail local log files (sshd auth.log, nginx/Apache access logs, UFW, fail2ban...)."""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval

from ..engine import AttackEvent, LogTailer, parse_line
from .base import SentinelSource

_LOGGER = logging.getLogger(__name__)
_MAX_EVENTS_PER_POLL = 5000


class LogFileSource(SentinelSource):
    """Poll a set of files for appended lines and classify them."""

    name = "log_files"

    def __init__(self, hass: HomeAssistant, manager: Any, paths: list[str], interval: int) -> None:
        super().__init__(hass, manager)
        self._tailers = [LogTailer(p) for p in paths]
        self._interval = timedelta(seconds=max(1, interval))
        self._unsub: Any = None
        self._busy = False

    async def async_start(self) -> None:
        # The first read only records the current end of each file.
        await self.hass.async_add_executor_job(self._read_and_parse)
        self._unsub = async_track_time_interval(
            self.hass, self._async_poll, self._interval, name="ha_sentinel log poll", cancel_on_shutdown=True
        )

    async def async_stop(self) -> None:
        if self._unsub:
            self._unsub()
            self._unsub = None

    def _read_and_parse(self) -> list[AttackEvent]:
        """Blocking: read new lines from all files and classify them."""
        events: list[AttackEvent] = []
        for tailer in self._tailers:
            label = f"file:{tailer.path.name}"
            for line in tailer.read_new_lines():
                if (parsed := parse_line(line)) is not None:
                    events.append(parsed.to_event(label, raw=line))
                    if len(events) >= _MAX_EVENTS_PER_POLL:
                        _LOGGER.warning("Too many events in one poll; remaining lines will be read next time")
                        return events
        return events

    @callback
    def _async_poll(self, _now: datetime) -> None:
        if self._busy:
            return
        self._busy = True
        self.manager.entry.async_create_background_task(
            self.hass, self._async_do_poll(), "ha_sentinel_log_poll"
        )

    async def _async_do_poll(self) -> None:
        try:
            events = await self.hass.async_add_executor_job(self._read_and_parse)
            errors = [f"{t.path}: {t.error}" for t in self._tailers if t.error]
            self.last_error = "; ".join(errors) or None
            if events:
                self.events_seen += len(events)
                await self.manager.async_ingest(events)
        finally:
            self._busy = False

    def status(self) -> dict[str, Any]:
        data = super().status()
        data["files"] = [{"path": str(t.path), "error": t.error} for t in self._tailers]
        return data
