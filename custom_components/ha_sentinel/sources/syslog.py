"""UDP syslog receiver: routers, firewalls, NAS and servers can forward logs here."""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timedelta
import ipaddress
import logging
import time
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval

from ..engine import AttackEvent, parse_line, strip_syslog_header
from .base import SentinelSource

_LOGGER = logging.getLogger(__name__)

_MAX_DATAGRAM = 8192
_MAX_LINES_PER_SECOND = 2000
# Lines buffered on the event loop between executor drains. Bounded so a flood
# cannot grow memory without limit; excess is dropped and counted.
_MAX_QUEUE = 50_000
_DRAIN_INTERVAL = timedelta(seconds=0.5)


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, source: SyslogSource) -> None:
        self._source = source

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        self._source.handle_datagram(data, str(addr[0]))

    def error_received(self, exc: Exception) -> None:
        self._source.last_error = str(exc)


class SyslogSource(SentinelSource):
    """Listen for RFC3164/RFC5424 syslog messages over UDP.

    The datagram handler runs on the event loop, so it does the cheap work only
    (allowlist check, rate limit, decode, split) and queues raw lines. Parsing
    with the detection rules happens off-loop in an executor, drained in batches,
    so a flood of crafted lines cannot stall Home Assistant.
    """

    name = "syslog"

    def __init__(
        self,
        hass: HomeAssistant,
        manager: Any,
        host: str,
        port: int,
        allowed: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ) -> None:
        super().__init__(hass, manager)
        self._host = host
        self._port = port
        self._allowed = allowed
        self._transport: asyncio.DatagramTransport | None = None
        self._queue: deque[tuple[str, str]] = deque(maxlen=_MAX_QUEUE)
        self._unsub_drain: Any = None
        self._draining = False
        self._window_start = 0.0
        self._window_count = 0
        self.dropped = 0
        self.rejected = 0

    async def async_start(self) -> None:
        # A1: refuse to listen without an explicit sender allowlist. UDP source
        # addresses are spoofable, so an open receiver lets anyone inject events.
        if not self._allowed:
            self.last_error = (
                "Receptor syslog não iniciado: defina ao menos uma rede/IP confiável"
                " em 'Remetentes permitidos'."
            )
            _LOGGER.error(self.last_error)
            return
        try:
            transport, _ = await self.hass.loop.create_datagram_endpoint(
                lambda: _SyslogProtocol(self), local_addr=(self._host, self._port)
            )
        except OSError as err:
            self.last_error = f"Não foi possível abrir {self._host}:{self._port}/udp: {err}"
            _LOGGER.error(self.last_error)
            return
        self._transport = transport  # type: ignore[assignment]
        self._unsub_drain = async_track_time_interval(
            self.hass,
            self._async_drain_cb,
            _DRAIN_INTERVAL,
            name="ha_sentinel syslog drain",
            cancel_on_shutdown=True,
        )
        _LOGGER.info("Syslog receiver listening on %s:%s/udp", self._host, self._port)

    async def async_stop(self) -> None:
        if self._unsub_drain:
            self._unsub_drain()
            self._unsub_drain = None
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        if self._queue:
            await self._async_drain()

    def _sender_allowed(self, sender: str) -> bool:
        if not self._allowed:
            return False
        try:
            addr = ipaddress.ip_address(sender)
        except ValueError:
            return False
        return any(addr in net for net in self._allowed)

    def handle_datagram(self, data: bytes, sender: str) -> None:
        """Runs on the event loop for every UDP packet (cheap work only)."""
        if not self._sender_allowed(sender):
            self.rejected += 1
            return
        now = time.monotonic()
        if now - self._window_start >= 1:
            self._window_start, self._window_count = now, 0
        text = data[:_MAX_DATAGRAM].decode("utf-8", errors="replace")
        for raw_line in text.splitlines():
            self._window_count += 1
            if self._window_count > _MAX_LINES_PER_SECOND:
                self.dropped += 1
                continue
            if not raw_line:
                continue
            if len(self._queue) >= _MAX_QUEUE:
                self.dropped += 1
                continue
            self._queue.append((sender, raw_line))

    @callback
    def _async_drain_cb(self, _now: datetime) -> None:
        if self._draining or not self._queue:
            return
        self._draining = True
        self.manager.entry.async_create_background_task(
            self.hass, self._async_drain(), "ha_sentinel_syslog_drain"
        )

    async def _async_drain(self) -> None:
        """Parse queued lines in the executor and ingest the resulting events."""
        try:
            if not self._queue:
                return
            batch = list(self._queue)
            self._queue.clear()
            events = await self.hass.async_add_executor_job(self._parse_batch, batch)
            if events:
                self.events_seen += len(events)
                await self.manager.async_ingest(events)
        finally:
            self._draining = False

    def _parse_batch(self, batch: list[tuple[str, str]]) -> list[AttackEvent]:
        events: list[AttackEvent] = []
        for sender, raw_line in batch:
            line = strip_syslog_header(raw_line)
            if (parsed := parse_line(line)) is not None:
                events.append(parsed.to_event(f"syslog:{sender}", raw=line))
        return events

    def status(self) -> dict[str, Any]:
        data = super().status()
        data.update(
            listening=self._transport is not None,
            address=f"{self._host}:{self._port}/udp",
            queued=len(self._queue),
            dropped=self.dropped,
            rejected=self.rejected,
        )
        return data
