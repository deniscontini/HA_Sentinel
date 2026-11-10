"""UDP syslog receiver: routers, firewalls, NAS and servers can forward logs here."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from typing import Any

from homeassistant.core import HomeAssistant

from ..engine import parse_line, strip_syslog_header
from .base import SentinelSource

_LOGGER = logging.getLogger(__name__)

_MAX_DATAGRAM = 8192
_MAX_LINES_PER_SECOND = 2000


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, source: SyslogSource) -> None:
        self._source = source

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        self._source.handle_datagram(data, str(addr[0]))

    def error_received(self, exc: Exception) -> None:
        self._source.last_error = str(exc)


class SyslogSource(SentinelSource):
    """Listen for RFC3164/RFC5424 syslog messages over UDP."""

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
        self._window_start = 0.0
        self._window_count = 0
        self.dropped = 0
        self.rejected = 0

    async def async_start(self) -> None:
        try:
            transport, _ = await self.hass.loop.create_datagram_endpoint(
                lambda: _SyslogProtocol(self), local_addr=(self._host, self._port)
            )
        except OSError as err:
            self.last_error = f"Não foi possível abrir {self._host}:{self._port}/udp: {err}"
            _LOGGER.error(self.last_error)
            return
        self._transport = transport  # type: ignore[assignment]
        _LOGGER.info("Syslog receiver listening on %s:%s/udp", self._host, self._port)

    async def async_stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def _sender_allowed(self, sender: str) -> bool:
        if not self._allowed:
            return True
        try:
            addr = ipaddress.ip_address(sender)
        except ValueError:
            return False
        return any(addr in net for net in self._allowed)

    def handle_datagram(self, data: bytes, sender: str) -> None:
        """Runs on the event loop for every UDP packet."""
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
            line = strip_syslog_header(raw_line)
            if (parsed := parse_line(line)) is None:
                continue
            self.events_seen += 1
            self.manager.async_submit(parsed.to_event(f"syslog:{sender}", raw=line))

    def status(self) -> dict[str, Any]:
        data = super().status()
        data.update(
            listening=self._transport is not None,
            address=f"{self._host}:{self._port}/udp",
            dropped=self.dropped,
            rejected=self.rejected,
        )
        return data
