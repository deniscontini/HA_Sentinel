"""Runtime orchestration: sources -> filtering -> correlation -> storage -> fan-out."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import datetime, timedelta
import ipaddress
import logging
import random
import time
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_call_later, async_track_time_interval

from .const import (
    CONF_BRUTE_FORCE_THRESHOLD,
    CONF_BRUTE_FORCE_WINDOW,
    CONF_BUS_EVENT_MIN_SEVERITY,
    CONF_IGNORED_NETWORKS,
    CONF_LOG_PATHS,
    CONF_MONITOR_HA_AUTH,
    CONF_POLL_INTERVAL,
    CONF_PORT_SCAN_THRESHOLD,
    CONF_PORT_SCAN_WINDOW,
    CONF_RETENTION_DAYS,
    CONF_SYSLOG_ALLOWED,
    CONF_SYSLOG_ENABLED,
    CONF_SYSLOG_HOST,
    CONF_SYSLOG_PORT,
    CONF_UNDER_ATTACK_THRESHOLD,
    DB_FILENAME,
    DEFAULT_OPTIONS,
    EVENT_ATTACK_DETECTED,
    PURGE_INTERVAL_HOURS,
    SIGNAL_NEW_EVENTS,
    split_lines,
)
from .engine import AttackEvent, AttackType, Correlator, CorrelatorConfig, EventStore, Severity
from .engine.models import DEFAULT_SEVERITY, SEVERITY_RANK
from .sources import HomeAssistantAuthSource, LogFileSource, SentinelSource, SyslogSource

_LOGGER = logging.getLogger(__name__)

_SUBMIT_FLUSH_DELAY = 0.5
_SUBMIT_MAX_BUFFER = 5000

type IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(value: str | None) -> list[IPNetwork]:
    """Parse a list of IPs/CIDRs; invalid entries raise ``ValueError``."""
    return [ipaddress.ip_network(item, strict=False) for item in split_lines(value)]


class SentinelManager:
    """Owns the store, the correlator and all configured sources."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.options: dict[str, Any] = {**DEFAULT_OPTIONS, **entry.options}
        self.store = EventStore(hass.config.path(DB_FILENAME))
        self.correlator = Correlator(
            CorrelatorConfig(
                brute_force_threshold=int(self.options[CONF_BRUTE_FORCE_THRESHOLD]),
                brute_force_window=float(self.options[CONF_BRUTE_FORCE_WINDOW]),
                port_scan_threshold=int(self.options[CONF_PORT_SCAN_THRESHOLD]),
                port_scan_window=float(self.options[CONF_PORT_SCAN_WINDOW]),
            )
        )
        self._ignored = parse_networks(self.options[CONF_IGNORED_NETWORKS])
        self._bus_min_rank = SEVERITY_RANK[Severity(self.options[CONF_BUS_EVENT_MIN_SEVERITY])]
        self.sources: list[SentinelSource] = []
        self._write_lock = asyncio.Lock()
        self._buffer: list[AttackEvent] = []
        self._flush_unsub: CALLBACK_TYPE | None = None
        self._unsubs: list[CALLBACK_TYPE] = []
        self.ingested = 0
        self.ignored = 0
        self.started_at = time.time()

    @property
    def under_attack_threshold(self) -> int:
        return int(self.options[CONF_UNDER_ATTACK_THRESHOLD])

    # -- lifecycle ---------------------------------------------------------

    async def async_start(self) -> None:
        """Open storage and start every enabled source."""
        await self.hass.async_add_executor_job(self.store.open)

        opts = self.options
        if opts[CONF_MONITOR_HA_AUTH]:
            self.sources.append(HomeAssistantAuthSource(self.hass, self))
        if paths := split_lines(opts[CONF_LOG_PATHS]):
            self.sources.append(LogFileSource(self.hass, self, paths, int(opts[CONF_POLL_INTERVAL])))
        if opts[CONF_SYSLOG_ENABLED]:
            self.sources.append(
                SyslogSource(
                    self.hass,
                    self,
                    str(opts[CONF_SYSLOG_HOST]),
                    int(opts[CONF_SYSLOG_PORT]),
                    parse_networks(opts[CONF_SYSLOG_ALLOWED]),
                )
            )
        for source in self.sources:
            try:
                await source.async_start()
            except Exception as err:
                source.last_error = str(err)
                _LOGGER.exception("Failed to start source %s", source.name)

        self._unsubs.append(
            async_track_time_interval(
                self.hass,
                self._async_scheduled_purge,
                timedelta(hours=PURGE_INTERVAL_HOURS),
                name="ha_sentinel purge",
                cancel_on_shutdown=True,
            )
        )
        await self.async_purge_expired()

    async def async_stop(self) -> None:
        """Stop sources, flush pending events and close storage."""
        for unsub in self._unsubs:
            unsub()
        self._unsubs.clear()
        for source in self.sources:
            await source.async_stop()
        if self._flush_unsub:
            self._flush_unsub()
            self._flush_unsub = None
        if self._buffer:
            await self._async_flush()
        async with self._write_lock:
            await self.hass.async_add_executor_job(self.store.close)

    # -- ingestion ---------------------------------------------------------

    def _is_ignored(self, ip: str | None) -> bool:
        if not ip or not self._ignored:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._ignored)

    @callback
    def async_submit(self, event: AttackEvent) -> None:
        """Queue a single event from a push source; flushed in small batches."""
        if len(self._buffer) >= _SUBMIT_MAX_BUFFER:
            return
        self._buffer.append(event)
        if self._flush_unsub is None:
            self._flush_unsub = async_call_later(self.hass, _SUBMIT_FLUSH_DELAY, self._async_flush_cb)

    @callback
    def _async_flush_cb(self, _now: datetime) -> None:
        self._flush_unsub = None
        self.entry.async_create_background_task(self.hass, self._async_flush(), "ha_sentinel_flush")

    async def _async_flush(self) -> None:
        events, self._buffer = self._buffer, []
        if events:
            await self.async_ingest(events)

    async def async_ingest(
        self,
        events: Sequence[AttackEvent],
        *,
        correlate: bool = True,
        fire_bus_events: bool = True,
    ) -> list[AttackEvent]:
        """Filter, correlate, persist and publish a batch of events."""
        accepted: list[AttackEvent] = []
        for event in sorted(events, key=lambda e: e.timestamp):
            if self._is_ignored(event.ip):
                self.ignored += 1
                continue
            accepted.append(event)
            if correlate:
                accepted.extend(self.correlator.process(event))
        if not accepted:
            return []

        async with self._write_lock:
            await self.hass.async_add_executor_job(self.store.insert_many, accepted)
        self.ingested += len(accepted)

        payload = [event.as_dict() for event in accepted]
        async_dispatcher_send(self.hass, SIGNAL_NEW_EVENTS, payload)

        if fire_bus_events:
            for event, data in zip(accepted, payload, strict=True):
                if SEVERITY_RANK[event.severity] >= self._bus_min_rank:
                    self.hass.bus.async_fire(
                        EVENT_ATTACK_DETECTED, {k: v for k, v in data.items() if k != "raw"}
                    )
        return accepted

    # -- maintenance -------------------------------------------------------

    async def _async_scheduled_purge(self, _now: datetime) -> None:
        await self.async_purge_expired()

    async def async_purge_expired(self) -> int:
        """Apply the retention policy."""
        days = int(self.options[CONF_RETENTION_DAYS])
        return await self.async_purge(time.time() - days * 86400)

    async def async_purge(self, older_than: float | None) -> int:
        """Delete events older than ``older_than`` (``None`` = everything)."""
        async with self._write_lock:
            deleted = await self.hass.async_add_executor_job(self.store.purge, older_than)
        if deleted:
            _LOGGER.info("Purged %s events", deleted)
            async_dispatcher_send(self.hass, SIGNAL_NEW_EVENTS, [])
        return deleted

    async def async_generate_test_events(self, count: int, hours: float) -> int:
        """Insert synthetic events (documentation IP ranges) to try the dashboard."""
        now = time.time()
        rng = random.Random()
        attackers = [
            f"{net}.{rng.randint(1, 254)}" for net in ("192.0.2", "198.51.100", "203.0.113") for _ in range(6)
        ]
        weights = {
            AttackType.FAILED_LOGIN: 30,
            AttackType.FIREWALL_BLOCK: 25,
            AttackType.SENSITIVE_FILE_PROBE: 12,
            AttackType.SCANNER: 10,
            AttackType.SQL_INJECTION: 6,
            AttackType.PATH_TRAVERSAL: 5,
            AttackType.XSS: 4,
            AttackType.BRUTE_FORCE: 4,
            AttackType.PORT_SCAN: 2,
            AttackType.COMMAND_INJECTION: 1,
            AttackType.LOG4SHELL: 1,
        }
        samples = {
            AttackType.FAILED_LOGIN: ("ssh", "root"),
            AttackType.FIREWALL_BLOCK: ("tcp/23", None),
            AttackType.SENSITIVE_FILE_PROBE: ("GET /.env", None),
            AttackType.SCANNER: ("GET /", None),
            AttackType.SQL_INJECTION: ("GET /?id=1' OR '1'='1", None),
            AttackType.PATH_TRAVERSAL: ("GET /../../etc/passwd", None),
            AttackType.XSS: ("GET /?q=<script>alert(1)</script>", None),
            AttackType.BRUTE_FORCE: ("/auth/login_flow", "admin"),
            AttackType.PORT_SCAN: ("12 portas", None),
            AttackType.COMMAND_INJECTION: ("GET /cgi-bin/;wget http://x", None),
            AttackType.LOG4SHELL: ("GET / (${jndi:ldap://x})", None),
        }
        types = list(weights)
        events = []
        for _ in range(count):
            attack_type = rng.choices(types, weights=list(weights.values()))[0]
            target, user = samples[attack_type]
            events.append(
                AttackEvent(
                    attack_type=attack_type,
                    severity=DEFAULT_SEVERITY[attack_type],
                    source="test",
                    ip=rng.choice(attackers),
                    timestamp=now - rng.random() * hours * 3600,
                    username=user,
                    target=target,
                    details="[TESTE] evento sintético gerado por ha_sentinel.generate_test_events",
                )
            )
        await self.async_ingest(events, correlate=False, fire_bus_events=False)
        return len(events)

    def status(self) -> dict[str, Any]:
        """Runtime status for the dashboard / diagnostics."""
        return {
            "started_at": self.started_at,
            "ingested": self.ingested,
            "ignored": self.ignored,
            "sources": [source.status() for source in self.sources],
        }
