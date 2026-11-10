"""Stateful correlation: derive higher-level attacks from sequences of events.

* Brute force: N failed logins from the same IP inside a sliding window.
* Port scan: N distinct destination ports blocked for the same IP inside a window.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass

from .models import AttackEvent, AttackType, Severity

_MAX_TRACKED_IPS = 10_000


@dataclass(slots=True)
class CorrelatorConfig:
    """Thresholds for correlation rules."""

    brute_force_threshold: int = 5
    brute_force_window: float = 300.0
    port_scan_threshold: int = 10
    port_scan_window: float = 60.0


class _LRU[K, V](OrderedDict[K, V]):
    """Bounded mapping so an attacker rotating IPs cannot exhaust memory."""

    def __init__(self, maxsize: int) -> None:
        super().__init__()
        self._maxsize = maxsize

    def touch(self, key: K, default: V) -> V:
        if key in self:
            self.move_to_end(key)
            return self[key]
        self[key] = default
        if len(self) > self._maxsize:
            self.popitem(last=False)
        return default


class Correlator:
    """Feed events in chronological order and receive derived events back."""

    def __init__(self, config: CorrelatorConfig | None = None) -> None:
        self.config = config or CorrelatorConfig()
        self._failures: _LRU[str, deque[float]] = _LRU(_MAX_TRACKED_IPS)
        self._ports: _LRU[str, deque[tuple[float, int]]] = _LRU(_MAX_TRACKED_IPS)
        self._last_alert: _LRU[tuple[str, AttackType], float] = _LRU(_MAX_TRACKED_IPS)

    def process(self, event: AttackEvent) -> list[AttackEvent]:
        """Register ``event`` and return any newly derived events."""
        if not event.ip:
            return []
        if event.attack_type is AttackType.FAILED_LOGIN:
            return self._check_brute_force(event)
        if event.attack_type is AttackType.FIREWALL_BLOCK and event.port is not None:
            return self._check_port_scan(event)
        return []

    def _cooldown_ok(self, ip: str, kind: AttackType, now: float, window: float) -> bool:
        last = self._last_alert.get((ip, kind))
        if last is not None and now - last < window:
            return False
        self._last_alert.touch((ip, kind), now)
        self._last_alert[(ip, kind)] = now
        return True

    def _check_brute_force(self, event: AttackEvent) -> list[AttackEvent]:
        cfg = self.config
        assert event.ip
        now = event.timestamp
        attempts = self._failures.touch(event.ip, deque())
        attempts.append(now)
        while attempts and now - attempts[0] > cfg.brute_force_window:
            attempts.popleft()
        if len(attempts) < cfg.brute_force_threshold:
            return []
        if not self._cooldown_ok(event.ip, AttackType.BRUTE_FORCE, now, cfg.brute_force_window):
            return []
        return [
            AttackEvent(
                attack_type=AttackType.BRUTE_FORCE,
                severity=Severity.HIGH,
                source=event.source,
                ip=event.ip,
                timestamp=now,
                port=event.port,
                username=event.username,
                target=event.target,
                details=(
                    f"{len(attempts)} falhas de login em {int(cfg.brute_force_window)}s (correlacionado)"
                ),
            )
        ]

    def _check_port_scan(self, event: AttackEvent) -> list[AttackEvent]:
        cfg = self.config
        assert event.ip and event.port is not None
        now = event.timestamp
        hits = self._ports.touch(event.ip, deque())
        hits.append((now, event.port))
        while hits and now - hits[0][0] > cfg.port_scan_window:
            hits.popleft()
        ports = {port for _, port in hits}
        if len(ports) < cfg.port_scan_threshold:
            return []
        if not self._cooldown_ok(event.ip, AttackType.PORT_SCAN, now, cfg.port_scan_window):
            return []
        sample = ", ".join(str(p) for p in sorted(ports)[:15])
        return [
            AttackEvent(
                attack_type=AttackType.PORT_SCAN,
                severity=Severity.HIGH,
                source=event.source,
                ip=event.ip,
                timestamp=now,
                target=f"{len(ports)} portas",
                details=(
                    f"{len(ports)} portas distintas em {int(cfg.port_scan_window)}s: "
                    f"{sample}{'…' if len(ports) > 15 else ''}"
                ),
            )
        ]
