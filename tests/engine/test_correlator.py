"""Tests for event correlation (brute force / port scan)."""

from __future__ import annotations

from custom_components.ha_sentinel.engine.correlator import Correlator, CorrelatorConfig
from custom_components.ha_sentinel.engine.models import AttackEvent, AttackType, Severity


def _fail(ip: str, ts: float) -> AttackEvent:
    return AttackEvent(AttackType.FAILED_LOGIN, Severity.LOW, "test", ip=ip, timestamp=ts)


def _block(ip: str, ts: float, port: int) -> AttackEvent:
    return AttackEvent(AttackType.FIREWALL_BLOCK, Severity.LOW, "test", ip=ip, timestamp=ts, port=port)


def test_brute_force_triggers_once_per_window() -> None:
    corr = Correlator(CorrelatorConfig(brute_force_threshold=3, brute_force_window=60))
    derived = [d for i in range(10) for d in corr.process(_fail("192.0.2.1", 1000 + i))]
    assert len(derived) == 1
    assert derived[0].attack_type is AttackType.BRUTE_FORCE
    assert derived[0].severity is Severity.HIGH

    # After the cooldown a sustained attack raises a new alert.
    later = [d for i in range(3) for d in corr.process(_fail("192.0.2.1", 1100 + i))]
    assert len(later) == 1


def test_brute_force_window_expires() -> None:
    corr = Correlator(CorrelatorConfig(brute_force_threshold=3, brute_force_window=10))
    events = [_fail("192.0.2.1", t) for t in (0, 20, 40, 60)]
    assert all(corr.process(e) == [] for e in events)


def test_brute_force_is_per_ip() -> None:
    corr = Correlator(CorrelatorConfig(brute_force_threshold=3, brute_force_window=60))
    out = []
    for i in range(2):
        for ip in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
            out += corr.process(_fail(ip, 1000 + i))
    assert out == []


def test_port_scan() -> None:
    corr = Correlator(CorrelatorConfig(port_scan_threshold=5, port_scan_window=30))
    out = []
    for i, port in enumerate([22, 22, 23, 80, 443, 3389, 8080]):
        out += corr.process(_block("198.51.100.1", 100 + i, port))
    assert len(out) == 1
    assert out[0].attack_type is AttackType.PORT_SCAN
    assert "5 portas" in (out[0].target or "")


def test_events_without_ip_are_ignored() -> None:
    corr = Correlator(CorrelatorConfig(brute_force_threshold=1))
    assert corr.process(AttackEvent(AttackType.FAILED_LOGIN, Severity.LOW, "x")) == []
