"""Tests for the SQLite event store."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from custom_components.ha_sentinel.engine.models import AttackEvent, AttackType, Severity
from custom_components.ha_sentinel.engine.store import EventStore, auto_bucket

NOW = 1_800_000_000.0


@pytest.fixture
def store(tmp_path: Path) -> Iterator[EventStore]:
    s = EventStore(tmp_path / "sentinel.db")
    s.open()
    yield s
    s.close()


def _ev(ts: float, t: AttackType, sev: Severity, ip: str = "203.0.113.1", **kw) -> AttackEvent:
    return AttackEvent(t, sev, kw.pop("source", "test"), ip=ip, timestamp=ts, **kw)


def test_insert_assigns_ids(store: EventStore) -> None:
    evs = [_ev(NOW, AttackType.XSS, Severity.MEDIUM), _ev(NOW, AttackType.XSS, Severity.MEDIUM)]
    ids = store.insert_many(evs)
    assert ids == [1, 2]
    assert [e.id for e in evs] == [1, 2]


def test_query_filters_and_paging(store: EventStore) -> None:
    store.insert_many(
        [
            _ev(NOW - 10, AttackType.SQL_INJECTION, Severity.HIGH, username="root"),
            _ev(NOW - 20, AttackType.FAILED_LOGIN, Severity.LOW, ip="192.168.1.5"),
            _ev(NOW - 30, AttackType.FAILED_LOGIN, Severity.LOW, ip="198.51.100.4"),
            _ev(NOW - 5000, AttackType.PORT_SCAN, Severity.HIGH),
        ]
    )
    res = store.query_events(NOW - 100, NOW)
    assert res["total"] == 3
    assert res["events"][0]["attack_type"] == "sql_injection"  # newest first

    res = store.query_events(NOW - 100, NOW, attack_types=["failed_login"], limit=1)
    assert res["total"] == 2 and len(res["events"]) == 1

    res = store.query_events(NOW - 100, NOW, ip="192.168")
    assert res["total"] == 1 and res["events"][0]["is_private"] is True

    res = store.query_events(None, None, severities=["high"])
    assert res["total"] == 2

    res = store.query_events(None, None, search="root")
    assert res["total"] == 1


def test_like_wildcards_are_escaped(store: EventStore) -> None:
    store.insert_many([_ev(NOW, AttackType.OTHER, Severity.LOW, details="abc")])
    assert store.query_events(None, None, search="%")["total"] == 0
    assert store.query_events(None, None, search="_")["total"] == 0


def test_stats(store: EventStore) -> None:
    start, end = NOW - 3600, NOW
    store.insert_many(
        [
            _ev(NOW - 3500, AttackType.FAILED_LOGIN, Severity.LOW, ip="198.51.100.1"),
            _ev(NOW - 3400, AttackType.FAILED_LOGIN, Severity.LOW, ip="198.51.100.1"),
            _ev(NOW - 100, AttackType.BRUTE_FORCE, Severity.HIGH, ip="198.51.100.1"),
            _ev(NOW - 50, AttackType.XSS, Severity.MEDIUM, ip="203.0.113.2"),
        ]
    )
    stats = store.stats(start, end)
    assert stats["total"] == 4
    assert stats["unique_ips"] == 2
    assert stats["bucket"] == 300
    assert stats["by_type"][0] == {"key": "failed_login", "count": 2}
    assert stats["by_severity"] == {"low": 2, "high": 1, "medium": 1}
    top = stats["top_ips"][0]
    assert top["ip"] == "198.51.100.1" and top["count"] == 3
    assert top["max_severity"] == "high"
    assert top["types"] == ["brute_force", "failed_login"]
    assert sum(b["low"] + b["medium"] + b["high"] + b["critical"] for b in stats["timeline"]) == 4
    assert stats["timeline"][0]["low"] == 2


def test_summary_and_under_attack(store: EventStore) -> None:
    store.insert_many([_ev(NOW - 60, AttackType.BRUTE_FORCE, Severity.HIGH)])
    summary = store.summary(NOW)
    assert summary["last_hour"] == 1
    assert summary["under_attack"] is True
    assert summary["threat_level"] == "high"
    assert summary["last_event"]["attack_type"] == "brute_force"

    summary = store.summary(NOW + 600)
    assert summary["under_attack"] is False


def test_summary_volume_raises_threat(store: EventStore) -> None:
    store.insert_many([_ev(NOW - 1000 - i, AttackType.FIREWALL_BLOCK, Severity.LOW) for i in range(25)])
    assert store.summary(NOW, under_attack_threshold=20)["threat_level"] == "medium"


def test_purge(store: EventStore) -> None:
    store.insert_many([_ev(NOW - 100, AttackType.XSS, Severity.LOW), _ev(NOW, AttackType.XSS, Severity.LOW)])
    assert store.purge(NOW - 50) == 1
    assert store.purge(None) == 1


@pytest.mark.parametrize(
    ("span", "bucket"),
    [(3600, 300), (86400, 3600), (7 * 86400, 21600), (30 * 86400, 86400), (365 * 86400, 604800)],
)
def test_auto_bucket(span: int, bucket: int) -> None:
    assert auto_bucket(0, span) == bucket
