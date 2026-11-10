"""SQLite persistence and aggregation queries.

All methods are synchronous and thread-safe; the Home Assistant layer calls
them through ``hass.async_add_executor_job`` so the event loop never blocks.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any

from .models import SEVERITY_RANK, AttackEvent, AttackType, Severity, ThreatLevel

SCHEMA_VERSION = 1
MAX_PAGE_SIZE = 10_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL    NOT NULL,
    source        TEXT    NOT NULL,
    attack_type   TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    severity_rank INTEGER NOT NULL,
    ip            TEXT,
    is_private    INTEGER,
    port          INTEGER,
    username      TEXT,
    target        TEXT,
    details       TEXT,
    raw           TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts   ON events (ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events (attack_type, ts);
"""

_COLUMNS = "id, ts, source, attack_type, severity, ip, is_private, port, username, target, details, raw"


def auto_bucket(start: float, end: float) -> int:
    """Pick a histogram bucket size (seconds) that yields a readable chart."""
    span = max(end - start, 1)
    for limit, bucket in (
        (3 * 3600, 300),  # <= 3 h   -> 5 min
        (36 * 3600, 3600),  # <= 36 h  -> 1 h
        (8 * 86400, 6 * 3600),  # <= 8 d   -> 6 h
        (62 * 86400, 86400),  # <= 62 d  -> 1 day
    ):
        if span <= limit:
            return bucket
    return 7 * 86400


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["timestamp"] = data.pop("ts")
    data["is_private"] = None if data["is_private"] is None else bool(data["is_private"])
    return data


class EventStore:
    """Persistent event storage backed by a single SQLite file."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        """Open (and migrate) the database."""
        with self._lock:
            if self._conn is not None:
                return
            if self._path != ":memory:":
                Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            conn.commit()
            self._conn = conn

    def close(self) -> None:
        """Close the database."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    @property
    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("EventStore is not open")
        return self._conn

    # -- writes ------------------------------------------------------------

    def insert_many(self, events: Sequence[AttackEvent]) -> list[int]:
        """Persist events, assign their ``id`` and return the ids."""
        if not events:
            return []
        ids: list[int] = []
        with self._lock:
            cur = self._db.cursor()
            for ev in events:
                private = ev.is_private
                cur.execute(
                    "INSERT INTO events (ts, source, attack_type, severity, severity_rank, ip,"
                    " is_private, port, username, target, details, raw)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        ev.timestamp,
                        ev.source,
                        str(ev.attack_type),
                        str(ev.severity),
                        SEVERITY_RANK[ev.severity],
                        ev.ip,
                        None if private is None else int(private),
                        ev.port,
                        ev.username,
                        ev.target,
                        ev.details,
                        ev.raw,
                    ),
                )
                ev.id = cur.lastrowid
                ids.append(cur.lastrowid or 0)
            self._db.commit()
        return ids

    def purge(self, older_than: float | None) -> int:
        """Delete events older than ``older_than`` (epoch); ``None`` wipes all."""
        with self._lock:
            if older_than is None:
                cur = self._db.execute("DELETE FROM events")
            else:
                cur = self._db.execute("DELETE FROM events WHERE ts < ?", (older_than,))
            self._db.commit()
            deleted = cur.rowcount
        if deleted > 1000:
            with self._lock:
                self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return deleted

    # -- reads -------------------------------------------------------------

    @staticmethod
    def _where(
        start: float | None,
        end: float | None,
        attack_types: Iterable[str] | None = None,
        severities: Iterable[str] | None = None,
        ip: str | None = None,
        source: str | None = None,
        search: str | None = None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if start is not None:
            clauses.append("ts >= ?")
            params.append(start)
        if end is not None:
            clauses.append("ts <= ?")
            params.append(end)
        if attack_types:
            types = [str(AttackType(t)) for t in attack_types]
            clauses.append(f"attack_type IN ({','.join('?' * len(types))})")
            params.extend(types)
        if severities:
            sevs = [str(Severity(s)) for s in severities]
            clauses.append(f"severity IN ({','.join('?' * len(sevs))})")
            params.extend(sevs)
        if ip:
            clauses.append("ip LIKE ? ESCAPE '\\'")
            params.append(_like(ip))
        if source:
            clauses.append("source LIKE ? ESCAPE '\\'")
            params.append(_like(source))
        if search:
            clauses.append(
                "(ip LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\'"
                " OR target LIKE ? ESCAPE '\\' OR details LIKE ? ESCAPE '\\')"
            )
            params.extend([_like(search)] * 4)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def query_events(
        self,
        start: float | None = None,
        end: float | None = None,
        *,
        attack_types: Iterable[str] | None = None,
        severities: Iterable[str] | None = None,
        ip: str | None = None,
        source: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Return a page of events (newest first) and the total match count."""
        where, params = self._where(start, end, attack_types, severities, ip, source, search)
        limit = max(1, min(int(limit), MAX_PAGE_SIZE))
        offset = max(0, int(offset))
        with self._lock:
            total = self._db.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
            rows = self._db.execute(
                f"SELECT {_COLUMNS} FROM events {where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return {"total": total, "events": [_row_to_dict(r) for r in rows]}

    def stats(
        self,
        start: float,
        end: float,
        *,
        bucket: int | None = None,
        attack_types: Iterable[str] | None = None,
        severities: Iterable[str] | None = None,
        ip: str | None = None,
        source: str | None = None,
        search: str | None = None,
        top: int = 10,
    ) -> dict[str, Any]:
        """Aggregations used by the dashboard for the given period/filters."""
        bucket = int(bucket or auto_bucket(start, end))
        where, params = self._where(start, end, attack_types, severities, ip, source, search)
        with self._lock:
            db = self._db
            total, unique_ips = db.execute(
                f"SELECT COUNT(*), COUNT(DISTINCT ip) FROM events {where}", params
            ).fetchone()
            by_type = db.execute(
                f"SELECT attack_type AS key, COUNT(*) AS count FROM events {where}"
                " GROUP BY attack_type ORDER BY count DESC",
                params,
            ).fetchall()
            by_severity = db.execute(
                f"SELECT severity AS key, COUNT(*) AS count FROM events {where} GROUP BY severity",
                params,
            ).fetchall()
            by_source = db.execute(
                f"SELECT source AS key, COUNT(*) AS count FROM events {where}"
                " GROUP BY source ORDER BY count DESC LIMIT 20",
                params,
            ).fetchall()
            top_ips = db.execute(
                f"SELECT ip, COUNT(*) AS count, MAX(ts) AS last_seen, MIN(ts) AS first_seen,"
                f" MAX(severity_rank) AS max_rank, MAX(is_private) AS is_private,"
                f" GROUP_CONCAT(DISTINCT attack_type) AS types"
                f" FROM events {where}{' AND' if where else ' WHERE'} ip IS NOT NULL"
                f" GROUP BY ip ORDER BY count DESC LIMIT ?",
                [*params, int(top)],
            ).fetchall()
            timeline_rows = db.execute(
                f"SELECT CAST((ts - ?) / ? AS INTEGER) AS b, severity, COUNT(*) AS count"
                f" FROM events {where} GROUP BY b, severity",
                [start, bucket, *params],
            ).fetchall()

        n_buckets = max(1, int((end - start) // bucket) + 1)
        timeline = [
            {"start": start + i * bucket, "low": 0, "medium": 0, "high": 0, "critical": 0}
            for i in range(n_buckets)
        ]
        for row in timeline_rows:
            idx = row["b"]
            if 0 <= idx < n_buckets:
                timeline[idx][row["severity"]] = row["count"]

        rank_to_sev = {v: str(k) for k, v in SEVERITY_RANK.items()}
        return {
            "start": start,
            "end": end,
            "bucket": bucket,
            "total": total,
            "unique_ips": unique_ips,
            "by_type": [dict(r) for r in by_type],
            "by_severity": {r["key"]: r["count"] for r in by_severity},
            "by_source": [dict(r) for r in by_source],
            "top_ips": [
                {
                    "ip": r["ip"],
                    "count": r["count"],
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                    "max_severity": rank_to_sev.get(r["max_rank"], "low"),
                    "is_private": None if r["is_private"] is None else bool(r["is_private"]),
                    "types": sorted((r["types"] or "").split(",")),
                }
                for r in top_ips
            ],
            "timeline": timeline,
        }

    def summary(self, now: float | None = None, under_attack_threshold: int = 20) -> dict[str, Any]:
        """Compact numbers for the sensors."""
        now = now or time.time()
        hour, day, recent = now - 3600, now - 86400, now - 300
        with self._lock:
            db = self._db
            last_hour = db.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (hour,)).fetchone()[0]
            day_total, day_ips, day_high = db.execute(
                "SELECT COUNT(*), COUNT(DISTINCT ip),"
                " COALESCE(SUM(CASE WHEN severity_rank >= 3 THEN 1 ELSE 0 END), 0)"
                " FROM events WHERE ts >= ?",
                (day,),
            ).fetchone()
            recent_count, recent_max = db.execute(
                "SELECT COUNT(*), COALESCE(MAX(severity_rank), 0) FROM events WHERE ts >= ?",
                (recent,),
            ).fetchone()
            hour_max = db.execute(
                "SELECT COALESCE(MAX(severity_rank), 0) FROM events WHERE ts >= ?", (hour,)
            ).fetchone()[0]
            by_type = db.execute(
                "SELECT attack_type, COUNT(*) FROM events WHERE ts >= ? GROUP BY attack_type ORDER BY 2 DESC",
                (day,),
            ).fetchall()
            last = db.execute(f"SELECT {_COLUMNS} FROM events ORDER BY ts DESC, id DESC LIMIT 1").fetchone()
            total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        threat = ThreatLevel(hour_max)
        # Volume alone also raises the level: lots of low-grade noise is a signal.
        if last_hour >= under_attack_threshold * 5:
            threat = max(threat, ThreatLevel.HIGH)
        elif last_hour >= under_attack_threshold:
            threat = max(threat, ThreatLevel.MEDIUM)

        return {
            "last_hour": last_hour,
            "last_24h": day_total,
            "unique_ips_24h": day_ips,
            "high_severity_24h": day_high,
            "recent_5m": recent_count,
            "under_attack": recent_max >= 3 or recent_count >= under_attack_threshold,
            "threat_level": threat.name.lower(),
            "by_type_24h": {t: c for t, c in by_type},
            "last_event": _row_to_dict(last) if last else None,
            "total_stored": total,
        }


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"
