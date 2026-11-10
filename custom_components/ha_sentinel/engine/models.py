"""Core data model for HA Sentinel.

This package (``engine``) is intentionally free of Home Assistant imports so it
can be unit-tested in isolation and reused by other front-ends (e.g. an add-on).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum, StrEnum
import ipaddress
import time
from typing import Any


class AttackType(StrEnum):
    """Categories of detected malicious activity."""

    FAILED_LOGIN = "failed_login"
    BRUTE_FORCE = "brute_force"
    BANNED_IP = "banned_ip"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    LOG4SHELL = "log4shell"
    SHELLSHOCK = "shellshock"
    SENSITIVE_FILE_PROBE = "sensitive_file_probe"
    SCANNER = "scanner"
    PORT_SCAN = "port_scan"
    FIREWALL_BLOCK = "firewall_block"
    SUSPICIOUS_REQUEST = "suspicious_request"
    OTHER = "other"


class Severity(StrEnum):
    """Severity of an event, ordered from least to most severe."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank used for ordering and SQL filtering."""
        return SEVERITY_RANK[self]


class ThreatLevel(IntEnum):
    """Overall threat level exposed by the threat-level sensor."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Default severity per attack type (rules may override it).
DEFAULT_SEVERITY: dict[AttackType, Severity] = {
    AttackType.FAILED_LOGIN: Severity.LOW,
    AttackType.BRUTE_FORCE: Severity.HIGH,
    AttackType.BANNED_IP: Severity.HIGH,
    AttackType.SQL_INJECTION: Severity.HIGH,
    AttackType.XSS: Severity.MEDIUM,
    AttackType.PATH_TRAVERSAL: Severity.HIGH,
    AttackType.COMMAND_INJECTION: Severity.CRITICAL,
    AttackType.LOG4SHELL: Severity.CRITICAL,
    AttackType.SHELLSHOCK: Severity.CRITICAL,
    AttackType.SENSITIVE_FILE_PROBE: Severity.MEDIUM,
    AttackType.SCANNER: Severity.MEDIUM,
    AttackType.PORT_SCAN: Severity.HIGH,
    AttackType.FIREWALL_BLOCK: Severity.LOW,
    AttackType.SUSPICIOUS_REQUEST: Severity.LOW,
    AttackType.OTHER: Severity.MEDIUM,
}


def is_private_ip(value: str | None) -> bool | None:
    """Return True for LAN/loopback addresses, False for public, None if not an IP."""
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _clip(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return value if len(value) <= limit else value[: limit - 1] + "…"


@dataclass(slots=True)
class AttackEvent:
    """A single detected attack attempt."""

    attack_type: AttackType
    severity: Severity
    source: str
    ip: str | None = None
    timestamp: float = field(default_factory=time.time)
    port: int | None = None
    username: str | None = None
    target: str | None = None
    details: str | None = None
    raw: str | None = None
    id: int | None = None

    def __post_init__(self) -> None:
        # Attacker-controlled strings are clipped to keep the DB and UI sane.
        self.username = _clip(self.username, 128)
        self.target = _clip(self.target, 512)
        self.details = _clip(self.details, 1024)
        self.raw = _clip(self.raw, 2048)
        if self.ip:
            self.ip = self.ip.strip("[]")

    @property
    def is_private(self) -> bool | None:
        """Whether the origin IP belongs to a private network."""
        return is_private_ip(self.ip)

    def as_dict(self) -> dict[str, Any]:
        """Serialize for websocket/bus consumers."""
        data = asdict(self)
        data["attack_type"] = str(self.attack_type)
        data["severity"] = str(self.severity)
        data["is_private"] = self.is_private
        return data


@dataclass(slots=True)
class ParsedLine:
    """Intermediate result of a rule match before an event is built."""

    attack_type: AttackType
    ip: str | None
    severity: Severity | None = None
    port: int | None = None
    username: str | None = None
    target: str | None = None
    details: str | None = None
    matches: list[str] = field(default_factory=list)

    def to_event(self, source: str, raw: str | None = None) -> AttackEvent:
        """Build an :class:`AttackEvent` from this match."""
        return AttackEvent(
            attack_type=self.attack_type,
            severity=self.severity or DEFAULT_SEVERITY[self.attack_type],
            source=source,
            ip=self.ip,
            port=self.port,
            username=self.username,
            target=self.target,
            details=self.details,
            raw=raw,
        )
