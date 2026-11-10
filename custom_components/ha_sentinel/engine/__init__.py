"""Home-Assistant-independent detection engine for HA Sentinel."""

from .correlator import Correlator, CorrelatorConfig
from .models import AttackEvent, AttackType, ParsedLine, Severity, ThreatLevel
from .rules import parse_ha_auth_message, parse_line, strip_syslog_header
from .store import EventStore, auto_bucket
from .tailer import LogTailer

__all__ = [
    "AttackEvent",
    "AttackType",
    "Correlator",
    "CorrelatorConfig",
    "EventStore",
    "LogTailer",
    "ParsedLine",
    "Severity",
    "ThreatLevel",
    "auto_bucket",
    "parse_ha_auth_message",
    "parse_line",
    "strip_syslog_header",
]
