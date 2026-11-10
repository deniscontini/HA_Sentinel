"""Constants for HA Sentinel."""

from __future__ import annotations

from typing import Any, Final

DOMAIN: Final = "ha_sentinel"
NAME: Final = "HA Sentinel"
VERSION: Final = "0.1.0"

DB_FILENAME: Final = "ha_sentinel.db"

PANEL_URL_PATH: Final = "ha-sentinel"
PANEL_COMPONENT: Final = "ha-sentinel-panel"
PANEL_TITLE: Final = "Sentinel"
PANEL_ICON: Final = "mdi:shield-alert"
STATIC_URL: Final = "/ha_sentinel_static"

SIGNAL_NEW_EVENTS: Final = f"{DOMAIN}_new_events"
EVENT_ATTACK_DETECTED: Final = f"{DOMAIN}_attack_detected"

# Logger used by Home Assistant core for failed logins and IP bans.
HA_BAN_LOGGER: Final = "homeassistant.components.http.ban"

# --- Options ---------------------------------------------------------------
CONF_RETENTION_DAYS: Final = "retention_days"
CONF_MONITOR_HA_AUTH: Final = "monitor_ha_auth"
CONF_LOG_PATHS: Final = "log_paths"
CONF_POLL_INTERVAL: Final = "poll_interval"
CONF_SYSLOG_ENABLED: Final = "syslog_enabled"
CONF_SYSLOG_HOST: Final = "syslog_host"
CONF_SYSLOG_PORT: Final = "syslog_port"
CONF_SYSLOG_ALLOWED: Final = "syslog_allowed_senders"
CONF_IGNORED_NETWORKS: Final = "ignored_networks"
CONF_BRUTE_FORCE_THRESHOLD: Final = "brute_force_threshold"
CONF_BRUTE_FORCE_WINDOW: Final = "brute_force_window"
CONF_PORT_SCAN_THRESHOLD: Final = "port_scan_threshold"
CONF_PORT_SCAN_WINDOW: Final = "port_scan_window"
CONF_UNDER_ATTACK_THRESHOLD: Final = "under_attack_threshold"
CONF_BUS_EVENT_MIN_SEVERITY: Final = "bus_event_min_severity"

DEFAULT_OPTIONS: Final[dict[str, Any]] = {
    CONF_RETENTION_DAYS: 90,
    CONF_MONITOR_HA_AUTH: True,
    CONF_LOG_PATHS: "",
    CONF_POLL_INTERVAL: 5,
    CONF_SYSLOG_ENABLED: False,
    CONF_SYSLOG_HOST: "0.0.0.0",
    CONF_SYSLOG_PORT: 5514,
    CONF_SYSLOG_ALLOWED: "",
    CONF_IGNORED_NETWORKS: "",
    CONF_BRUTE_FORCE_THRESHOLD: 5,
    CONF_BRUTE_FORCE_WINDOW: 300,
    CONF_PORT_SCAN_THRESHOLD: 10,
    CONF_PORT_SCAN_WINDOW: 60,
    CONF_UNDER_ATTACK_THRESHOLD: 20,
    CONF_BUS_EVENT_MIN_SEVERITY: "high",
}

SEVERITY_OPTIONS: Final = ["low", "medium", "high", "critical"]

# --- Services --------------------------------------------------------------
SERVICE_REPORT_EVENT: Final = "report_event"
SERVICE_PURGE_EVENTS: Final = "purge_events"
SERVICE_GENERATE_TEST_EVENTS: Final = "generate_test_events"

SUMMARY_UPDATE_SECONDS: Final = 60
PURGE_INTERVAL_HOURS: Final = 6


def split_lines(value: str | None) -> list[str]:
    """Split a multiline/comma separated option into clean items."""
    if not value:
        return []
    items = (part.strip() for line in value.splitlines() for part in line.split(","))
    return [item for item in items if item and not item.startswith("#")]
