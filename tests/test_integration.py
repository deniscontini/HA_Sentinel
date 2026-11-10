"""End-to-end tests running the integration inside a real Home Assistant core."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
import logging
from pathlib import Path
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ha_sentinel.const import (
    CONF_LOG_PATHS,
    CONF_MONITOR_HA_AUTH,
    CONF_SYSLOG_ALLOWED,
    CONF_SYSLOG_ENABLED,
    CONF_SYSLOG_HOST,
    CONF_SYSLOG_PORT,
    DEFAULT_OPTIONS,
    DOMAIN,
    EVENT_ATTACK_DETECTED,
    HA_BAN_LOGGER,
)


@pytest.fixture(autouse=True)
async def setup_dependencies(hass: HomeAssistant, tmp_path: Path) -> AsyncIterator[None]:
    """Run real http/websocket_api; stub the frontend (needs the frontend wheel)."""
    assert await async_setup_component(hass, "http", {})
    hass.config.components.update({"frontend", "panel_custom"})
    with (
        patch("custom_components.ha_sentinel.manager.DB_FILENAME", str(tmp_path / "sentinel.db")),
        patch("custom_components.ha_sentinel.panel.panel_custom.async_register_panel", AsyncMock()),
        patch("custom_components.ha_sentinel.panel.frontend.async_remove_panel"),
    ):
        yield


async def _setup(hass: HomeAssistant, **options: Any) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN, title="HA Sentinel", data={}, options={**DEFAULT_OPTIONS, **options}
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


async def test_config_flow_creates_single_entry(hass: HomeAssistant) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_MONITOR_HA_AUTH: True, "retention_days": 30}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["options"]["retention_days"] == 30
    await hass.async_block_till_done()

    again = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert again["type"] is FlowResultType.ABORT
    assert again["reason"] == "single_instance_allowed"


async def test_setup_creates_entities_and_unloads(hass: HomeAssistant) -> None:
    entry = await _setup(hass)
    assert entry.state is ConfigEntryState.LOADED
    assert hass.states.get("binary_sensor.ha_sentinel_under_attack").state == "off"
    assert hass.states.get("sensor.ha_sentinel_attacks_last_hour").state == "0"
    assert hass.states.get("sensor.ha_sentinel_threat_level").state == "none"

    assert await hass.config_entries.async_unload(entry.entry_id)
    assert entry.state is ConfigEntryState.NOT_LOADED


async def test_report_event_service_updates_sensors_and_fires_event(hass: HomeAssistant) -> None:
    await _setup(hass)
    fired: list[Any] = []
    hass.bus.async_listen(EVENT_ATTACK_DETECTED, fired.append)

    response = await hass.services.async_call(
        DOMAIN,
        "report_event",
        {"attack_type": "sql_injection", "ip": "203.0.113.5", "source": "pytest"},
        blocking=True,
        return_response=True,
    )
    assert response == {"stored": 1, "ids": [1]}
    await hass.async_block_till_done()

    assert hass.states.get("sensor.ha_sentinel_attacks_last_hour").state == "1"
    assert hass.states.get("sensor.ha_sentinel_last_attack").state == "sql_injection"
    assert hass.states.get("binary_sensor.ha_sentinel_under_attack").state == "on"
    assert hass.states.get("sensor.ha_sentinel_threat_level").state == "high"
    assert len(fired) == 1 and fired[0].data["ip"] == "203.0.113.5"


async def test_ha_failed_login_log_is_captured(hass: HomeAssistant) -> None:
    await _setup(hass, brute_force_threshold=3)
    logger = logging.getLogger(HA_BAN_LOGGER)
    for _ in range(3):
        logger.warning(
            "Login attempt or request with invalid authentication from bad.example (198.51.100.66). "
            "Requested URL: '/auth/login_flow/x'. (curl/8.0)"
        )
    await asyncio.sleep(0.7)  # submit buffer flush delay
    await hass.async_block_till_done()

    runtime = hass.config_entries.async_loaded_entries(DOMAIN)[0].runtime_data
    events = await hass.async_add_executor_job(runtime.manager.store.query_events)
    types = sorted(e["attack_type"] for e in events["events"])
    assert types == ["brute_force", "failed_login", "failed_login", "failed_login"]
    assert all(e["ip"] == "198.51.100.66" for e in events["events"])


async def test_log_file_source(hass: HomeAssistant, tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text("")
    hass.config.allowlist_external_dirs = {str(tmp_path)}
    await _setup(hass, **{CONF_LOG_PATHS: str(log), "poll_interval": 1})
    with log.open("a") as fh:
        fh.write('203.0.113.9 - - [10/Nov/2026:13:55:36 -0300] "GET /.env HTTP/1.1" 404 1 "-" "zgrab/0.x"\n')

    runtime = hass.config_entries.async_loaded_entries(DOMAIN)[0].runtime_data
    source = next(s for s in runtime.manager.sources if s.name == "log_files")
    await source._async_do_poll()
    await hass.async_block_till_done()

    events = await hass.async_add_executor_job(runtime.manager.store.query_events)
    assert events["total"] == 1
    assert events["events"][0]["attack_type"] == "sensitive_file_probe"
    assert events["events"][0]["source"] == "file:access.log"


async def test_syslog_source(hass: HomeAssistant) -> None:
    endpoint = AsyncMock(return_value=(MagicMock(), None))
    with patch.object(hass.loop, "create_datagram_endpoint", endpoint):
        await _setup(
            hass,
            **{
                CONF_SYSLOG_ENABLED: True,
                CONF_SYSLOG_HOST: "127.0.0.1",
                CONF_SYSLOG_PORT: 5514,
                CONF_SYSLOG_ALLOWED: "10.0.0.0/8",
            },
        )
    assert endpoint.call_args.kwargs["local_addr"] == ("127.0.0.1", 5514)

    runtime = hass.config_entries.async_loaded_entries(DOMAIN)[0].runtime_data
    source = next(s for s in runtime.manager.sources if s.name == "syslog")
    line = b"<38>Nov 10 13:00:01 nas sshd[1]: Failed password for root from 203.0.113.77 port 4242 ssh2"
    source.handle_datagram(line, "10.1.2.3")
    source.handle_datagram(line, "192.168.1.50")  # not in allowed senders
    await asyncio.sleep(0.7)
    await hass.async_block_till_done()

    events = await hass.async_add_executor_job(runtime.manager.store.query_events)
    assert events["total"] == 1
    assert events["events"][0]["source"] == "syslog:10.1.2.3"
    assert events["events"][0]["username"] == "root"
    assert source.rejected == 1


async def test_websocket_api(hass: HomeAssistant, hass_ws_client: Any) -> None:
    await _setup(hass)
    await hass.services.async_call(DOMAIN, "generate_test_events", {"count": 40, "hours": 2}, blocking=True)

    client = await hass_ws_client(hass)
    now = time.time()
    await client.send_json_auto_id({"type": "ha_sentinel/stats", "start": now - 3 * 3600, "end": now + 1})
    stats = (await client.receive_json())["result"]
    assert stats["total"] == 40
    assert sum(r["count"] for r in stats["by_type"]) == 40

    await client.send_json_auto_id(
        {
            "type": "ha_sentinel/events",
            "start": now - 3 * 3600,
            "end": now + 1,
            "limit": 10,
            "severities": ["low"],
        }
    )
    page = (await client.receive_json())["result"]
    assert len(page["events"]) <= 10
    assert all(e["severity"] == "low" for e in page["events"])

    await client.send_json_auto_id({"type": "ha_sentinel/subscribe"})
    assert (await client.receive_json())["success"]
    await hass.services.async_call(
        DOMAIN, "report_event", {"attack_type": "xss", "ip": "192.0.2.1"}, blocking=True
    )
    pushed = await client.receive_json()
    assert pushed["event"]["events"][0]["attack_type"] == "xss"

    await client.send_json_auto_id({"type": "ha_sentinel/stats", "start": now, "end": now - 1})
    assert (await client.receive_json())["error"]["code"] == "invalid_period"


async def test_options_flow_validates_paths(hass: HomeAssistant, tmp_path: Path) -> None:
    entry = await _setup(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM

    def _payload(paths: str, ignored: str = "") -> dict[str, Any]:
        return {
            "sources": {"monitor_ha_auth": True, "log_paths": paths, "poll_interval": 5},
            "syslog": {
                "syslog_enabled": False,
                "syslog_host": "0.0.0.0",
                "syslog_port": 5514,
                "syslog_allowed_senders": "",
            },
            "detection": {
                "brute_force_threshold": 5,
                "brute_force_window": 300,
                "port_scan_threshold": 10,
                "port_scan_window": 60,
                "under_attack_threshold": 20,
                "ignored_networks": ignored,
            },
            "general": {"retention_days": 90, "bus_event_min_severity": "high"},
        }

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], _payload("relative/path.log")
    )
    assert result["errors"] == {"sources": "path_not_absolute"}

    result = await hass.config_entries.options.async_configure(result["flow_id"], _payload("", "not-an-ip"))
    assert result["errors"] == {"detection": "invalid_network"}

    log = tmp_path / "auth.log"
    log.write_text("")
    hass.config.allowlist_external_dirs = {str(tmp_path)}
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], _payload(str(log), "192.168.0.0/16")
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.options[CONF_LOG_PATHS] == str(log)
    await hass.async_block_till_done()
