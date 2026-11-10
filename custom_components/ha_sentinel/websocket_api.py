"""Websocket commands consumed by the dashboard panel."""

from __future__ import annotations

from typing import Any

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.dispatcher import async_dispatcher_connect
import voluptuous as vol

from .const import SIGNAL_NEW_EVENTS, VERSION
from .engine import AttackType, Severity
from .engine.store import MAX_PAGE_SIZE
from .helpers import get_runtime

_FILTERS = {
    vol.Optional("attack_types"): [vol.In([str(t) for t in AttackType])],
    vol.Optional("severities"): [vol.In([str(s) for s in Severity])],
    vol.Optional("ip"): vol.All(str, vol.Length(max=64)),
    vol.Optional("source"): vol.All(str, vol.Length(max=128)),
    vol.Optional("search"): vol.All(str, vol.Length(max=256)),
}
_PERIOD = {
    vol.Required("start"): vol.Coerce(float),
    vol.Required("end"): vol.Coerce(float),
}


@callback
def async_register_websocket_api(hass: HomeAssistant) -> None:
    """Register all websocket commands."""
    websocket_api.async_register_command(hass, ws_info)
    websocket_api.async_register_command(hass, ws_stats)
    websocket_api.async_register_command(hass, ws_events)
    websocket_api.async_register_command(hass, ws_subscribe)


def _filters(msg: dict[str, Any]) -> dict[str, Any]:
    return {key: msg[key] for key in ("attack_types", "severities", "ip", "source", "search") if msg.get(key)}


def _check_period(connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> bool:
    if msg["end"] <= msg["start"]:
        connection.send_error(msg["id"], "invalid_period", "end must be greater than start")
        return False
    return True


@websocket_api.websocket_command({vol.Required("type"): "ha_sentinel/info"})
@websocket_api.require_admin
@callback
def ws_info(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    """Version, available categories and source status."""
    try:
        runtime = get_runtime(hass)
    except HomeAssistantError as err:
        connection.send_error(msg["id"], "not_loaded", str(err))
        return
    connection.send_result(
        msg["id"],
        {
            "version": VERSION,
            "attack_types": [str(t) for t in AttackType],
            "severities": [str(s) for s in Severity],
            "status": runtime.manager.status(),
        },
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "ha_sentinel/stats",
        **_PERIOD,
        **_FILTERS,
        vol.Optional("bucket"): vol.All(vol.Coerce(int), vol.Range(min=60)),
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_stats(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Aggregated statistics for a period."""
    if not _check_period(connection, msg):
        return
    try:
        store = get_runtime(hass).manager.store
    except HomeAssistantError as err:
        connection.send_error(msg["id"], "not_loaded", str(err))
        return

    def _run() -> dict[str, Any]:
        return store.stats(msg["start"], msg["end"], bucket=msg.get("bucket"), **_filters(msg))

    connection.send_result(msg["id"], await hass.async_add_executor_job(_run))


@websocket_api.websocket_command(
    {
        vol.Required("type"): "ha_sentinel/events",
        **_PERIOD,
        **_FILTERS,
        vol.Optional("limit", default=50): vol.All(vol.Coerce(int), vol.Range(min=1, max=MAX_PAGE_SIZE)),
        vol.Optional("offset", default=0): vol.All(vol.Coerce(int), vol.Range(min=0)),
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_events(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """A page of events, newest first."""
    if not _check_period(connection, msg):
        return
    try:
        store = get_runtime(hass).manager.store
    except HomeAssistantError as err:
        connection.send_error(msg["id"], "not_loaded", str(err))
        return

    def _run() -> dict[str, Any]:
        return store.query_events(
            msg["start"], msg["end"], limit=msg["limit"], offset=msg["offset"], **_filters(msg)
        )

    connection.send_result(msg["id"], await hass.async_add_executor_job(_run))


@websocket_api.websocket_command({vol.Required("type"): "ha_sentinel/subscribe"})
@websocket_api.require_admin
@callback
def ws_subscribe(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Push new events to the panel as they are stored."""

    @callback
    def _forward(events: list[dict[str, Any]]) -> None:
        connection.send_message(websocket_api.event_message(msg["id"], {"events": events}))

    connection.subscriptions[msg["id"]] = async_dispatcher_connect(hass, SIGNAL_NEW_EVENTS, _forward)
    connection.send_result(msg["id"])
