"""Service actions."""

from __future__ import annotations

import time

from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse, callback
from homeassistant.helpers import config_validation as cv
import voluptuous as vol

from .const import (
    DOMAIN,
    SERVICE_GENERATE_TEST_EVENTS,
    SERVICE_PURGE_EVENTS,
    SERVICE_REPORT_EVENT,
)
from .engine import AttackEvent, AttackType, Severity
from .engine.models import DEFAULT_SEVERITY
from .helpers import get_runtime

REPORT_SCHEMA = vol.Schema(
    {
        vol.Required("attack_type"): vol.In([str(t) for t in AttackType]),
        vol.Optional("ip"): vol.All(cv.string, vol.Length(max=64)),
        vol.Optional("severity"): vol.In([str(s) for s in Severity]),
        vol.Optional("source", default="service"): vol.All(cv.string, vol.Length(max=64)),
        vol.Optional("port"): vol.All(vol.Coerce(int), vol.Range(min=0, max=65535)),
        vol.Optional("username"): cv.string,
        vol.Optional("target"): cv.string,
        vol.Optional("details"): cv.string,
    }
)
PURGE_SCHEMA = vol.Schema(
    {vol.Required("older_than_days"): vol.All(vol.Coerce(int), vol.Range(min=0, max=3650))}
)
TEST_SCHEMA = vol.Schema(
    {
        vol.Optional("count", default=100): vol.All(vol.Coerce(int), vol.Range(min=1, max=5000)),
        vol.Optional("hours", default=24): vol.All(vol.Coerce(float), vol.Range(min=0.1, max=24 * 90)),
    }
)


@callback
def async_register_services(hass: HomeAssistant) -> None:
    """Register integration services (once, independent of config entries)."""

    async def report_event(call: ServiceCall) -> ServiceResponse:
        manager = get_runtime(hass).manager
        attack_type = AttackType(call.data["attack_type"])
        severity = (
            Severity(call.data["severity"]) if "severity" in call.data else DEFAULT_SEVERITY[attack_type]
        )
        event = AttackEvent(
            attack_type=attack_type,
            severity=severity,
            source=call.data["source"],
            ip=call.data.get("ip"),
            timestamp=time.time(),
            port=call.data.get("port"),
            username=call.data.get("username"),
            target=call.data.get("target"),
            details=call.data.get("details"),
        )
        stored = await manager.async_ingest([event])
        return {"stored": len(stored), "ids": [e.id for e in stored]}

    async def purge_events(call: ServiceCall) -> ServiceResponse:
        manager = get_runtime(hass).manager
        days = call.data["older_than_days"]
        deleted = await manager.async_purge(None if days == 0 else time.time() - days * 86400)
        return {"deleted": deleted}

    async def generate_test_events(call: ServiceCall) -> ServiceResponse:
        manager = get_runtime(hass).manager
        created = await manager.async_generate_test_events(call.data["count"], call.data["hours"])
        return {"created": created}

    hass.services.async_register(
        DOMAIN, SERVICE_REPORT_EVENT, report_event, REPORT_SCHEMA, supports_response=SupportsResponse.OPTIONAL
    )
    hass.services.async_register(
        DOMAIN, SERVICE_PURGE_EVENTS, purge_events, PURGE_SCHEMA, supports_response=SupportsResponse.OPTIONAL
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_GENERATE_TEST_EVENTS,
        generate_test_events,
        TEST_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )
