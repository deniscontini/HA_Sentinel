"""Sensors exposing attack statistics."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.typing import StateType

from .coordinator import SentinelConfigEntry
from .engine import AttackType, ThreatLevel
from .entity import SentinelEntity

PARALLEL_UPDATES = 0


def _last(data: dict[str, Any]) -> dict[str, Any] | None:
    return data.get("last_event")


def _last_attrs(data: dict[str, Any]) -> dict[str, Any]:
    last = _last(data)
    if not last:
        return {}
    return {
        "ip": last.get("ip"),
        "severity": last.get("severity"),
        "source": last.get("source"),
        "target": last.get("target"),
        "username": last.get("username"),
        "details": last.get("details"),
        "is_private": last.get("is_private"),
    }


def _last_time(data: dict[str, Any]) -> datetime | None:
    last = _last(data)
    return datetime.fromtimestamp(last["timestamp"], tz=UTC) if last else None


@dataclass(frozen=True, kw_only=True)
class SentinelSensorDescription(SensorEntityDescription):
    """Sensor description with value extractors."""

    value_fn: Callable[[dict[str, Any]], StateType | datetime]
    attrs_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None


SENSORS: tuple[SentinelSensorDescription, ...] = (
    SentinelSensorDescription(
        key="attacks_last_hour",
        translation_key="attacks_last_hour",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d["last_hour"],
    ),
    SentinelSensorDescription(
        key="attacks_last_24h",
        translation_key="attacks_last_24h",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d["last_24h"],
        attrs_fn=lambda d: {"by_type": d["by_type_24h"]},
    ),
    SentinelSensorDescription(
        key="unique_attackers_24h",
        translation_key="unique_attackers_24h",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d["unique_ips_24h"],
    ),
    SentinelSensorDescription(
        key="high_severity_24h",
        translation_key="high_severity_24h",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d["high_severity_24h"],
    ),
    SentinelSensorDescription(
        key="threat_level",
        translation_key="threat_level",
        device_class=SensorDeviceClass.ENUM,
        options=[level.name.lower() for level in ThreatLevel],
        value_fn=lambda d: d["threat_level"],
    ),
    SentinelSensorDescription(
        key="last_attack",
        translation_key="last_attack",
        device_class=SensorDeviceClass.ENUM,
        options=[str(t) for t in AttackType],
        value_fn=lambda d: last["attack_type"] if (last := _last(d)) else None,
        attrs_fn=_last_attrs,
    ),
    SentinelSensorDescription(
        key="last_attack_time",
        translation_key="last_attack_time",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=_last_time,
    ),
    SentinelSensorDescription(
        key="stored_events",
        translation_key="stored_events",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=lambda d: d["total_stored"],
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SentinelConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up sensors."""
    coordinator = entry.runtime_data.coordinator
    async_add_entities(SentinelSensor(coordinator, description) for description in SENSORS)


class SentinelSensor(SentinelEntity, SensorEntity):
    """A summary sensor."""

    entity_description: SentinelSensorDescription

    @property
    def native_value(self) -> StateType | datetime:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.coordinator.data)
