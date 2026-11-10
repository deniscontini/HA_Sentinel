"""Binary sensor that turns on while an attack is in progress."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import SentinelConfigEntry
from .entity import SentinelEntity

PARALLEL_UPDATES = 0

UNDER_ATTACK = BinarySensorEntityDescription(
    key="under_attack",
    translation_key="under_attack",
    device_class=BinarySensorDeviceClass.SAFETY,  # on = unsafe
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SentinelConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the binary sensor."""
    async_add_entities([UnderAttackBinarySensor(entry.runtime_data.coordinator, UNDER_ATTACK)])


class UnderAttackBinarySensor(SentinelEntity, BinarySensorEntity):
    """On when a high/critical event or a burst of events happened in the last 5 minutes."""

    @property
    def is_on(self) -> bool:
        return bool(self.coordinator.data["under_attack"])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "events_last_5m": self.coordinator.data["recent_5m"],
            "threshold": self.coordinator.manager.under_attack_threshold,
        }
