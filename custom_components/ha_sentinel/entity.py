"""Base entity for HA Sentinel."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, NAME, VERSION
from .coordinator import SentinelCoordinator


class SentinelEntity(CoordinatorEntity[SentinelCoordinator]):
    """Common device/unique-id handling."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: SentinelCoordinator, description: EntityDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        entry_id = coordinator.config_entry.entry_id
        self._attr_unique_id = f"{entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry_id)},
            name=NAME,
            manufacturer=NAME,
            model="Attack monitor",
            sw_version=VERSION,
            entry_type=DeviceEntryType.SERVICE,
        )
