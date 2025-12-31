"""Sensor platform for PentaVision integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import PentaVisionCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up PentaVision sensors from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: PentaVisionCoordinator = data["coordinator"]

    sensors = [
        PentaVisionServerSensor(coordinator, entry, "camera_count", "Cameras"),
        PentaVisionServerSensor(coordinator, entry, "server_online", "Server Status"),
    ]

    async_add_entities(sensors)


class PentaVisionServerSensor(CoordinatorEntity[PentaVisionCoordinator], SensorEntity):
    """Sensor for PentaVision server statistics."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: PentaVisionCoordinator,
        entry: ConfigEntry,
        sensor_type: str,
        name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)

        self._sensor_type = sensor_type
        self._attr_unique_id = f"{entry.entry_id}_{sensor_type}"
        self._attr_name = name

        # Device info - associate with the main PentaVision device
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="PentaVision Server",
            manufacturer="PentaVision",
            model="Video Tunnel Server",
        )

        # Sensor-specific configuration
        if sensor_type == "camera_count":
            self._attr_state_class = SensorStateClass.MEASUREMENT
            self._attr_icon = "mdi:camera"
        elif sensor_type == "server_online":
            self._attr_icon = "mdi:server"

    @property
    def native_value(self) -> Any:
        """Return the sensor value."""
        if self.coordinator.data is None:
            return None

        if self._sensor_type == "camera_count":
            return self.coordinator.data.get("camera_count", 0)
        elif self._sensor_type == "server_online":
            return "Online" if self.coordinator.data.get("server_online") else "Offline"

        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        if self.coordinator.data is None:
            return {}

        if self._sensor_type == "server_online":
            status = self.coordinator.data.get("status", {})
            return {
                "requests_total": status.get("requests_total", 0),
                "requests_authenticated": status.get("requests_authenticated", 0),
                "active_streams": status.get("active_streams", 0),
                "uptime": status.get("uptime"),
            }

        return {}
