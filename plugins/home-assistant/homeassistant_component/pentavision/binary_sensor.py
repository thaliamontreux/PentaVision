"""Binary sensor platform for PentaVision integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, ATTR_CAMERA_ID
from .coordinator import PentaVisionCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up PentaVision binary sensors from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: PentaVisionCoordinator = data["coordinator"]

    sensors = []

    # Create motion detection sensors for each camera
    for camera_data in coordinator.cameras:
        camera_id = camera_data.get("id") or camera_data.get("camera_id")
        camera_name = camera_data.get("name", f"Camera {camera_id}")

        # Motion detection sensor
        sensors.append(
            PentaVisionMotionSensor(
                coordinator,
                entry,
                camera_id,
                camera_name,
            )
        )

        # Camera online sensor
        sensors.append(
            PentaVisionCameraOnlineSensor(
                coordinator,
                entry,
                camera_id,
                camera_name,
            )
        )

    async_add_entities(sensors)


class PentaVisionMotionSensor(CoordinatorEntity[PentaVisionCoordinator], BinarySensorEntity):
    """Binary sensor for camera motion detection."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.MOTION

    def __init__(
        self,
        coordinator: PentaVisionCoordinator,
        entry: ConfigEntry,
        camera_id: str,
        camera_name: str,
    ) -> None:
        """Initialize the motion sensor."""
        super().__init__(coordinator)

        self._camera_id = camera_id
        self._attr_unique_id = f"{entry.entry_id}_{camera_id}_motion"
        self._attr_name = f"{camera_name} Motion"

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{entry.entry_id}_{camera_id}")},
            name=camera_name,
            manufacturer="PentaVision",
            via_device=(DOMAIN, entry.entry_id),
        )

    @property
    def is_on(self) -> bool | None:
        """Return True if motion is detected."""
        if self.coordinator.data is None:
            return None

        for camera in self.coordinator.data.get("cameras", []):
            cam_id = camera.get("id") or camera.get("camera_id")
            if cam_id == self._camera_id:
                return camera.get("motion_detected", False)

        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            ATTR_CAMERA_ID: self._camera_id,
        }


class PentaVisionCameraOnlineSensor(CoordinatorEntity[PentaVisionCoordinator], BinarySensorEntity):
    """Binary sensor for camera online status."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self,
        coordinator: PentaVisionCoordinator,
        entry: ConfigEntry,
        camera_id: str,
        camera_name: str,
    ) -> None:
        """Initialize the online sensor."""
        super().__init__(coordinator)

        self._camera_id = camera_id
        self._attr_unique_id = f"{entry.entry_id}_{camera_id}_online"
        self._attr_name = f"{camera_name} Online"

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{entry.entry_id}_{camera_id}")},
            name=camera_name,
            manufacturer="PentaVision",
            via_device=(DOMAIN, entry.entry_id),
        )

    @property
    def is_on(self) -> bool | None:
        """Return True if camera is online."""
        if self.coordinator.data is None:
            return None

        for camera in self.coordinator.data.get("cameras", []):
            cam_id = camera.get("id") or camera.get("camera_id")
            if cam_id == self._camera_id:
                return camera.get("online", True)

        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            ATTR_CAMERA_ID: self._camera_id,
        }
