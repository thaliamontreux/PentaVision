"""Camera platform for PentaVision integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, ATTR_CAMERA_ID, ATTR_PTZ_CAPABLE
from .coordinator import PentaVisionCoordinator
from .api import PentaVisionAPI

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up PentaVision cameras from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: PentaVisionCoordinator = data["coordinator"]
    api: PentaVisionAPI = data["api"]

    cameras = []
    for camera_data in coordinator.cameras:
        cameras.append(
            PentaVisionCamera(
                coordinator,
                api,
                entry,
                camera_data,
            )
        )

    async_add_entities(cameras)


class PentaVisionCamera(CoordinatorEntity[PentaVisionCoordinator], Camera):
    """Representation of a PentaVision camera."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: PentaVisionCoordinator,
        api: PentaVisionAPI,
        entry: ConfigEntry,
        camera_data: dict[str, Any],
    ) -> None:
        """Initialize the camera."""
        super().__init__(coordinator)
        Camera.__init__(self)

        self._api = api
        self._camera_id = camera_data.get("id") or camera_data.get("camera_id")
        self._camera_data = camera_data

        # Entity attributes
        self._attr_unique_id = f"{entry.entry_id}_{self._camera_id}"
        self._attr_name = camera_data.get("name", f"Camera {self._camera_id}")

        # Camera features
        features = CameraEntityFeature.STREAM
        if camera_data.get("ptz_capable", False):
            features |= CameraEntityFeature.ON_OFF
        self._attr_supported_features = features

        # Device info
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{entry.entry_id}_{self._camera_id}")},
            name=self._attr_name,
            manufacturer="PentaVision",
            model=camera_data.get("model", "IP Camera"),
            sw_version=camera_data.get("firmware", "Unknown"),
            via_device=(DOMAIN, entry.entry_id),
        )

    @property
    def is_streaming(self) -> bool:
        """Return True if the camera is streaming."""
        return self._camera_data.get("streaming", True)

    @property
    def is_recording(self) -> bool:
        """Return True if the camera is recording."""
        return self._camera_data.get("recording", False)

    @property
    def motion_detection_enabled(self) -> bool:
        """Return True if motion detection is enabled."""
        return self._camera_data.get("motion_detection", False)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            ATTR_CAMERA_ID: self._camera_id,
            ATTR_PTZ_CAPABLE: self._camera_data.get("ptz_capable", False),
            "recording": self.is_recording,
            "motion_detection": self.motion_detection_enabled,
            "stream_url": self._api.get_mjpeg_url(self._camera_id),
        }

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image from the camera."""
        try:
            return await self._api.get_snapshot(self._camera_id)
        except Exception as err:
            _LOGGER.error("Error getting snapshot from %s: %s", self._camera_id, err)
            return None

    async def stream_source(self) -> str | None:
        """Return the stream source URL."""
        return self._api.get_hls_url(self._camera_id)

    @property
    def frontend_stream_type(self) -> str:
        """Return the stream type for the frontend."""
        return "hls"

    async def async_turn_on(self) -> None:
        """Turn on the camera (start streaming)."""
        _LOGGER.debug("Turn on camera %s", self._camera_id)

    async def async_turn_off(self) -> None:
        """Turn off the camera (stop streaming)."""
        _LOGGER.debug("Turn off camera %s", self._camera_id)
