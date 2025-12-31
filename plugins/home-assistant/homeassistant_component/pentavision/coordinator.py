"""Data coordinator for PentaVision integration."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import PentaVisionAPI, PentaVisionAPIError
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=30)


class PentaVisionCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator to manage fetching PentaVision data."""

    def __init__(self, hass: HomeAssistant, api: PentaVisionAPI) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=SCAN_INTERVAL,
        )
        self.api = api
        self.cameras: list[dict[str, Any]] = []

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from PentaVision API."""
        try:
            # Get server status
            status = await self.api.get_status()

            # Get cameras list
            self.cameras = await self.api.get_cameras()

            return {
                "status": status,
                "cameras": self.cameras,
                "camera_count": len(self.cameras),
                "server_online": True,
            }

        except PentaVisionAPIError as err:
            # Try to re-authenticate if session expired
            if err.code == "SESSION_INVALID":
                _LOGGER.info("Session expired, re-authenticating...")
                if await self.api.authenticate():
                    # Retry the request
                    return await self._async_update_data()

            raise UpdateFailed(f"Error communicating with PentaVision: {err}") from err

        except Exception as err:
            raise UpdateFailed(f"Unexpected error: {err}") from err
