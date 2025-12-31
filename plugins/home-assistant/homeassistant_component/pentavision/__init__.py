"""PentaVision integration for Home Assistant."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import DOMAIN, CONF_HOST, CONF_PORT, CONF_API_KEY
from .coordinator import PentaVisionCoordinator
from .api import PentaVisionAPI

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.CAMERA, Platform.BINARY_SENSOR, Platform.SENSOR]

SCAN_INTERVAL = timedelta(seconds=30)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up PentaVision from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    host = entry.data[CONF_HOST]
    port = entry.data[CONF_PORT]
    api_key = entry.data[CONF_API_KEY]

    session = async_get_clientsession(hass)
    api = PentaVisionAPI(host, port, api_key, session)

    # Perform handshake to get session token
    if not await api.authenticate():
        _LOGGER.error("Failed to authenticate with PentaVision server")
        return False

    coordinator = PentaVisionCoordinator(hass, api)
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "coordinator": coordinator,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data = hass.data[DOMAIN].pop(entry.entry_id)
        # Revoke session on unload
        api: PentaVisionAPI = data["api"]
        await api.revoke_session()

    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
