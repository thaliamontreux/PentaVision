"""Config flow for PentaVision integration."""
from __future__ import annotations

import hashlib
import logging
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import CONF_API_KEY, DEFAULT_PORT, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_API_KEY): str,
    }
)


class PentaVisionConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for PentaVision."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST]
            port = user_input[CONF_PORT]
            api_key = user_input[CONF_API_KEY]

            # Test connection
            try:
                session = async_get_clientsession(self.hass)
                url = f"http://{host}:{port}/api/auth/handshake/init"

                async with session.post(
                    url,
                    json={"api_key_hash": hashlib.sha256(api_key.encode()).hexdigest()},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "challenge" in data:
                            # Connection successful
                            await self.async_set_unique_id(f"{host}:{port}")
                            self._abort_if_unique_id_configured()

                            return self.async_create_entry(
                                title=f"PentaVision ({host})",
                                data=user_input,
                            )
                        else:
                            errors["base"] = "invalid_response"
                    elif response.status == 403:
                        errors["base"] = "invalid_api_key"
                    else:
                        errors["base"] = "cannot_connect"

            except aiohttp.ClientConnectorError:
                errors["base"] = "cannot_connect"
            except aiohttp.ClientError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )


class PentaVisionOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow for PentaVision."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        "scan_interval",
                        default=self.config_entry.options.get("scan_interval", 30),
                    ): vol.All(vol.Coerce(int), vol.Range(min=10, max=300)),
                }
            ),
        )
