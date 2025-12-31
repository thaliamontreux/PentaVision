"""PentaVision API client for Home Assistant."""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any

import aiohttp

from .const import (
    API_CAMERAS,
    API_CAMERA_INFO,
    API_CAMERA_SNAPSHOT,
    API_HANDSHAKE_COMPLETE,
    API_HANDSHAKE_INIT,
    API_HLS_PLAYLIST,
    API_MJPEG_STREAM,
    API_PTZ,
    API_SESSION_REVOKE,
    API_STATUS,
)

_LOGGER = logging.getLogger(__name__)


class PentaVisionAPIError(Exception):
    """Exception for PentaVision API errors."""

    def __init__(self, message: str, code: str | None = None):
        """Initialize the exception."""
        super().__init__(message)
        self.code = code


class PentaVisionAPI:
    """API client for PentaVision Video Tunnel."""

    def __init__(
        self,
        host: str,
        port: int,
        api_key: str,
        session: aiohttp.ClientSession,
    ) -> None:
        """Initialize the API client."""
        self.host = host
        self.port = port
        self.api_key = api_key
        self._session = session
        self._session_token: str | None = None
        self._base_url = f"http://{host}:{port}"

    @property
    def authenticated(self) -> bool:
        """Return True if we have a valid session token."""
        return self._session_token is not None

    async def authenticate(self) -> bool:
        """Perform secure handshake to get session token."""
        try:
            # Step 1: Initialize handshake
            init_response = await self._request(
                "POST",
                API_HANDSHAKE_INIT,
                json={"api_key_hash": hashlib.sha256(self.api_key.encode()).hexdigest()},
                auth=False,
            )

            if "error" in init_response:
                _LOGGER.error("Handshake init failed: %s", init_response.get("error"))
                return False

            challenge = init_response.get("challenge")
            nonce = init_response.get("nonce")

            if not challenge or not nonce:
                _LOGGER.error("Invalid handshake response: missing challenge or nonce")
                return False

            # Step 2: Complete handshake with HMAC response
            response_hmac = hmac.new(
                self.api_key.encode(),
                challenge.encode(),
                hashlib.sha256,
            ).hexdigest()

            complete_response = await self._request(
                "POST",
                API_HANDSHAKE_COMPLETE,
                json={
                    "nonce": nonce,
                    "response": response_hmac,
                    "client_info": {
                        "type": "home_assistant",
                        "version": "1.0.0",
                    },
                },
                headers={"X-API-Key": self.api_key},
                auth=False,
            )

            if "error" in complete_response:
                _LOGGER.error("Handshake complete failed: %s", complete_response.get("error"))
                return False

            self._session_token = complete_response.get("session_token")
            if not self._session_token:
                _LOGGER.error("No session token in handshake response")
                return False

            _LOGGER.info("Successfully authenticated with PentaVision server")
            return True

        except Exception as err:
            _LOGGER.error("Authentication failed: %s", err)
            return False

    async def revoke_session(self) -> bool:
        """Revoke the current session."""
        if not self._session_token:
            return True

        try:
            await self._request("POST", API_SESSION_REVOKE)
            self._session_token = None
            return True
        except Exception as err:
            _LOGGER.warning("Failed to revoke session: %s", err)
            return False

    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        json: dict | None = None,
        headers: dict | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        """Make an API request."""
        url = f"{self._base_url}{endpoint}"
        request_headers = headers or {}

        if auth and self._session_token:
            request_headers["X-Session-Token"] = self._session_token

        try:
            async with self._session.request(
                method,
                url,
                json=json,
                headers=request_headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                data = await response.json()

                if response.status >= 400:
                    raise PentaVisionAPIError(
                        data.get("error", "Unknown error"),
                        data.get("code"),
                    )

                return data

        except aiohttp.ClientError as err:
            raise PentaVisionAPIError(f"Connection error: {err}") from err

    async def get_status(self) -> dict[str, Any]:
        """Get server status."""
        return await self._request("GET", API_STATUS)

    async def get_cameras(self) -> list[dict[str, Any]]:
        """Get list of cameras."""
        response = await self._request("GET", API_CAMERAS)
        return response.get("cameras", [])

    async def get_camera_info(self, camera_id: str) -> dict[str, Any]:
        """Get camera information."""
        endpoint = API_CAMERA_INFO.format(camera_id=camera_id)
        return await self._request("GET", endpoint)

    async def get_snapshot(self, camera_id: str) -> bytes:
        """Get camera snapshot as bytes."""
        endpoint = API_CAMERA_SNAPSHOT.format(camera_id=camera_id)
        url = f"{self._base_url}{endpoint}"
        headers = {}

        if self._session_token:
            headers["X-Session-Token"] = self._session_token

        async with self._session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as response:
            if response.status >= 400:
                raise PentaVisionAPIError(f"Snapshot failed: {response.status}")
            return await response.read()

    def get_mjpeg_url(self, camera_id: str) -> str:
        """Get MJPEG stream URL."""
        endpoint = API_MJPEG_STREAM.format(camera_id=camera_id)
        if self._session_token:
            return f"{self._base_url}{endpoint}?session_token={self._session_token}"
        return f"{self._base_url}{endpoint}?api_key={self.api_key}"

    def get_hls_url(self, camera_id: str) -> str:
        """Get HLS stream URL."""
        endpoint = API_HLS_PLAYLIST.format(camera_id=camera_id)
        if self._session_token:
            return f"{self._base_url}{endpoint}?session_token={self._session_token}"
        return f"{self._base_url}{endpoint}?api_key={self.api_key}"

    async def ptz_move(
        self,
        camera_id: str,
        direction: str,
        speed: int = 50,
    ) -> dict[str, Any]:
        """Send PTZ move command."""
        endpoint = API_PTZ.format(camera_id=camera_id)
        return await self._request(
            "POST",
            endpoint,
            json={
                "command": "move",
                "direction": direction,
                "speed": speed,
            },
        )

    async def ptz_preset(self, camera_id: str, preset: int) -> dict[str, Any]:
        """Go to PTZ preset."""
        endpoint = API_PTZ.format(camera_id=camera_id)
        return await self._request(
            "POST",
            endpoint,
            json={
                "command": "preset",
                "preset": preset,
            },
        )

    async def ptz_stop(self, camera_id: str) -> dict[str, Any]:
        """Stop PTZ movement."""
        endpoint = API_PTZ.format(camera_id=camera_id)
        return await self._request(
            "POST",
            endpoint,
            json={"command": "stop"},
        )
