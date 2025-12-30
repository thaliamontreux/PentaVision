"""
Unit tests for Home Assistant plugin.
"""

import json
import unittest
from unittest.mock import MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import HomeAssistantPlugin, create_plugin, get_plugin_info


class TestHomeAssistantPlugin(unittest.TestCase):
    """Test cases for HomeAssistantPlugin class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "ha_url": "http://homeassistant.local:8123",
            "ha_token": "test_token_12345",
            "webhook_secret": "test_secret",
            "event_types": ["motion_start", "person_detected"],
            "mqtt_enabled": False,
        }
        self.property_id = 1
        self.api_key = "test_api_key"

    def test_plugin_init(self):
        """Test plugin initialization with valid config."""
        plugin = HomeAssistantPlugin(self.config, self.property_id, self.api_key)

        self.assertEqual(plugin.ha_url, "http://homeassistant.local:8123")
        self.assertEqual(plugin.ha_token, "test_token_12345")
        self.assertEqual(plugin.property_id, 1)
        self.assertEqual(plugin.event_types, ["motion_start", "person_detected"])
        self.assertFalse(plugin.mqtt_enabled)

    def test_plugin_init_strips_trailing_slash(self):
        """Test that trailing slash is stripped from HA URL."""
        config = self.config.copy()
        config["ha_url"] = "http://homeassistant.local:8123/"

        plugin = HomeAssistantPlugin(config, self.property_id, self.api_key)

        self.assertEqual(plugin.ha_url, "http://homeassistant.local:8123")

    def test_plugin_init_default_event_types(self):
        """Test default event types when not specified."""
        config = {
            "ha_url": "http://homeassistant.local:8123",
            "ha_token": "test_token",
        }

        plugin = HomeAssistantPlugin(config, self.property_id, self.api_key)

        self.assertIn("motion_start", plugin.event_types)
        self.assertIn("person_detected", plugin.event_types)
        self.assertIn("recording_started", plugin.event_types)

    @patch("main.requests.get")
    def test_ha_connection_success(self, mock_get):
        """Test successful connection to Home Assistant."""
        mock_get.return_value.status_code = 200

        plugin = HomeAssistantPlugin(self.config, self.property_id, self.api_key)
        result = plugin._test_ha_connection()

        self.assertTrue(result)
        mock_get.assert_called_once()

    @patch("main.requests.get")
    def test_ha_connection_failure(self, mock_get):
        """Test failed connection to Home Assistant."""
        mock_get.return_value.status_code = 401

        plugin = HomeAssistantPlugin(self.config, self.property_id, self.api_key)
        result = plugin._test_ha_connection()

        self.assertFalse(result)

    @patch("main.requests.get")
    def test_ha_connection_exception(self, mock_get):
        """Test connection exception handling."""
        mock_get.side_effect = Exception("Connection refused")

        plugin = HomeAssistantPlugin(self.config, self.property_id, self.api_key)
        result = plugin._test_ha_connection()

        self.assertFalse(result)

    def test_handle_event_queues_valid_event(self):
        """Test that valid events are queued."""
        plugin = HomeAssistantPlugin(self.config, self.property_id, self.api_key)

        result = plugin.handle_event("motion_start", {"camera_id": 1})

        self.assertTrue(result)
        self.assertFalse(plugin.event_queue.empty())

    def test_handle_event_ignores_unconfigured_type(self):
        """Test that unconfigured event types are ignored."""
        plugin = HomeAssistantPlugin(self.config, self.property_id, self.api_key)

        result = plugin.handle_event("camera_offline", {"camera_id": 1})

        self.assertTrue(result)
        self.assertTrue(plugin.event_queue.empty())

    def test_webhook_signature_verification(self):
        """Test webhook HMAC signature verification."""
        plugin = HomeAssistantPlugin(self.config, self.property_id, self.api_key)

        payload = {"action": "test", "data": "value"}

        import hashlib
        import hmac
        expected_sig = hmac.new(
            b"test_secret",
            json.dumps(payload, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()

        result = plugin.handle_webhook(payload, expected_sig)

        self.assertNotEqual(result.get("status"), 401)

    def test_webhook_invalid_signature(self):
        """Test webhook with invalid signature."""
        plugin = HomeAssistantPlugin(self.config, self.property_id, self.api_key)

        payload = {"action": "test"}
        result = plugin.handle_webhook(payload, "invalid_signature")

        self.assertEqual(result.get("status"), 401)

    def test_health_check(self):
        """Test health check returns expected fields."""
        plugin = HomeAssistantPlugin(self.config, self.property_id, self.api_key)
        plugin._health_status = "healthy"

        with patch.object(plugin, "_test_ha_connection", return_value=True):
            health = plugin.health_check()

        self.assertIn("status", health)
        self.assertIn("ha_connected", health)
        self.assertIn("events_sent", health)
        self.assertIn("events_failed", health)
        self.assertIn("last_check", health)

    def test_create_plugin_factory(self):
        """Test plugin factory function."""
        plugin = create_plugin(self.config, self.property_id, self.api_key)

        self.assertIsInstance(plugin, HomeAssistantPlugin)

    def test_get_plugin_info(self):
        """Test plugin info function."""
        info = get_plugin_info()

        self.assertEqual(info["plugin_key"], "home-assistant")
        self.assertIn("version", info)
        self.assertIn("name", info)
        self.assertIn("description", info)


class TestWebhookActions(unittest.TestCase):
    """Test webhook action handlers."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "ha_url": "http://homeassistant.local:8123",
            "ha_token": "test_token",
        }
        self.plugin = HomeAssistantPlugin(self.config, 1, "api_key")

    def test_trigger_recording_action(self):
        """Test trigger_recording webhook action."""
        payload = {
            "action": "trigger_recording",
            "camera_id": 5,
            "duration": 120
        }

        result = self.plugin.handle_webhook(payload)

        self.assertEqual(result["status"], "ok")
        self.assertIn("camera 5", result["message"])

    def test_arm_camera_action(self):
        """Test arm_camera webhook action."""
        payload = {"action": "arm_camera", "camera_id": 3}

        result = self.plugin.handle_webhook(payload)

        self.assertEqual(result["status"], "ok")
        self.assertIn("armed", result["message"])

    def test_disarm_camera_action(self):
        """Test disarm_camera webhook action."""
        payload = {"action": "disarm_camera", "camera_id": 3}

        result = self.plugin.handle_webhook(payload)

        self.assertEqual(result["status"], "ok")
        self.assertIn("disarmed", result["message"])

    def test_unknown_action(self):
        """Test handling of unknown webhook action."""
        payload = {"action": "unknown_action"}

        result = self.plugin.handle_webhook(payload)

        self.assertEqual(result["status"], "ok")


if __name__ == "__main__":
    unittest.main()
