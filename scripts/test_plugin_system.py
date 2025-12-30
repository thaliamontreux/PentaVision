#!/usr/bin/env python3
"""
Test script for the PentaVision Plugin System.

This script tests:
1. Plugin loading and initialization
2. Event broadcasting
3. Home Assistant plugin functionality
4. Database integration

Run from project root:
    python scripts/test_plugin_system.py
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import plugin module dynamically since it's not a proper package
import importlib.util
plugin_path = Path(__file__).parent.parent / "plugins" / "home-assistant" / "main.py"
spec = importlib.util.spec_from_file_location("ha_plugin", plugin_path)
ha_plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ha_plugin)


class TestHomeAssistantPlugin(unittest.TestCase):
    """Test the Home Assistant plugin."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "ha_url": "http://homeassistant.local:8123",
            "ha_token": "test_token_12345",
            "webhook_secret": "test_secret",
            "event_types": ["motion_start", "person_detected", "recording_started"],
            "mqtt_enabled": False,
        }
        self.property_id = 1
        self.api_key = "test_api_key"

    def test_plugin_initialization(self):
        """Test plugin initializes correctly."""
        plugin = ha_plugin.HomeAssistantPlugin(
            self.config, self.property_id, self.api_key
        )

        self.assertEqual(plugin.ha_url, "http://homeassistant.local:8123")
        self.assertEqual(plugin.property_id, 1)
        self.assertFalse(plugin.mqtt_enabled)
        self.assertIn("motion_start", plugin.event_types)

    def test_plugin_factory(self):
        """Test create_plugin factory function."""
        plugin = ha_plugin.create_plugin(self.config, self.property_id, self.api_key)

        self.assertIsInstance(plugin, ha_plugin.HomeAssistantPlugin)

    def test_plugin_info(self):
        """Test get_plugin_info returns correct metadata."""
        info = ha_plugin.get_plugin_info()

        self.assertEqual(info["plugin_key"], "home-assistant")
        self.assertIn("version", info)
        self.assertIn("name", info)

    def test_event_handling(self):
        """Test events are queued correctly."""
        plugin = ha_plugin.HomeAssistantPlugin(
            self.config, self.property_id, self.api_key
        )

        # Test valid event type
        result = plugin.handle_event("motion_start", {"camera_id": 1})
        self.assertTrue(result)
        self.assertFalse(plugin.event_queue.empty())

        # Test ignored event type
        plugin.event_queue.get()  # Clear queue
        result = plugin.handle_event("unknown_event", {"camera_id": 1})
        self.assertTrue(result)
        self.assertTrue(plugin.event_queue.empty())

    def test_webhook_handling(self):
        """Test webhook processing."""
        plugin = ha_plugin.HomeAssistantPlugin(
            self.config, self.property_id, self.api_key
        )

        # Test trigger_recording action
        result = plugin.handle_webhook({
            "action": "trigger_recording",
            "camera_id": 5,
            "duration": 60
        })
        self.assertEqual(result["status"], "ok")

        # Test arm_camera action
        result = plugin.handle_webhook({"action": "arm_camera", "camera_id": 3})
        self.assertEqual(result["status"], "ok")

    def test_ha_connection_check(self):
        """Test Home Assistant connection check."""
        plugin = ha_plugin.HomeAssistantPlugin(
            self.config, self.property_id, self.api_key
        )

        # Mock the requests module within the plugin
        with patch.object(ha_plugin, "requests") as mock_requests:
            mock_requests.get.return_value.status_code = 200
            result = plugin._test_ha_connection()

            self.assertTrue(result)
            mock_requests.get.assert_called_once()

    def test_health_check(self):
        """Test health check returns expected fields."""
        plugin = ha_plugin.HomeAssistantPlugin(
            self.config, self.property_id, self.api_key
        )

        with patch.object(plugin, "_test_ha_connection", return_value=True):
            health = plugin.health_check()

        self.assertIn("status", health)
        self.assertIn("ha_connected", health)
        self.assertIn("events_sent", health)
        self.assertIn("last_check", health)


class TestPluginEvents(unittest.TestCase):
    """Test the plugin events module."""

    def test_motion_detected_event(self):
        """Test motion_detected creates correct event data."""
        from app import plugin_events

        with patch.object(plugin_events, "broadcast_event") as mock_broadcast:
            plugin_events.motion_detected(
                camera_id=1,
                camera_name="Front Door",
                property_id=1,
                confidence=0.95,
            )

            mock_broadcast.assert_called_once()
            call_args = mock_broadcast.call_args
            self.assertEqual(call_args[0][0], "motion_start")
            self.assertEqual(call_args[0][1]["camera_id"], 1)
            self.assertEqual(call_args[0][1]["camera_name"], "Front Door")
            self.assertEqual(call_args[0][1]["confidence"], 0.95)

    def test_recording_started_event(self):
        """Test recording_started creates correct event data."""
        from app import plugin_events

        with patch.object(plugin_events, "broadcast_event") as mock_broadcast:
            plugin_events.recording_started(
                camera_id=2,
                camera_name="Backyard",
                property_id=1,
                recording_id=123,
            )

            mock_broadcast.assert_called_once()
            call_args = mock_broadcast.call_args
            self.assertEqual(call_args[0][0], "recording_started")
            self.assertEqual(call_args[0][1]["recording_id"], 123)


class TestPluginPackageStructure(unittest.TestCase):
    """Test plugin package structure is correct."""

    def test_plugin_files_exist(self):
        """Test all required plugin files exist."""
        plugin_dir = Path(__file__).parent.parent / "plugins" / "home-assistant"

        self.assertTrue((plugin_dir / "plugin.id").exists())
        self.assertTrue((plugin_dir / "definition.json").exists())
        self.assertTrue((plugin_dir / "main.py").exists())
        self.assertTrue((plugin_dir / "README.md").exists())
        self.assertTrue((plugin_dir / "tests" / "test_plan.json").exists())

    def test_plugin_id_valid(self):
        """Test plugin.id contains valid JSON."""
        plugin_dir = Path(__file__).parent.parent / "plugins" / "home-assistant"

        with open(plugin_dir / "plugin.id") as f:
            plugin_id = json.load(f)

        self.assertEqual(plugin_id["plugin_key"], "home-assistant")
        self.assertIn("version", plugin_id)
        self.assertIn("entrypoint", plugin_id)
        self.assertEqual(plugin_id["entrypoint"], "main.py")

    def test_definition_valid(self):
        """Test definition.json contains valid schema."""
        plugin_dir = Path(__file__).parent.parent / "plugins" / "home-assistant"

        with open(plugin_dir / "definition.json") as f:
            definition = json.load(f)

        self.assertIn("capabilities", definition)
        self.assertIn("scopes", definition)
        self.assertIn("config_schema", definition)
        self.assertIn("requirements", definition)

        # Check config schema has required fields
        schema = definition["config_schema"]
        self.assertIn("ha_url", schema["properties"])
        self.assertIn("ha_token", schema["properties"])


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestHomeAssistantPlugin))
    suite.addTests(loader.loadTestsFromTestCase(TestPluginEvents))
    suite.addTests(loader.loadTestsFromTestCase(TestPluginPackageStructure))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    print("=" * 60)
    print("PentaVision Plugin System Tests")
    print("=" * 60)
    print()

    success = run_tests()

    print()
    print("=" * 60)
    if success:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed")
    print("=" * 60)

    sys.exit(0 if success else 1)
