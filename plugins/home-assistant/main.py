"""
Home Assistant Integration Plugin for PentaVision

Provides bidirectional integration with Home Assistant:
- Sends camera events (motion, person detection, recordings) to HA
- Receives automation triggers from HA via webhooks
- Supports both REST API and MQTT communication
"""

import hashlib
import hmac
import json
import logging
import threading
from datetime import datetime
from typing import Optional
from queue import Queue, Empty

import requests

logger = logging.getLogger("pentavision.plugins.home-assistant")


class HomeAssistantPlugin:
    """Main plugin class for Home Assistant integration."""

    PLUGIN_KEY = "home-assistant"
    VERSION = "1.0.0"

    def __init__(self, config: dict, property_id: int, api_key: str):
        """
        Initialize the Home Assistant plugin.

        Args:
            config: Plugin configuration from property settings
            property_id: The property ID this instance is running for
            api_key: API key for authenticating with PentaVision
        """
        self.config = config
        self.property_id = property_id
        self.api_key = api_key

        self.ha_url = config.get("ha_url", "").rstrip("/")
        self.ha_token = config.get("ha_token", "")
        self.webhook_secret = config.get("webhook_secret", "")
        self.event_types = config.get("event_types", [
            "motion_start", "person_detected", "recording_started"
        ])

        self.mqtt_enabled = config.get("mqtt_enabled", False)
        self.mqtt_client = None
        self.mqtt_connected = False

        self.event_queue: Queue = Queue()
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None

        self._last_health_check = None
        self._health_status = "unknown"
        self._events_sent = 0
        self._events_failed = 0

    def start(self) -> bool:
        """Start the plugin and its background workers."""
        logger.info(f"Starting Home Assistant plugin for property {self.property_id}")

        if not self.ha_url or not self.ha_token:
            logger.error("Home Assistant URL and token are required")
            self._health_status = "misconfigured"
            return False

        if not self._test_ha_connection():
            logger.error("Failed to connect to Home Assistant")
            self._health_status = "unreachable"
            return False

        if self.mqtt_enabled:
            self._setup_mqtt()

        self.running = True
        self.worker_thread = threading.Thread(target=self._event_worker, daemon=True)
        self.worker_thread.start()

        self._health_status = "healthy"
        logger.info("Home Assistant plugin started successfully")
        return True

    def stop(self):
        """Stop the plugin and cleanup resources."""
        logger.info(f"Stopping Home Assistant plugin for property {self.property_id}")
        self.running = False

        if self.mqtt_client and self.mqtt_connected:
            try:
                self.mqtt_client.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting MQTT: {e}")

        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)

        logger.info("Home Assistant plugin stopped")

    def health_check(self) -> dict:
        """Return health status of the plugin."""
        self._last_health_check = datetime.utcnow()

        ha_reachable = self._test_ha_connection()

        return {
            "status": "healthy" if ha_reachable else "unhealthy",
            "ha_connected": ha_reachable,
            "mqtt_connected": self.mqtt_connected if self.mqtt_enabled else None,
            "events_sent": self._events_sent,
            "events_failed": self._events_failed,
            "last_check": self._last_health_check.isoformat(),
        }

    def handle_event(self, event_type: str, event_data: dict) -> bool:
        """
        Handle an incoming event from PentaVision.

        Args:
            event_type: Type of event (e.g., 'motion_start', 'person_detected')
            event_data: Event payload

        Returns:
            True if event was queued successfully
        """
        if event_type not in self.event_types:
            logger.debug(f"Ignoring event type {event_type} (not in configured types)")
            return True

        self.event_queue.put({
            "type": event_type,
            "data": event_data,
            "timestamp": datetime.utcnow().isoformat(),
        })

        return True

    def handle_webhook(self, payload: dict, signature: Optional[str] = None) -> dict:
        """
        Handle incoming webhook from Home Assistant.

        Args:
            payload: Webhook payload
            signature: HMAC signature for verification

        Returns:
            Response dict
        """
        if self.webhook_secret and signature:
            expected_sig = hmac.new(
                self.webhook_secret.encode(),
                json.dumps(payload, sort_keys=True).encode(),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_sig):
                logger.warning("Invalid webhook signature")
                return {"error": "Invalid signature", "status": 401}

        action = payload.get("action")
        entity_id = payload.get("entity_id")

        logger.info(f"Received webhook: action={action}, entity_id={entity_id}")

        if action == "trigger_recording":
            return self._handle_trigger_recording(payload)
        elif action == "arm_camera":
            return self._handle_arm_camera(payload)
        elif action == "disarm_camera":
            return self._handle_disarm_camera(payload)
        else:
            return {"status": "ok", "message": f"Received action: {action}"}

    def _test_ha_connection(self) -> bool:
        """Test connection to Home Assistant."""
        try:
            response = requests.get(
                f"{self.ha_url}/api/",
                headers={"Authorization": f"Bearer {self.ha_token}"},
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to connect to Home Assistant: {e}")
            return False

    def _setup_mqtt(self):
        """Setup MQTT client for real-time communication."""
        try:
            import paho.mqtt.client as mqtt

            broker = self.config.get("mqtt_broker", "localhost")
            port = self.config.get("mqtt_port", 1883)
            username = self.config.get("mqtt_username")
            password = self.config.get("mqtt_password")
            topic_prefix = self.config.get("mqtt_topic_prefix", "pentavision")

            self.mqtt_topic_prefix = topic_prefix
            self.mqtt_client = mqtt.Client(
                client_id=f"pentavision-ha-{self.property_id}"
            )

            if username and password:
                self.mqtt_client.username_pw_set(username, password)

            self.mqtt_client.on_connect = self._on_mqtt_connect
            self.mqtt_client.on_disconnect = self._on_mqtt_disconnect
            self.mqtt_client.on_message = self._on_mqtt_message

            self.mqtt_client.connect_async(broker, port)
            self.mqtt_client.loop_start()

            logger.info(f"MQTT client connecting to {broker}:{port}")

        except ImportError:
            logger.warning("paho-mqtt not installed, MQTT disabled")
            self.mqtt_enabled = False
        except Exception as e:
            logger.error(f"Failed to setup MQTT: {e}")
            self.mqtt_enabled = False

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        """MQTT connection callback."""
        if rc == 0:
            self.mqtt_connected = True
            logger.info("Connected to MQTT broker")

            client.subscribe(f"{self.mqtt_topic_prefix}/command/#")
        else:
            logger.error(f"MQTT connection failed with code {rc}")

    def _on_mqtt_disconnect(self, client, userdata, rc):
        """MQTT disconnection callback."""
        self.mqtt_connected = False
        logger.warning(f"Disconnected from MQTT broker (rc={rc})")

    def _on_mqtt_message(self, client, userdata, msg):
        """MQTT message callback."""
        try:
            payload = json.loads(msg.payload.decode())
            logger.info(f"MQTT message on {msg.topic}: {payload}")

            if "/command/" in msg.topic:
                self.handle_webhook(payload)

        except Exception as e:
            logger.error(f"Error processing MQTT message: {e}")

    def _event_worker(self):
        """Background worker to process and send events."""
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
            except Empty:
                continue

            try:
                self._send_event_to_ha(event)
                self._events_sent += 1
            except Exception as e:
                logger.error(f"Failed to send event to HA: {e}")
                self._events_failed += 1

    def _send_event_to_ha(self, event: dict):
        """Send an event to Home Assistant."""
        event_type = event["type"]
        event_data = event["data"]

        ha_event_type = f"pentavision_{event_type}"

        payload = {
            "property_id": self.property_id,
            "event_type": event_type,
            "timestamp": event["timestamp"],
            **event_data
        }

        if self.mqtt_enabled and self.mqtt_connected:
            topic = f"{self.mqtt_topic_prefix}/event/{event_type}"
            self.mqtt_client.publish(topic, json.dumps(payload))
            logger.debug(f"Published event to MQTT: {topic}")

        try:
            response = requests.post(
                f"{self.ha_url}/api/events/{ha_event_type}",
                headers={
                    "Authorization": f"Bearer {self.ha_token}",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                logger.debug(f"Event {ha_event_type} sent to Home Assistant")
            else:
                logger.warning(
                    f"HA returned {response.status_code} for event {ha_event_type}"
                )

        except Exception as e:
            logger.error(f"Failed to send event to HA REST API: {e}")
            raise

    def _handle_trigger_recording(self, payload: dict) -> dict:
        """Handle trigger_recording action from HA."""
        camera_id = payload.get("camera_id")
        duration = payload.get("duration", 60)

        logger.info(f"Triggering recording for camera {camera_id}, duration={duration}s")

        return {
            "status": "ok",
            "message": f"Recording triggered for camera {camera_id}"
        }

    def _handle_arm_camera(self, payload: dict) -> dict:
        """Handle arm_camera action from HA."""
        camera_id = payload.get("camera_id")

        logger.info(f"Arming camera {camera_id}")

        return {"status": "ok", "message": f"Camera {camera_id} armed"}

    def _handle_disarm_camera(self, payload: dict) -> dict:
        """Handle disarm_camera action from HA."""
        camera_id = payload.get("camera_id")

        logger.info(f"Disarming camera {camera_id}")

        return {"status": "ok", "message": f"Camera {camera_id} disarmed"}


def create_plugin(config: dict, property_id: int, api_key: str) -> HomeAssistantPlugin:
    """Factory function to create plugin instance."""
    return HomeAssistantPlugin(config, property_id, api_key)


def get_plugin_info() -> dict:
    """Return plugin metadata."""
    return {
        "plugin_key": HomeAssistantPlugin.PLUGIN_KEY,
        "version": HomeAssistantPlugin.VERSION,
        "name": "Home Assistant Integration",
        "description": "Bidirectional integration with Home Assistant",
    }
