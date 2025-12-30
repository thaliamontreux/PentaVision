# Home Assistant Integration Plugin

Bidirectional integration between PentaVision and Home Assistant for smart home automation.

## Features

- **Camera Events → Home Assistant**: Forward motion detection, person detection, and recording events to Home Assistant
- **Home Assistant → PentaVision**: Receive automation triggers via webhooks (trigger recordings, arm/disarm cameras)
- **MQTT Support**: Optional real-time event delivery via MQTT
- **Per-Property Configuration**: Each property can have its own Home Assistant instance

## Installation

1. Upload this plugin package via the PentaVision Admin Panel
2. Enable the plugin for your property
3. Configure your Home Assistant connection details

## Configuration

| Setting | Required | Description |
|---------|----------|-------------|
| `ha_url` | Yes | Home Assistant URL (e.g., `http://homeassistant.local:8123`) |
| `ha_token` | Yes | Long-Lived Access Token from Home Assistant |
| `webhook_secret` | No | Secret for authenticating incoming webhooks |
| `event_types` | No | Which events to forward (default: motion, person, recording) |
| `mqtt_enabled` | No | Enable MQTT for real-time events |
| `mqtt_broker` | No | MQTT broker hostname |
| `mqtt_port` | No | MQTT broker port (default: 1883) |
| `mqtt_username` | No | MQTT authentication username |
| `mqtt_password` | No | MQTT authentication password |
| `mqtt_topic_prefix` | No | MQTT topic prefix (default: `pentavision`) |

## Home Assistant Setup

### 1. Create Long-Lived Access Token

1. Go to your Home Assistant profile (click your name in the sidebar)
2. Scroll to "Long-Lived Access Tokens"
3. Click "Create Token"
4. Copy the token and paste it into the plugin configuration

### 2. Configure Automations

PentaVision sends events to Home Assistant that you can use in automations:

```yaml
automation:
  - alias: "Flash lights on motion"
    trigger:
      - platform: event
        event_type: pentavision_motion_start
    action:
      - service: light.turn_on
        target:
          entity_id: light.porch
        data:
          flash: short
```

### 3. Send Commands to PentaVision (Optional)

Configure a webhook in Home Assistant to trigger PentaVision actions:

```yaml
rest_command:
  pentavision_trigger_recording:
    url: "https://your-pentavision-url/plugins/home-assistant/webhook/ha"
    method: POST
    headers:
      X-Webhook-Signature: "{{ webhook_secret }}"
    payload: >
      {
        "action": "trigger_recording",
        "camera_id": "{{ camera_id }}",
        "duration": 60
      }
```

## Events

### Events Sent to Home Assistant

| Event Type | Description | Data |
|------------|-------------|------|
| `pentavision_motion_start` | Motion detected | `camera_id`, `camera_name`, `timestamp` |
| `pentavision_motion_end` | Motion ended | `camera_id`, `camera_name`, `timestamp`, `duration` |
| `pentavision_person_detected` | Person detected | `camera_id`, `camera_name`, `timestamp`, `confidence` |
| `pentavision_recording_started` | Recording started | `camera_id`, `recording_id`, `timestamp` |
| `pentavision_recording_ended` | Recording ended | `camera_id`, `recording_id`, `timestamp`, `duration` |
| `pentavision_camera_online` | Camera came online | `camera_id`, `camera_name` |
| `pentavision_camera_offline` | Camera went offline | `camera_id`, `camera_name` |

### Webhook Actions (HA → PentaVision)

| Action | Description | Parameters |
|--------|-------------|------------|
| `trigger_recording` | Start recording on a camera | `camera_id`, `duration` |
| `arm_camera` | Enable motion detection | `camera_id` |
| `disarm_camera` | Disable motion detection | `camera_id` |

## MQTT Topics

When MQTT is enabled:

- **Events**: `pentavision/event/{event_type}` (e.g., `pentavision/event/motion_start`)
- **Commands**: `pentavision/command/{action}` (subscribe to receive commands)

## Troubleshooting

### Connection Issues

1. Verify your Home Assistant URL is accessible from the PentaVision server
2. Check that the Long-Lived Access Token is valid
3. Ensure Home Assistant API is enabled (default in recent versions)

### Events Not Appearing

1. Check the plugin health status in PentaVision
2. Verify the event types are enabled in configuration
3. Check Home Assistant Developer Tools → Events for incoming events

### MQTT Issues

1. Verify MQTT broker is running and accessible
2. Check MQTT credentials are correct
3. Monitor MQTT topics with a tool like MQTT Explorer

## Version History

- **1.0.0** - Initial release
  - REST API integration
  - MQTT support
  - Webhook receiver
  - Basic event forwarding
