# PentaVision Home Assistant Integration

This custom integration allows you to connect your Home Assistant instance to a PentaVision video surveillance server.

## Features

- **Camera Streams**: View live camera feeds directly in Home Assistant
- **Motion Detection**: Binary sensors for motion detection events
- **Camera Status**: Monitor camera online/offline status
- **PTZ Control**: Control PTZ cameras via services
- **Snapshots**: Take camera snapshots on demand

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Go to "Integrations"
3. Click the three dots menu and select "Custom repositories"
4. Add this repository URL and select "Integration" as the category
5. Search for "PentaVision" and install
6. Restart Home Assistant

### Manual Installation

1. Copy the `pentavision` folder to your `custom_components` directory:
   ```
   config/custom_components/pentavision/
   ```
2. Restart Home Assistant

## Configuration

1. Go to **Settings** → **Devices & Services**
2. Click **Add Integration**
3. Search for "PentaVision"
4. Enter your PentaVision server details:
   - **Host**: IP address or hostname of your PentaVision server
   - **Port**: Video Tunnel API port (default: 8473)
   - **API Key**: Your API key from PentaVision

### Getting Your API Key

1. Log into your PentaVision admin panel
2. Go to **Admin** → **Plugins** → **Home Assistant**
3. Find your property and click "Generate Key" or copy the existing API key

## Entities

### Cameras
Each camera from PentaVision will appear as a camera entity with:
- Live stream (MJPEG or HLS)
- Snapshot capability
- PTZ controls (if supported)

### Binary Sensors
- **Motion**: Triggered when motion is detected
- **Online**: Shows camera connectivity status

### Sensors
- **Cameras**: Total number of cameras
- **Server Status**: PentaVision server online/offline status

## Services

### `pentavision.ptz_move`
Move a PTZ camera in a direction.

| Parameter | Description |
|-----------|-------------|
| `direction` | up, down, left, right, up_left, up_right, down_left, down_right, zoom_in, zoom_out |
| `speed` | Movement speed (1-100, default: 50) |

### `pentavision.ptz_preset`
Go to a PTZ preset position.

| Parameter | Description |
|-----------|-------------|
| `preset` | Preset number (1-255) |

### `pentavision.ptz_stop`
Stop PTZ movement.

## Example Automations

### Motion Alert
```yaml
automation:
  - alias: "PentaVision Motion Alert"
    trigger:
      - platform: state
        entity_id: binary_sensor.front_door_motion
        to: "on"
    action:
      - service: notify.mobile_app
        data:
          title: "Motion Detected"
          message: "Motion detected at front door"
          data:
            image: /api/camera_proxy/camera.front_door
```

### PTZ Patrol
```yaml
automation:
  - alias: "PTZ Patrol"
    trigger:
      - platform: time_pattern
        minutes: "/15"
    action:
      - service: pentavision.ptz_preset
        target:
          entity_id: camera.ptz_camera
        data:
          preset: 1
      - delay: "00:05:00"
      - service: pentavision.ptz_preset
        target:
          entity_id: camera.ptz_camera
        data:
          preset: 2
```

## Troubleshooting

### Cannot Connect
- Verify the PentaVision server is running
- Check the port is correct (default: 8473)
- Ensure the API key is valid
- Check firewall settings

### Invalid API Key
- Regenerate the API key in PentaVision admin panel
- Ensure the property has Home Assistant integration enabled

### Cameras Not Showing
- Wait for the integration to poll (default: 30 seconds)
- Check that cameras are configured in PentaVision
- Verify the property has cameras assigned

## Support

For issues and feature requests, please visit:
- [GitHub Issues](https://github.com/pentavision/home-assistant-integration/issues)
- [PentaVision Documentation](https://docs.pentavision.com)
