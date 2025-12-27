---
description: Admin Overview icon set spec (full-color PNG)
---

# Admin Overview Icons (Full-Color PNG) — Copy/Paste Spec

## Directory to create

- `app/static/img/admin-icons/`

## Global icon requirements (apply to all)

- **File type**: PNG
- **Background**: transparent
- **Canvas**: square
- **Recommended size**: 96x96 (preferred) or 64x64
- **Padding inside canvas**: ~10–18% so it doesn’t touch edges
- **Visual style**:
  - Full color
  - Clean, modern, “techy” look (HUD/neon accents are welcome)
  - High-contrast shapes that read well at 42x42 display size
  - Avoid tiny text; use recognizable symbols
- **Color guidance**:
  - Use accents that complement the site glass UI (cyan/blue glow works well)
  - It’s okay to include additional colors (yellow/orange/green) as long as it stays cohesive

## Where these icons are used

- Admin Overview tiles: `app/templates/admin/index.html`
- Icon container style: `.pv-admin-tile-icon` in `app/static/css/main.css`

## Icon list (filename, path, and visual definition)

### Overview

- **Path**: `app/static/img/admin-icons/overview.png`
- **Definition**: Command-center/dashboard symbol. A HUD panel/grid with a subtle pulse line, crosshair, or status indicators. Should read as “admin hub”.

### Users

- **Path**: `app/static/img/admin-icons/users.png`
- **Definition**: 1–2 user silhouettes with a small shield or gear overlay to imply roles/permissions.

### Properties

- **Path**: `app/static/img/admin-icons/properties.png`
- **Definition**: Building/site icon with a location pin (or stacked buildings) to represent properties/sites.

### Cameras

- **Path**: `app/static/img/admin-icons/cameras.png`
- **Definition**: CCTV camera or camera lens. Prefer a modern lens look with a small glow ring.

### Camera URL Templates

- **Path**: `app/static/img/admin-icons/camera-url-templates.png`
- **Definition**: Document/page + code brackets or template lines, with a small link/chain symbol. Should read as “URL patterns/templates”.

### RTMP Outputs

- **Path**: `app/static/img/admin-icons/rtmp-outputs.png`
- **Definition**: Broadcast/streaming output icon. Example: arrow exiting a port, or signal waves leaving a node.

### Recordings

- **Path**: `app/static/img/admin-icons/recordings.png`
- **Definition**: Film strip + play button, or a recording dot + storage/clip element. Should read as “recorded video”.

### Recording Schedule

- **Path**: `app/static/img/admin-icons/recording-schedule.png`
- **Definition**: Calendar + recording dot (red) or clock indicator. Should read as “schedule/timer-based recording”.

### Storage Providers

- **Path**: `app/static/img/admin-icons/storage-providers.png`
- **Definition**: Database cylinder / storage stack with a plug/connector or module chip to represent provider modules.

### Themes

- **Path**: `app/static/img/admin-icons/themes.png`
- **Definition**: Sliders/equalizer controls, palette, or sparkle brush to represent theme customization.

### Block / Allow

- **Path**: `app/static/img/admin-icons/block-allow.png`
- **Definition**: Shield with split indicators (checkmark + ban). Should read as allowlist/blocklist controls.

### Blocklist Distribution

- **Path**: `app/static/img/admin-icons/blocklist-distribution.png`
- **Definition**: Shield + outward arrows/nodes (distribution/publishing). Should read as “sending blocklist out”.

### Blocklist Integration

- **Path**: `app/static/img/admin-icons/blocklist-integration.png`
- **Definition**: Plug/puzzle piece + shield. Should read as “integration endpoint / external hookup”.

### Blocklist Audit

- **Path**: `app/static/img/admin-icons/blocklist-audit.png`
- **Definition**: Clipboard/log lines + shield. Should read as “audit trail for blocklist actions”.

### Services

- **Path**: `app/static/img/admin-icons/services.png`
- **Definition**: Server rack + gear, or gear + heartbeat line. Should read as “system services / controls”.

### Pull GitHub Update

- **Path**: `app/static/img/admin-icons/github-pull.png`
- **Definition**: Repo/branch with a download arrow. Should read as “pull update from GitHub”.

### Audit Log

- **Path**: `app/static/img/admin-icons/audit-log.png`
- **Definition**: Log lines + magnifying glass. Should read as “review events”.

### Login Failures

- **Path**: `app/static/img/admin-icons/login-failures.png`
- **Definition**: Key/lock + warning triangle or X. Should read as “failed login attempts”.

### Installer & Databases

- **Path**: `app/static/img/admin-icons/installer-databases.png`
- **Definition**: Wrench/tool + database cylinder. Should read as “installer + database config”.
