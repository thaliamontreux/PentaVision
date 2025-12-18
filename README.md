# PentaVision Attendance & Recording Platform

This project is a web-based system for managing attendance and video recordings using facial recognition, secure authentication (passkeys/2FA), and pluggable cloud storage providers.

## Quick start (development)

1. Create and activate a virtual environment (recommended):

   ```bash
   python -m venv .venv
   # Windows PowerShell
   .venv\\Scripts\\Activate.ps1
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the development server:

   ```bash
   python run.py
   ```

4. Open the app in your browser:
 
   - [http://127.0.0.1:5000/](http://127.0.0.1:5000/) (root)
   - [http://127.0.0.1:5000/health](http://127.0.0.1:5000/health) (basic health check)

## Configuration (early stage)

Configuration is read from environment variables. At this stage, the key settings are:

- `APP_SECRET_KEY` – secret key for Flask sessions.
- `USER_DB_URL` – SQLAlchemy URL for the user/auth database.
- `FACE_DB_URL` – SQLAlchemy URL for the facial recognition database.
- `RECORD_DB_URL` – SQLAlchemy URL for the recordings/metadata database.

Recording/video-worker related settings:

- `RECORDING_ENABLED` – set to `1` to enable background recording.
- `USE_GSTREAMER_RECORDING` – set to `1` to use GStreamer for recording; when enabled, the recorder will fall back to ffmpeg if GStreamer fails.
- `USE_SHM_INGEST` – when enabled, segments are written under `/dev/shm/pentavision/ingest/...` before being committed to storage.

Operational notes:

- The background worker (`video_worker.py`) runs a periodic MAC audit (twice daily) to populate missing camera MAC addresses and log `CAMERA_MAC_CHANGED` audit events when a camera's MAC changes.
- Recording ingest directories prefer a stable per-camera key derived from MAC address when available (fallback to numeric device id).

These will be wired into the graphical installer and database layer as the project progresses.
