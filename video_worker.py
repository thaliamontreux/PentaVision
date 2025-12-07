#!/usr/bin/env python3
"""Dedicated background worker for camera streaming and recording.

Run this under systemd on a Linux server to handle video processing
separately from the web front-end workers.
"""

from __future__ import annotations

import time

from app import create_app
from app.recording_service import start_recording_service
from app.stream_service import start_stream_service


def main() -> None:
    app = create_app()
    # Start long-running background services (each manages its own threads).
    start_recording_service(app)
    start_stream_service(app)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        # Allow clean shutdown when run interactively.
        pass


if __name__ == "__main__":
    main()
