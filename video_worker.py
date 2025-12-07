#!/usr/bin/env python3
"""Dedicated background worker for camera streaming and recording.

Run this under systemd on a Linux server to handle video processing
separately from the web front-end workers.
"""

from __future__ import annotations

import sys
import time

from app import create_app
from app.recording_service import start_recording_service
from app.stream_service import start_stream_service


class _StderrFilter:
    _PATTERNS = (
        "[h264 @",
        "error while decoding MB",
        "cabac decode of qscale diff failed",
        "left block unavailable for requested intra4x4 mode",
        "left block unavailable for requested intra mode",
    )

    def __init__(self, wrapped) -> None:
        self._wrapped = wrapped

    def write(self, data: str) -> int:  # type: ignore[override]
        if not data:
            return 0
        lines = data.splitlines(keepends=True)
        out_chunks = []
        for line in lines:
            text = line.strip()
            if any(p in text for p in self._PATTERNS):
                continue
            out_chunks.append(line)
        out = "".join(out_chunks)
        if out:
            return self._wrapped.write(out)
        return len(data)

    def flush(self) -> None:  # type: ignore[override]
        self._wrapped.flush()

    def __getattr__(self, item):
        return getattr(self._wrapped, item)


def _install_stderr_filter() -> None:
    try:
        sys.stderr = _StderrFilter(sys.stderr)
    except Exception:
        pass


def main() -> None:
    _install_stderr_filter()
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
