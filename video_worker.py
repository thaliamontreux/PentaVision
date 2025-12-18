#!/usr/bin/env python3
"""Dedicated background worker for camera streaming and recording.

Run this under systemd on a Linux server to handle video processing
separately from the web front-end workers.
"""

from __future__ import annotations

import sys
import time

from app import create_app
from app.ingest_service import start_ingest_service
from app.mac_audit_service import start_mac_audit_service
from app.recording_service import start_recording_service
from app.stream_service import start_stream_service
from app.rtmp_service import start_rtmp_service


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
    try:
        startup_line = (
            "video_worker starting: "
            f"INGEST_ENABLED={app.config.get('INGEST_ENABLED')} "
            f"STREAMS_ENABLED={app.config.get('STREAMS_ENABLED')} "
            f"RECORDING_ENABLED={app.config.get('RECORDING_ENABLED')} "
            f"SHM_PROCESSING_REQUIRED={app.config.get('SHM_PROCESSING_REQUIRED')} "
            f"RECORD_DB_URL_set={bool(str(app.config.get('RECORD_DB_URL') or '').strip())} "
            f"USER_DB_URL_set={bool(str(app.config.get('USER_DB_URL') or '').strip())} "
            f"STORAGE_TARGETS={str(app.config.get('STORAGE_TARGETS') or '')} "
            f"LOCAL_STORAGE_PATH={str(app.config.get('LOCAL_STORAGE_PATH') or '')}"
        )
        print(startup_line, file=sys.stderr, flush=True)
    except Exception:
        pass
    try:
        app.logger.warning(
            "video_worker starting: INGEST_ENABLED=%s STREAMS_ENABLED=%s RECORDING_ENABLED=%s RECORD_DB_URL_set=%s USER_DB_URL_set=%s STORAGE_TARGETS=%s LOCAL_STORAGE_PATH=%s",
            app.config.get("INGEST_ENABLED"),
            app.config.get("STREAMS_ENABLED"),
            app.config.get("RECORDING_ENABLED"),
            bool(str(app.config.get("RECORD_DB_URL") or "").strip()),
            bool(str(app.config.get("USER_DB_URL") or "").strip()),
            str(app.config.get("STORAGE_TARGETS") or ""),
            str(app.config.get("LOCAL_STORAGE_PATH") or ""),
        )
    except Exception:
        pass
    # Start long-running background services (each manages its own threads).
    try:
        ingest_enabled = bool(app.config.get("INGEST_ENABLED", False))
    except Exception:
        ingest_enabled = False

    if ingest_enabled:
        start_ingest_service(app)
    else:
        start_recording_service(app)
    try:
        streams_enabled = bool(app.config.get("STREAMS_ENABLED", True))
    except Exception:
        streams_enabled = True
    if streams_enabled and (not ingest_enabled):
        start_stream_service(app)
    start_rtmp_service(app)
    start_mac_audit_service(app)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        # Allow clean shutdown when run interactively.
        pass


if __name__ == "__main__":
    main()
