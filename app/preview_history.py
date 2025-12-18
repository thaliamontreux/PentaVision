from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from flask import Flask


def _preview_base(app: Flask) -> Path:
    base = str(app.config.get("PREVIEW_CACHE_DIR", "/var/lib/pentavision/previews"))
    return Path(base)


def camera_dir(app: Flask, device_id: int) -> Path:
    return _preview_base(app) / f"camera_{int(device_id)}"


def history_dir(app: Flask, device_id: int) -> Path:
    return camera_dir(app, device_id) / "history"


def latest_path(app: Flask, device_id: int) -> Path:
    return _preview_base(app) / f"{int(device_id)}.jpg"


def history_seconds(app: Flask) -> int:
    try:
        value = int(app.config.get("PREVIEW_HISTORY_SECONDS", 60) or 60)
    except (TypeError, ValueError):
        value = 60
    return max(10, value)


def max_history_frames(app: Flask) -> int:
    # Keep a cap even if fps is high.
    try:
        fps = float(app.config.get("PREVIEW_CAPTURE_FPS", 10.0) or 10.0)
    except (TypeError, ValueError):
        fps = 10.0
    if fps <= 0:
        fps = 1.0
    return int(max(60.0, min(2000.0, fps * float(history_seconds(app)) * 1.5)))


def write_frame(app: Flask, device_id: int, jpg_bytes: bytes, ts: Optional[float] = None) -> None:
    if not jpg_bytes:
        return
    now = float(time.time() if ts is None else ts)
    base = _preview_base(app)
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        return

    # Legacy latest path
    try:
        tmp_latest = base / f"{int(device_id)}.jpg.tmp"
        final_latest = latest_path(app, device_id)
        tmp_latest.write_bytes(jpg_bytes)
        tmp_latest.replace(final_latest)
    except Exception:
        pass

    # History ring
    hdir = history_dir(app, device_id)
    try:
        hdir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return

    ts_ms = int(now * 1000.0)
    tmp_path = hdir / f"{ts_ms}.jpg.tmp"
    final_path = hdir / f"{ts_ms}.jpg"
    try:
        tmp_path.write_bytes(jpg_bytes)
        tmp_path.replace(final_path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return

    prune_history(app, device_id)


def prune_history(app: Flask, device_id: int) -> None:
    hdir = history_dir(app, device_id)
    if not hdir.exists():
        return

    now_ms = int(time.time() * 1000.0)
    cutoff_ms = now_ms - int(history_seconds(app) * 1000)

    # Remove old frames first.
    files = []
    try:
        files = sorted(hdir.glob("*.jpg"))
    except Exception:
        return

    for path in files:
        try:
            ts_ms = int(path.stem)
        except Exception:
            continue
        if ts_ms < cutoff_ms:
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass

    # Enforce max frame cap.
    try:
        files = sorted(hdir.glob("*.jpg"))
    except Exception:
        return
    cap = max_history_frames(app)
    if len(files) <= cap:
        return
    for path in files[: max(0, len(files) - cap)]:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass


def find_frame_by_age(app: Flask, device_id: int, age_seconds: float) -> Optional[Path]:
    age = max(0.0, float(age_seconds))
    target_ms = int((time.time() - age) * 1000.0)
    hdir = history_dir(app, device_id)
    if not hdir.exists():
        return None

    candidates = []
    try:
        candidates = sorted(hdir.glob("*.jpg"))
    except Exception:
        return None

    best: Optional[Path] = None
    best_ts = -1
    for path in candidates:
        try:
            ts = int(path.stem)
        except Exception:
            continue
        if ts <= target_ms and ts > best_ts:
            best = path
            best_ts = ts

    if best is not None:
        return best

    # If none <= target, return earliest available.
    for path in candidates:
        try:
            _ = int(path.stem)
        except Exception:
            continue
        return path

    return None
