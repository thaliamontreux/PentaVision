from __future__ import annotations

import io
import hashlib
import json
import os
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from flask import Flask
from sqlalchemy.orm import Session

from .db import get_record_engine
from .models import (
    CameraDevice,
    CameraPropertyLink,
    CameraRecording,
    CameraRecordingSchedule,
    CameraRecordingWindow,
    CameraStorageScheduleEntry,
    CameraStoragePolicy,
    CameraUrlPattern,
    Property,
    StorageModule,
    StorageModuleEvent,
    StorageModuleWriteStat,
    UploadQueueItem,
)
from .storage_providers import StorageProvider, build_storage_providers
from .storage_csal import get_storage_router
from .camera_utils import build_camera_url


def _normalize_bool(value: str) -> bool:
    if not value:
        return False
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "on"}


class CameraConfig:
    def __init__(self, device_id: int, name: str, url: str) -> None:
        self.device_id = device_id
        self.name = name
        self.url = url


def _mask_url_password(url: str) -> str:
    if not url:
        return url
    parsed = urlparse(url)
    if parsed.username is None and parsed.password is None:
        return url

    username = parsed.username or ""
    password = parsed.password or ""
    masked_userinfo = username
    if password:
        stars = "*" * len(password)
        if username:
            masked_userinfo = f"{username}:{stars}"
        else:
            masked_userinfo = stars

    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"

    if masked_userinfo:
        netloc = f"{masked_userinfo}@{host}"
    else:
        netloc = host

    return urlunparse(parsed._replace(netloc=netloc))


def _parse_time_str(value: str) -> Optional[int]:
    if not value:
        return None
    parts = value.split(":", 1)
    if len(parts) != 2:
        return None
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError:
        return None
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return None
    return hour * 60 + minute


def _is_time_in_window(
    now_minutes: int,
    start_minutes: int,
    end_minutes: int,
) -> bool:
    if start_minutes == end_minutes:
        return False
    if start_minutes < end_minutes:
        return start_minutes <= now_minutes < end_minutes
    return now_minutes >= start_minutes or now_minutes < end_minutes


def _should_record_now(app: Flask, device_id: int) -> bool:
    engine = get_record_engine()
    if engine is None:
        return True
    now_utc = datetime.now(timezone.utc)
    with Session(engine) as session:
        CameraStorageScheduleEntry.__table__.create(bind=engine, checkfirst=True)
        CameraRecordingSchedule.__table__.create(bind=engine, checkfirst=True)
        CameraRecordingWindow.__table__.create(bind=engine, checkfirst=True)
        CameraPropertyLink.__table__.create(bind=engine, checkfirst=True)
        Property.__table__.create(bind=engine, checkfirst=True)

        active_entry = _get_active_storage_schedule_entry(session, app, device_id, now_utc)
        if active_entry is not None:
            return True

        # If schedule entries exist for this camera but none are active, do not record.
        try:
            any_entries = (
                session.query(CameraStorageScheduleEntry)
                .filter(CameraStorageScheduleEntry.device_id == device_id)
                .count()
            )
        except Exception:  # noqa: BLE001
            any_entries = 0
        if any_entries:
            return False

        schedule = (
            session.query(CameraRecordingSchedule)
            .filter(CameraRecordingSchedule.device_id == device_id)
            .first()
        )
        if schedule is None:
            return True
        windows_raw = (
            session.query(CameraRecordingWindow)
            .filter(CameraRecordingWindow.schedule_id == schedule.id)
            .all()
        )
        windows = [
            {
                "day_of_week": w.day_of_week,
                "start_time": w.start_time or "",
                "end_time": w.end_time or "",
                "mode": (w.mode or "").strip().lower() or None,
            }
            for w in windows_raw
        ]
        link = (
            session.query(CameraPropertyLink)
            .filter(CameraPropertyLink.device_id == device_id)
            .first()
        )
        property_tz = None
        if link is not None and getattr(link, "property_id", None) is not None:
            prop = session.get(Property, link.property_id)
            if prop is not None:
                property_tz = getattr(prop, "timezone", None)
        mode = (schedule.mode or "always").strip().lower()
        days_raw = (schedule.days_of_week or "*").strip()
        sched_tz_name = schedule.timezone or property_tz
        if not sched_tz_name:
            sched_tz_name = str(app.config.get("DEFAULT_TIMEZONE") or "UTC")

    try:
        tz = ZoneInfo(str(sched_tz_name))
    except Exception:
        tz = timezone.utc

    now_local = now_utc.astimezone(tz)
    weekday = now_local.weekday()
    now_minutes = now_local.hour * 60 + now_local.minute

    if windows:
        day_windows: list[tuple[int, int, str]] = []
        for item in windows:
            day = item.get("day_of_week")
            if day is not None and day != weekday:
                continue
            start_minutes = _parse_time_str(item.get("start_time", "") or "")
            end_minutes = _parse_time_str(item.get("end_time", "") or "")
            if start_minutes is None or end_minutes is None:
                continue
            window_mode = item.get("mode") or mode
            day_windows.append((start_minutes, end_minutes, window_mode))

        for start_minutes, end_minutes, _window_mode in day_windows:
            if _is_time_in_window(now_minutes, start_minutes, end_minutes):
                return True

        return False

    if days_raw and days_raw != "*":
        allowed_days: set[int] = set()
        for token in days_raw.split(","):
            token = token.strip()
            if not token:
                continue
            try:
                day_idx = int(token)
            except ValueError:
                continue
            if 0 <= day_idx <= 6:
                allowed_days.add(day_idx)
        if allowed_days and weekday not in allowed_days:
            return False

    if mode in {"always", "motion_only"}:
        return True

    start_minutes = _parse_time_str(getattr(schedule, "start_time", "") or "")
    end_minutes = _parse_time_str(getattr(schedule, "end_time", "") or "")
    if start_minutes is None or end_minutes is None:
        return True
    return _is_time_in_window(now_minutes, start_minutes, end_minutes)


def _get_active_storage_schedule_entry(
    session: Session,
    app: Flask,
    device_id: int,
    now_utc: datetime,
) -> Optional[CameraStorageScheduleEntry]:
    try:
        entries = (
            session.query(CameraStorageScheduleEntry)
            .filter(CameraStorageScheduleEntry.device_id == device_id)
            .order_by(
                getattr(CameraStorageScheduleEntry, "priority", CameraStorageScheduleEntry.id),
                CameraStorageScheduleEntry.id,
            )
            .all()
        )
    except Exception:  # noqa: BLE001
        return None
    if not entries:
        return None

    # Use the camera schedule timezone if configured, otherwise fall back.
    sched_tz_name = None
    try:
        schedule = (
            session.query(CameraRecordingSchedule)
            .filter(CameraRecordingSchedule.device_id == device_id)
            .first()
        )
        if schedule is not None:
            sched_tz_name = getattr(schedule, "timezone", None)
    except Exception:  # noqa: BLE001
        sched_tz_name = None
    if not sched_tz_name:
        sched_tz_name = str(app.config.get("DEFAULT_TIMEZONE") or "UTC")
    try:
        tz = ZoneInfo(str(sched_tz_name))
    except Exception:  # noqa: BLE001
        tz = timezone.utc
    now_local = now_utc.astimezone(tz)
    weekday = now_local.weekday()
    now_minutes = now_local.hour * 60 + now_local.minute

    for entry in entries:
        try:
            if not bool(getattr(entry, "is_enabled", 1)):
                continue
        except Exception:  # noqa: BLE001
            continue

        mode = (getattr(entry, "mode", None) or "always").strip().lower()
        if mode in {"always", "motion_only"}:
            return entry

        days_raw = (getattr(entry, "days_of_week", None) or "*").strip()
        if days_raw and days_raw != "*":
            allowed_days: set[int] = set()
            for token in days_raw.split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    day_idx = int(token)
                except ValueError:
                    continue
                if 0 <= day_idx <= 6:
                    allowed_days.add(day_idx)
            if allowed_days and weekday not in allowed_days:
                continue

        start_minutes = _parse_time_str(getattr(entry, "start_time", "") or "")
        end_minutes = _parse_time_str(getattr(entry, "end_time", "") or "")
        if start_minutes is None or end_minutes is None:
            # If scheduled without times, treat as active.
            return entry
        if _is_time_in_window(now_minutes, start_minutes, end_minutes):
            return entry
    return None


def _get_active_storage_targets(app: Flask, device_id: int) -> Optional[set[str]]:
    engine = get_record_engine()
    if engine is None:
        return None
    now_utc = datetime.now(timezone.utc)
    with Session(engine) as session:
        try:
            CameraStorageScheduleEntry.__table__.create(bind=engine, checkfirst=True)
        except Exception:  # noqa: BLE001
            return None
        entry = _get_active_storage_schedule_entry(session, app, device_id, now_utc)
        if entry is None:
            return None
        raw = (getattr(entry, "storage_targets", None) or "").strip()
        if not raw:
            return set()
        return {name.strip() for name in raw.split(",") if name.strip()}


def _get_schedule_mode(app: Flask, device_id: int) -> str:
    engine = get_record_engine()
    if engine is None:
        return "always"
    with Session(engine) as session:
        CameraRecordingSchedule.__table__.create(bind=engine, checkfirst=True)
        schedule = (
            session.query(CameraRecordingSchedule)
            .filter(CameraRecordingSchedule.device_id == device_id)
            .first()
        )
        if schedule is None:
            return "always"
        raw_mode = getattr(schedule, "mode", None) or "always"
        mode = str(raw_mode).strip().lower()
        if not mode:
            mode = "always"
    return mode


def _should_record_based_on_motion(app: Flask, device_id: int, url: str) -> bool:
    mode = _get_schedule_mode(app, device_id)
    if mode not in {"motion_only", "scheduled_motion"}:
        return True

    try:
        import cv2  # type: ignore[import]
    except Exception:  # noqa: BLE001
        return True

    try:
        threshold = float(
            app.config.get("RECORD_MOTION_THRESHOLD", 0.01) or 0.01
        )
    except (TypeError, ValueError):
        threshold = 0.01
    if threshold <= 0:
        threshold = 0.01

    try:
        max_frames = int(app.config.get("RECORD_MOTION_FRAMES", 10) or 10)
    except (TypeError, ValueError):
        max_frames = 10
    if max_frames <= 0:
        max_frames = 10

    cap = cv2.VideoCapture(url)
    if not cap.isOpened():
        cap.release()
        return False

    ret, prev_frame = cap.read()
    if not ret:
        cap.release()
        return False

    try:
        prev_gray = cv2.cvtColor(prev_frame, cv2.COLOR_BGR2GRAY)
    except Exception:  # noqa: BLE001
        cap.release()
        return False

    frames_checked = 0
    while frames_checked < max_frames:
        ret, frame = cap.read()
        if not ret:
            break
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            diff = cv2.absdiff(prev_gray, gray)
            _, thresh_img = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)
            non_zero = cv2.countNonZero(thresh_img)
            total = thresh_img.shape[0] * thresh_img.shape[1]
            if total > 0:
                ratio = float(non_zero) / float(total)
                if ratio >= threshold:
                    cap.release()
                    return True
            prev_gray = gray
        except Exception:  # noqa: BLE001
            break
        frames_checked += 1

    cap.release()
    return False


class CameraWorker(threading.Thread):
    def __init__(
        self,
        app: Flask,
        config: CameraConfig,
        providers: List[StorageProvider],
        segment_seconds: int = 60,
    ) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.config = config
        self.providers = providers
        self.segment_seconds = segment_seconds
        self.retry_delay = 10
        self._ingest_session_id = uuid.uuid4().hex

    def run(self) -> None:
        with self.app.app_context():
            while True:
                try:
                    self._record_segment()
                except Exception:
                    time.sleep(self.retry_delay)

    def _record_segment(self) -> None:
        if not _should_record_now(self.app, self.config.device_id):
            sleep_seconds = max(5, min(self.segment_seconds, 60))
            time.sleep(sleep_seconds)
            return
        if not _should_record_based_on_motion(
            self.app,
            self.config.device_id,
            self.config.url,
        ):
            time.sleep(5)
            return
        use_gst = bool(self.app.config.get("USE_GSTREAMER_RECORDING"))
        if use_gst:
            try:
                self._record_segment_gstreamer()
                return
            except Exception as exc:  # noqa: BLE001
                try:
                    self.app.logger.warning(
                        "Recording GStreamer failed for device=%s; falling back to ffmpeg. err=%s",
                        self.config.device_id,
                        str(exc)[:200],
                    )
                except Exception:
                    pass
        self._record_segment_ffmpeg()

    def _record_segment_ffmpeg(self) -> None:
        base_dir = self._segment_temp_dir()
        base_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        temp_path = base_dir / f"{self.config.device_id}_{timestamp}.mp4"
        # Limit ffmpeg thread usage for lower CPU impact and allow segment
        # length to be tuned via configuration.
        try:
            threads = int(
                self.app.config.get("RECORD_FFMPEG_THREADS", 2) or 2
            )
        except (TypeError, ValueError):
            threads = 2
        threads = max(1, threads)
        command = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-rtsp_transport",
            "tcp",
            "-i",
            self.config.url,
            "-t",
            str(self.segment_seconds),
            "-threads",
            str(threads),
            "-c",
            "copy",
            str(temp_path),
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("ffmpeg executable not found") from exc
        if result.returncode != 0 or not temp_path.exists():
            if temp_path.exists():
                temp_path.unlink()
            stderr_text = result.stderr or ""
            masked_url = _mask_url_password(self.config.url)
            try:
                self.app.logger.warning(
                    "Recording ffmpeg error for device=%s url=%s returncode=%s stderr=%s",
                    self.config.device_id,
                    masked_url,
                    result.returncode,
                    stderr_text.strip(),
                )
            except Exception:
                # Logging must not crash the worker.
                pass
            raise RuntimeError("recording command failed")
        segment_meta = self._validate_segment(temp_path)
        if not segment_meta:
            temp_path.unlink(missing_ok=True)
            raise RuntimeError("segment validation failed")
        key_hint = f"camera{self.config.device_id}_{timestamp}"
        router = get_storage_router(self.app)
        providers_sorted = sorted(
            self.providers,
            key=lambda p: (
                int(getattr(p, "priority", 100) or 100),
                str(getattr(p, "name", "") or ""),
            ),
        )
        for provider in providers_sorted:
            storage_key: Optional[str] = None
            instance_key = getattr(provider, "name", "") or ""
            # Primary path: route through CSAL when an instance exists.
            if instance_key:
                try:
                    stream = io.BytesIO(temp_path.read_bytes())
                    result = router.write(instance_key, stream, {"key_hint": key_hint})
                    storage_key = str(result.get("object_id") or "")
                except Exception:  # noqa: BLE001
                    storage_key = None

            # Fallback path: call the legacy provider directly if CSAL write failed.
            if not storage_key:
                try:
                    storage_key = provider.upload(temp_path.read_bytes(), key_hint)
                except Exception as exc:  # noqa: BLE001
                    self._enqueue_upload_failure(
                        provider.name,
                        key_hint,
                        temp_path.read_bytes(),
                        str(exc),
                    )
                    self._write_stat(
                        provider.name,
                        None,
                        int(segment_meta.get("size_bytes") or 0),
                        False,
                        str(exc),
                    )
                    continue

            self._create_camera_recording(provider.name, storage_key)
            self._append_ingest_index(
                {
                    **segment_meta,
                    "provider": str(provider.name or ""),
                    "storage_key": str(storage_key or ""),
                    "key_hint": key_hint,
                    "committed": True,
                }
            )
            self._write_stat(
                provider.name,
                storage_key,
                int(segment_meta.get("size_bytes") or 0),
                True,
                None,
            )
            break
        temp_path.unlink(missing_ok=True)
        self._cleanup_ingest_dirs()

    def _record_segment_gstreamer(self) -> None:
        base_dir = self._segment_temp_dir()
        base_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        temp_path = base_dir / f"{self.config.device_id}_{timestamp}.mp4"
        try:
            latency_ms = int(self.app.config.get("GST_RTSP_LATENCY_MS", 200) or 200)
        except (TypeError, ValueError):
            latency_ms = 200
        if latency_ms < 0:
            latency_ms = 0

        command = [
            "gst-launch-1.0",
            "-e",
            "rtspsrc",
            f"location={self.config.url}",
            f"latency={latency_ms}",
            "!",
            "rtph264depay",
            "!",
            "h264parse",
            "!",
            "mp4mux",
            "!",
            "filesink",
            f"location={str(temp_path)}",
        ]

        masked_url = _mask_url_password(self.config.url)
        proc: Optional[subprocess.Popen[str]] = None
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                _ = proc.wait(timeout=self.segment_seconds + 5)
            except subprocess.TimeoutExpired:
                try:
                    proc.send_signal(signal.SIGINT)
                    _ = proc.wait(timeout=10)
                except Exception:
                    proc.kill()
                    _ = proc.wait(timeout=5)
        except FileNotFoundError as exc:
            raise RuntimeError("gst-launch-1.0 executable not found") from exc

        returncode = proc.returncode if proc is not None else -1
        if returncode != 0 or not temp_path.exists():
            if temp_path.exists():
                temp_path.unlink()
            stderr_text = ""
            if proc is not None and proc.stderr is not None:
                try:
                    stderr_text = proc.stderr.read() or ""
                except Exception:
                    stderr_text = ""
            try:
                self.app.logger.warning(
                    "Recording GStreamer error for device=%s url=%s returncode=%s stderr=%s",
                    self.config.device_id,
                    masked_url,
                    returncode,
                    stderr_text.strip(),
                )
            except Exception:
                # Logging must not crash the worker.
                pass
            raise RuntimeError("recording command failed")
        segment_meta = self._validate_segment(temp_path)
        if not segment_meta:
            temp_path.unlink(missing_ok=True)
            raise RuntimeError("segment validation failed")
        key_hint = f"camera{self.config.device_id}_{timestamp}"
        providers_sorted = sorted(
            self.providers,
            key=lambda p: (
                int(getattr(p, "priority", 100) or 100),
                str(getattr(p, "name", "") or ""),
            ),
        )
        for provider in providers_sorted:
            try:
                storage_key = provider.upload(temp_path.read_bytes(), key_hint)
            except Exception as exc:  # noqa: BLE001
                self._enqueue_upload_failure(
                    provider.name,
                    key_hint,
                    temp_path.read_bytes(),
                    str(exc),
                )
                self._write_stat(
                    provider.name,
                    None,
                    int(segment_meta.get("size_bytes") or 0),
                    False,
                    str(exc),
                )
                continue
            self._create_camera_recording(provider.name, storage_key)
            self._append_ingest_index(
                {
                    **segment_meta,
                    "provider": str(provider.name or ""),
                    "storage_key": str(storage_key or ""),
                    "key_hint": key_hint,
                    "committed": True,
                }
            )
            self._write_stat(
                provider.name,
                storage_key,
                int(segment_meta.get("size_bytes") or 0),
                True,
                None,
            )
            break
        temp_path.unlink(missing_ok=True)
        self._cleanup_ingest_dirs()

    def _segment_temp_dir(self) -> Path:
        ingest_root = self._ingest_root_dir()
        if ingest_root is not None:
            return ingest_root / "segments"
        base = self.app.config.get("RECORDING_BASE_DIR") or ""
        if base:
            return Path(str(base)) / "tmp" / f"camera_{self.config.device_id}"
        return Path(self.app.instance_path) / "recording_tmp" / f"camera_{self.config.device_id}"

    def _ingest_root_dir(self) -> Optional[Path]:
        try:
            enabled = self.app.config.get("USE_SHM_INGEST")
            if enabled is None:
                enabled = True
            if not bool(enabled):
                return None
        except Exception:  # noqa: BLE001
            return None

        shm_base = Path("/dev/shm")
        if not shm_base.exists() or not shm_base.is_dir():
            return None

        root = shm_base / "pentavision" / "ingest" / f"camera_{self.config.device_id}" / f"session_{self._ingest_session_id}"
        try:
            # Quota/backpressure check before creating more data.
            if not self._shm_quota_allows_write(root.parent):
                return None
            (root / "segments").mkdir(parents=True, exist_ok=True)
            return root
        except Exception:  # noqa: BLE001
            return None

    def _shm_quota_allows_write(self, camera_root: Path) -> bool:
        """Basic backpressure: if /dev/shm usage is above limits, skip recording."""

        try:
            per_cam_limit_mb = int(self.app.config.get("SHM_INGEST_CAMERA_LIMIT_MB", 256) or 256)
        except Exception:  # noqa: BLE001
            per_cam_limit_mb = 256
        try:
            global_limit_mb = int(self.app.config.get("SHM_INGEST_GLOBAL_LIMIT_MB", 2048) or 2048)
        except Exception:  # noqa: BLE001
            global_limit_mb = 2048

        per_cam_limit_mb = max(16, per_cam_limit_mb)
        global_limit_mb = max(per_cam_limit_mb, global_limit_mb)

        cam_bytes = self._dir_size_bytes(camera_root)
        if cam_bytes >= (per_cam_limit_mb * 1024 * 1024):
            return False

        global_root = Path("/dev/shm") / "pentavision" / "ingest"
        global_bytes = self._dir_size_bytes(global_root)
        if global_bytes >= (global_limit_mb * 1024 * 1024):
            return False
        return True

    def _dir_size_bytes(self, path: Path) -> int:
        try:
            if not path.exists():
                return 0
        except Exception:  # noqa: BLE001
            return 0
        total = 0
        try:
            for root, _, files in os.walk(str(path)):
                for name in files:
                    try:
                        fp = os.path.join(root, name)
                        total += os.path.getsize(fp)
                    except Exception:  # noqa: BLE001
                        continue
        except Exception:  # noqa: BLE001
            return total
        return total

    def _validate_segment(self, path: Path) -> Optional[dict]:
        try:
            if not path.exists() or not path.is_file():
                return None
            size = path.stat().st_size
            if size <= 0:
                return None
        except Exception:  # noqa: BLE001
            return None

        sha256_hex = None
        try:
            h = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    h.update(chunk)
            sha256_hex = h.hexdigest()
        except Exception:  # noqa: BLE001
            sha256_hex = None

        duration_s = None
        try:
            if bool(self.app.config.get("SHM_INGEST_PROBE_DURATION", False)):
                result = subprocess.run(
                    [
                        "ffprobe",
                        "-v",
                        "error",
                        "-show_entries",
                        "format=duration",
                        "-of",
                        "default=nw=1:nk=1",
                        str(path),
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                if result.returncode == 0:
                    raw = (result.stdout or "").strip()
                    if raw:
                        duration_s = float(raw)
        except Exception:  # noqa: BLE001
            duration_s = None

        return {
            "segment_file": path.name,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "size_bytes": int(size),
            "sha256": sha256_hex,
            "duration_s": duration_s,
        }

    def _ingest_index_path(self) -> Optional[Path]:
        root = self._ingest_root_dir()
        if root is None:
            return None
        return root / "index.json"

    def _append_ingest_index(self, entry: dict) -> None:
        index_path = self._ingest_index_path()
        if index_path is None:
            return
        payload = {
            "camera_id": int(self.config.device_id),
            "session_id": str(self._ingest_session_id),
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "segments": [],
        }
        try:
            if index_path.exists():
                payload = json.loads(index_path.read_text(encoding="utf-8") or "{}")
                if not isinstance(payload, dict):
                    payload = {}
        except Exception:  # noqa: BLE001
            payload = {}
        if "segments" not in payload or not isinstance(payload.get("segments"), list):
            payload["segments"] = []
        payload.setdefault("camera_id", int(self.config.device_id))
        payload.setdefault("session_id", str(self._ingest_session_id))
        payload["updated_at"] = datetime.utcnow().isoformat() + "Z"
        try:
            payload["segments"].append(entry)
        except Exception:  # noqa: BLE001
            return
        try:
            index_path.write_text(json.dumps(payload, indent=2)[:2_000_000], encoding="utf-8")
        except Exception:  # noqa: BLE001
            return

    def _cleanup_ingest_dirs(self) -> None:
        root = self._ingest_root_dir()
        if root is None:
            return
        seg_dir = root / "segments"
        try:
            if seg_dir.exists() and seg_dir.is_dir() and not any(seg_dir.iterdir()):
                # Keep index.json but remove empty segment dir to reduce inode churn.
                seg_dir.rmdir()
        except Exception:  # noqa: BLE001
            return

    def _create_camera_recording(
        self,
        provider_name: str,
        storage_key: str,
    ) -> None:
        engine = get_record_engine()
        if engine is None:
            return
        CameraRecording.__table__.create(bind=engine, checkfirst=True)
        with Session(engine) as session:
            row = CameraRecording(
                device_id=self.config.device_id,
                storage_provider=provider_name,
                storage_key=storage_key,
            )
            session.add(row)
            session.commit()

    def _write_stat(
        self,
        provider_name: str,
        storage_key: Optional[str],
        bytes_written: int,
        ok: bool,
        error: Optional[str],
    ) -> None:
        engine = get_record_engine()
        if engine is None:
            return
        StorageModuleWriteStat.__table__.create(bind=engine, checkfirst=True)
        StorageModule.__table__.create(bind=engine, checkfirst=True)
        StorageModuleEvent.__table__.create(bind=engine, checkfirst=True)
        module_id_val: Optional[int] = None
        module_name_val = str(provider_name or "")
        with Session(engine) as session:
            try:
                mod = (
                    session.query(StorageModule)
                    .filter(StorageModule.name == module_name_val)
                    .first()
                )
                if mod is not None:
                    module_id_val = int(mod.id)
                    module_name_val = str(mod.name or module_name_val)
            except Exception:  # noqa: BLE001
                module_id_val = None

            try:
                session.add(
                    StorageModuleWriteStat(
                        module_id=module_id_val,
                        module_name=module_name_val,
                        device_id=int(self.config.device_id),
                        storage_key=str(storage_key or "")[:512] if storage_key else None,
                        bytes_written=int(bytes_written) if bytes_written is not None else None,
                        ok=1 if ok else 0,
                        error=str(error)[:512] if error else None,
                    )
                )
                if not ok and error:
                    session.add(
                        StorageModuleEvent(
                            module_id=module_id_val,
                            module_name=module_name_val,
                            level="error",
                            event_type="write_error",
                            message=str(error)[:1024],
                            stream_id=str(self.config.device_id),
                        )
                    )
                session.commit()
            except Exception:  # noqa: BLE001
                return

    def _enqueue_upload_failure(
        self,
        provider_name: str,
        key_hint: str,
        data: bytes,
        error: str,
    ) -> None:
        engine = get_record_engine()
        if engine is None:
            return
        UploadQueueItem.__table__.create(bind=engine, checkfirst=True)
        with Session(engine) as session:
            item = UploadQueueItem(
                device_id=self.config.device_id,
                provider_name=provider_name,
                key_hint=key_hint,
                payload=data,
                status="pending",
                attempts=0,
                last_error=error[:512],
            )
            session.add(item)
            session.commit()


class RecordingManager:
    def __init__(self, app: Flask) -> None:
        self.app = app
        self.providers = build_storage_providers(app)
        self.workers: Dict[int, CameraWorker] = {}
        self.lock = threading.Lock()
        try:
            segment_seconds = int(
                self.app.config.get("RECORD_SEGMENT_SECONDS", 60) or 60
            )
        except (TypeError, ValueError):
            segment_seconds = 60
        if segment_seconds <= 0:
            segment_seconds = 60
        self.segment_seconds = segment_seconds

    def start(self) -> None:
        if not self.providers:
            return
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()

    def run(self) -> None:
        with self.app.app_context():
            while True:
                try:
                    self._sync_workers()
                except Exception:
                    time.sleep(5)
                time.sleep(10)

    def _sync_workers(self) -> None:
        engine = get_record_engine()
        if engine is None:
            return
        with Session(engine) as session:
            devices = session.query(CameraDevice).all()
            patterns = session.query(CameraUrlPattern).all()
            CameraStoragePolicy.__table__.create(bind=engine, checkfirst=True)
            policies = session.query(CameraStoragePolicy).all()
            CameraStorageScheduleEntry.__table__.create(bind=engine, checkfirst=True)
            schedule_entries = session.query(CameraStorageScheduleEntry).all()
        patterns_index = {item.id: item for item in patterns}
        policies_index = {p.device_id: p for p in policies}
        providers_index = {p.name: p for p in self.providers}
        entries_by_device: dict[int, list[CameraStorageScheduleEntry]] = {}
        for entry in schedule_entries:
            try:
                dev_id = int(getattr(entry, "device_id", 0) or 0)
            except Exception:  # noqa: BLE001
                continue
            if dev_id <= 0:
                continue
            entries_by_device.setdefault(dev_id, []).append(entry)
        for device in devices:
            if not getattr(device, "is_active", 1):
                continue
            device_providers: List[StorageProvider] = list(self.providers)

            # Prefer new schedule entries (multiple per camera) when present.
            if device.id in entries_by_device:
                active_targets = _get_active_storage_targets(self.app, int(device.id))
                if active_targets is None:
                    # schedule entries exist but none are active
                    continue
                if not active_targets:
                    continue
                selected = [
                    providers_index[name]
                    for name in active_targets
                    if name in providers_index
                ]
                if selected:
                    device_providers = selected
                else:
                    continue
            else:
                # Legacy per-camera policy fallback.
                policy = policies_index.get(device.id)
                if policy and policy.storage_targets:
                    targets = {
                        name.strip()
                        for name in policy.storage_targets.split(",")
                        if name.strip()
                    }
                    selected = [
                        providers_index[name]
                        for name in targets
                        if name in providers_index
                    ]
                    if selected:
                        device_providers = selected
                    else:
                        continue
            if not device_providers:
                continue
            if (
                device.id in self.workers
                and self.workers[device.id].is_alive()
            ):
                continue
            pattern = None
            if getattr(device, "pattern_id", None):
                pattern = patterns_index.get(device.pattern_id)
            url = build_camera_url(device, pattern)
            if not url:
                continue
            worker = CameraWorker(
                self.app,
                CameraConfig(device.id, device.name, url),
                device_providers,
                segment_seconds=self.segment_seconds,
            )
            worker.start()
            self.workers[device.id] = worker


class UploadQueueWorker(threading.Thread):
    def __init__(
        self,
        app: Flask,
        interval: int = 30,
        batch_size: int = 20,
        max_attempts: int = 5,
    ) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.interval = interval
        self.batch_size = batch_size
        self.max_attempts = max_attempts

    def run(self) -> None:
        with self.app.app_context():
            while True:
                try:
                    self._process_once()
                except Exception:  # noqa: BLE001
                    time.sleep(self.interval)
                time.sleep(self.interval)

    def _process_once(self) -> None:
        engine = get_record_engine()
        if engine is None:
            return
        UploadQueueItem.__table__.create(bind=engine, checkfirst=True)
        CameraRecording.__table__.create(bind=engine, checkfirst=True)
        StorageModuleWriteStat.__table__.create(bind=engine, checkfirst=True)
        StorageModule.__table__.create(bind=engine, checkfirst=True)
        StorageModuleEvent.__table__.create(bind=engine, checkfirst=True)
        with Session(engine) as session:
            items = (
                session.query(UploadQueueItem)
                .filter(UploadQueueItem.status == "pending")
                .order_by(UploadQueueItem.id)
                .limit(self.batch_size)
                .all()
            )
            if not items:
                return
            providers = build_storage_providers(self.app)
            providers_index = {provider.name: provider for provider in providers}
            router = get_storage_router(self.app)
            for item in items:
                provider = providers_index.get(item.provider_name)
                if provider is None:
                    item.attempts = (item.attempts or 0) + 1
                    item.status = "failed"
                    item.last_error = "Unknown provider"
                    try:
                        session.add(
                            StorageModuleEvent(
                                module_id=None,
                                module_name=str(item.provider_name or ""),
                                level="error",
                                event_type="upload_provider_missing",
                                message="Unknown provider",
                                stream_id=str(item.device_id),
                            )
                        )
                        session.add(
                            StorageModuleWriteStat(
                                module_id=None,
                                module_name=str(item.provider_name or ""),
                                device_id=int(item.device_id),
                                storage_key=None,
                                bytes_written=int(len(item.payload or b"")),
                                ok=0,
                                error="Unknown provider",
                            )
                        )
                    except Exception:  # noqa: BLE001
                        pass
                    session.add(item)
                    session.commit()
                    continue

                storage_key: Optional[str] = None
                instance_key = item.provider_name or ""

                # Primary path: CSAL write using the provider name as instance key.
                if instance_key:
                    try:
                        stream = io.BytesIO(item.payload)
                        result = router.write(
                            instance_key,
                            stream,
                            {"key_hint": item.key_hint},
                        )
                        storage_key = str(result.get("object_id") or "")
                    except Exception:  # noqa: BLE001
                        storage_key = None

                # Fallback path: legacy provider upload.
                if not storage_key:
                    try:
                        storage_key = provider.upload(item.payload, item.key_hint)
                    except Exception as exc:  # noqa: BLE001
                        item.attempts = (item.attempts or 0) + 1
                        item.last_error = str(exc)[:512]
                        try:
                            mod = (
                                session.query(StorageModule)
                                .filter(StorageModule.name == str(item.provider_name or ""))
                                .first()
                            )
                            mod_id = int(mod.id) if mod is not None else None
                            mod_name = str(mod.name if mod is not None else (item.provider_name or ""))
                            session.add(
                                StorageModuleWriteStat(
                                    module_id=mod_id,
                                    module_name=mod_name,
                                    device_id=int(item.device_id),
                                    storage_key=None,
                                    bytes_written=int(len(item.payload or b"")),
                                    ok=0,
                                    error=str(exc)[:512],
                                )
                            )
                            session.add(
                                StorageModuleEvent(
                                    module_id=mod_id,
                                    module_name=mod_name,
                                    level="error",
                                    event_type="upload_error",
                                    message=str(exc)[:1024],
                                    stream_id=str(item.device_id),
                                )
                            )
                        except Exception:  # noqa: BLE001
                            pass
                        if item.attempts >= self.max_attempts:
                            item.status = "failed"
                        session.add(item)
                        session.commit()
                        continue

                recording = CameraRecording(
                    device_id=item.device_id,
                    storage_provider=item.provider_name,
                    storage_key=storage_key,
                )
                try:
                    mod = (
                        session.query(StorageModule)
                        .filter(StorageModule.name == str(item.provider_name or ""))
                        .first()
                    )
                    mod_id = int(mod.id) if mod is not None else None
                    mod_name = str(mod.name if mod is not None else (item.provider_name or ""))
                    session.add(
                        StorageModuleWriteStat(
                            module_id=mod_id,
                            module_name=mod_name,
                            device_id=int(item.device_id),
                            storage_key=str(storage_key or "")[:512] if storage_key else None,
                            bytes_written=int(len(item.payload or b"")),
                            ok=1,
                            error=None,
                        )
                    )
                except Exception:  # noqa: BLE001
                    pass
                session.add(recording)
                session.delete(item)
                session.commit()


class RetentionWorker(threading.Thread):
    def __init__(
        self,
        app: Flask,
        interval: int = 3600,
    ) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.interval = interval

    def run(self) -> None:
        with self.app.app_context():
            while True:
                try:
                    self._run_once()
                except Exception:  # noqa: BLE001
                    time.sleep(self.interval)
                time.sleep(self.interval)

    def _run_once(self) -> None:
        engine = get_record_engine()
        if engine is None:
            return
        now = datetime.now(timezone.utc)
        providers = build_storage_providers(self.app)
        providers_index = {p.name: p for p in providers}
        router = get_storage_router(self.app)
        with Session(engine) as session:
            CameraRecording.__table__.create(bind=engine, checkfirst=True)
            CameraStoragePolicy.__table__.create(bind=engine, checkfirst=True)
            policies = (
                session.query(CameraStoragePolicy)
                .filter(CameraStoragePolicy.retention_days.isnot(None))
                .all()
            )
            for policy in policies:
                if not policy.retention_days or policy.retention_days <= 0:
                    continue
                cutoff = now - timedelta(days=policy.retention_days)
                old_records = (
                    session.query(CameraRecording)
                    .filter(
                        CameraRecording.device_id == policy.device_id,
                        CameraRecording.created_at < cutoff,
                    )
                    .all()
                )
                if not old_records:
                    continue
                for rec in old_records:
                    provider = providers_index.get(rec.storage_provider)
                    storage_key = rec.storage_key or ""
                    # Prefer CSAL-based delete when an instance is available.
                    deleted_via_csal = False
                    instance_key = rec.storage_provider or ""
                    if instance_key:
                        try:
                            instance = router.get_instance(instance_key)
                            if instance is not None:
                                instance.impl.delete(storage_key)
                                deleted_via_csal = True
                        except Exception:  # noqa: BLE001
                            deleted_via_csal = False

                    if not deleted_via_csal and provider is not None:
                        try:
                            provider.delete(storage_key)
                        except Exception:  # noqa: BLE001
                            pass

                    session.delete(rec)
                session.commit()


def start_recording_service(app: Flask) -> None:
    enabled = _normalize_bool(
        str(app.config.get("RECORDING_ENABLED", "0") or "0")
    )
    if not enabled:
        return
    # Some helpers (notably db.get_record_engine) currently depend on
    # flask.current_app. Ensure we have an application context here since
    # this is started from a systemd worker process.
    with app.app_context():
        manager = RecordingManager(app)
        manager.start()
        queue_worker = UploadQueueWorker(app)
        queue_worker.start()
        retention_worker = RetentionWorker(app)
        retention_worker.start()
