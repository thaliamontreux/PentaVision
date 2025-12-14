from __future__ import annotations

import io
import signal
import subprocess
import threading
import time
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
    CameraStoragePolicy,
    CameraUrlPattern,
    Property,
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
        CameraRecordingSchedule.__table__.create(bind=engine, checkfirst=True)
        CameraRecordingWindow.__table__.create(bind=engine, checkfirst=True)
        CameraPropertyLink.__table__.create(bind=engine, checkfirst=True)
        Property.__table__.create(bind=engine, checkfirst=True)
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
            self._record_segment_gstreamer()
        else:
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
        data = temp_path.read_bytes()
        key_hint = f"camera{self.config.device_id}_{timestamp}"
        router = get_storage_router(self.app)
        for provider in self.providers:
            storage_key: Optional[str] = None
            instance_key = getattr(provider, "name", "") or ""
            # Primary path: route through CSAL when an instance exists.
            if instance_key:
                try:
                    stream = io.BytesIO(data)
                    result = router.write(instance_key, stream, {"key_hint": key_hint})
                    storage_key = str(result.get("object_id") or "")
                except Exception:  # noqa: BLE001
                    storage_key = None

            # Fallback path: call the legacy provider directly if CSAL write failed.
            if not storage_key:
                try:
                    storage_key = provider.upload(data, key_hint)
                except Exception as exc:  # noqa: BLE001
                    self._enqueue_upload_failure(
                        provider.name,
                        key_hint,
                        data,
                        str(exc),
                    )
                    continue

            self._create_camera_recording(provider.name, storage_key)
        temp_path.unlink(missing_ok=True)

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
        data = temp_path.read_bytes()
        key_hint = f"camera{self.config.device_id}_{timestamp}"
        for provider in self.providers:
            try:
                storage_key = provider.upload(data, key_hint)
            except Exception as exc:  # noqa: BLE001
                self._enqueue_upload_failure(
                    provider.name,
                    key_hint,
                    data,
                    str(exc),
                )
                continue
            self._create_camera_recording(provider.name, storage_key)
        temp_path.unlink(missing_ok=True)

    def _segment_temp_dir(self) -> Path:
        base = self.app.config.get("RECORDING_BASE_DIR") or ""
        if base:
            return Path(str(base)) / "tmp"
        return Path(self.app.instance_path) / "recording_tmp"

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
        patterns_index = {item.id: item for item in patterns}
        policies_index = {p.device_id: p for p in policies}
        providers_index = {p.name: p for p in self.providers}
        for device in devices:
            if not getattr(device, "is_active", 1):
                continue
            policy = policies_index.get(device.id)
            device_providers: List[StorageProvider] = list(self.providers)
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
    manager = RecordingManager(app)
    manager.start()
    queue_worker = UploadQueueWorker(app)
    queue_worker.start()
    retention_worker = RetentionWorker(app)
    retention_worker.start()
