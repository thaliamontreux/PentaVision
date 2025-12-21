from __future__ import annotations

import io
import os
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask
from sqlalchemy.orm import Session

from .camera_utils import build_camera_url
from .db import get_record_engine
from .models import CameraDevice, CameraRecording, CameraStoragePolicy, CameraUrlPattern
from .storage_csal import get_storage_router
from .storage_providers import StorageProvider, build_storage_providers
from .preview_history import write_frame


def _mask_url_password(url: str) -> str:
    if not url:
        return url
    try:
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url)
        if parsed.username is None and parsed.password is None:
            return url
        username = parsed.username or ""
        password = parsed.password or ""
        masked_userinfo = username
        if password:
            stars = "*" * len(password)
            masked_userinfo = f"{username}:{stars}" if username else stars
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        netloc = f"{masked_userinfo}@{host}" if masked_userinfo else host
        return urlunparse(parsed._replace(netloc=netloc))
    except Exception:
        return url


class IngestCameraConfig:
    def __init__(self, device_id: int, name: str, url: str, dir_key: str) -> None:
        self.device_id = device_id
        self.name = name
        self.url = url
        self.dir_key = dir_key


def _normalize_dir_key(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    parts: list[str] = []
    for ch in text:
        if ch.isalnum():
            parts.append(ch)
    return "".join(parts)


class CameraIngestProcess:
    def __init__(self, app: Flask, config: IngestCameraConfig, segment_seconds: int) -> None:
        self.app = app
        self.config = config
        self.segment_seconds = max(5, int(segment_seconds))
        self.session_id = uuid.uuid4().hex
        self.proc: Optional[subprocess.Popen[str]] = None
        self.base_dir = self._ingest_root_dir()
        self.segments_dir = self.base_dir / "segments"
        self.segments_dir.mkdir(parents=True, exist_ok=True)

    def _ingest_root_dir(self) -> Path:
        try:
            shm_required = bool(self.app.config.get("SHM_PROCESSING_REQUIRED", True))
        except Exception:
            shm_required = True
        use_shm = self.app.config.get("USE_SHM_INGEST")
        if use_shm is None:
            use_shm = True
        if bool(use_shm) and Path("/dev/shm").is_dir():
            return (
                Path("/dev/shm")
                / "pentavision"
                / "ingest"
                / f"camera_{self.config.dir_key}"
                / f"session_{self.session_id}"
            )
        if shm_required:
            raise RuntimeError("SHM_PROCESSING_REQUIRED enabled but /dev/shm ingest not available")
        base = str(self.app.config.get("RECORDING_BASE_DIR", "") or "").strip()
        if base:
            return Path(base) / "ingest" / f"camera_{self.config.dir_key}" / f"session_{self.session_id}"
        return Path(self.app.instance_path) / "ingest" / f"camera_{self.config.dir_key}" / f"session_{self.session_id}"

    def start(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            return

        ts_fmt = "%Y%m%dT%H%M%S"
        out_pattern = str(self.segments_dir / f"{self.config.device_id}_{ts_fmt}.mp4")

        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-rtsp_transport",
            "tcp",
            "-fflags",
            "nobuffer",
            "-flags",
            "low_delay",
            "-probesize",
            "32",
            "-analyzeduration",
            "0",
            "-i",
            self.config.url,
            "-c",
            "copy",
            "-f",
            "segment",
            "-reset_timestamps",
            "1",
            "-segment_time",
            str(self.segment_seconds),
            "-strftime",
            "1",
            out_pattern,
        ]

        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

    def stop(self) -> None:
        proc = self.proc
        self.proc = None
        if proc is None:
            return
        try:
            proc.send_signal(signal.SIGTERM)
        except Exception:
            return


class IngestManager(threading.Thread):
    def __init__(self, app: Flask) -> None:
        super().__init__(daemon=True)
        self.app = app
        self._lock = threading.Lock()
        self._ingestors: Dict[int, CameraIngestProcess] = {}
        self._last_urls: Dict[int, str] = {}

        try:
            segment_seconds = int(app.config.get("RECORD_SEGMENT_SECONDS", 60) or 60)
        except (TypeError, ValueError):
            segment_seconds = 60
        self.segment_seconds = max(5, segment_seconds)

    def run(self) -> None:
        with self.app.app_context():
            while True:
                try:
                    self._sync()
                except Exception:
                    time.sleep(5)
                time.sleep(10)

    def _sync(self) -> None:
        engine = get_record_engine()
        if engine is None:
            return
        with Session(engine) as session:
            devices = session.query(CameraDevice).all()
            patterns = session.query(CameraUrlPattern).all()
        patterns_index = {p.id: p for p in patterns}

        desired: Dict[int, IngestCameraConfig] = {}
        for device in devices:
            if not getattr(device, "is_active", 1):
                continue
            pattern = patterns_index.get(device.pattern_id) if getattr(device, "pattern_id", None) else None
            url = build_camera_url(device, pattern)
            if not url:
                continue
            raw_key = str(getattr(device, "mac_address", "") or "")
            dir_key = _normalize_dir_key(raw_key) or str(int(device.id))
            desired[int(device.id)] = IngestCameraConfig(int(device.id), str(device.name or ""), url, dir_key)

        with self._lock:
            # Start/update
            for device_id, cfg in desired.items():
                ingest = self._ingestors.get(device_id)
                last_url = self._last_urls.get(device_id)
                if ingest is None or last_url != cfg.url:
                    if ingest is not None:
                        ingest.stop()
                    ingest = CameraIngestProcess(self.app, cfg, self.segment_seconds)
                    ingest.start()
                    self._ingestors[device_id] = ingest
                    self._last_urls[device_id] = cfg.url
                    continue
                if ingest.proc is None or ingest.proc.poll() is not None:
                    ingest.start()

            # Stop removed
            for device_id in list(self._ingestors.keys()):
                if device_id not in desired:
                    self._ingestors[device_id].stop()
                    self._ingestors.pop(device_id, None)
                    self._last_urls.pop(device_id, None)

    def list_ingest_dirs(self) -> List[Path]:
        with self._lock:
            return [i.segments_dir for i in self._ingestors.values()]


class SegmentUploader(threading.Thread):
    def __init__(self, app: Flask, ingest_manager: IngestManager) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.ingest_manager = ingest_manager
        self.providers = build_storage_providers(app)

    def run(self) -> None:
        with self.app.app_context():
            while True:
                try:
                    self._drain_once()
                except Exception:
                    time.sleep(2)
                time.sleep(2)

    def _drain_once(self) -> None:
        if not self.providers:
            return

        router = get_storage_router(self.app)
        engine = get_record_engine()
        if engine is None:
            return

        for seg_dir in self.ingest_manager.list_ingest_dirs():
            if not seg_dir.exists():
                continue
            for path in sorted(seg_dir.glob("*.mp4")):
                # Only process files that have settled a bit.
                try:
                    st = path.stat()
                except Exception:
                    continue
                if st.st_size <= 0:
                    continue
                if (time.time() - st.st_mtime) < 2.0:
                    continue

                device_id = self._parse_device_id(path.name)
                if device_id is None:
                    continue
                timestamp = self._parse_timestamp(path.name)
                key_hint = f"camera{device_id}_{timestamp}" if timestamp else f"camera{device_id}"

                providers_sorted = sorted(
                    self.providers,
                    key=lambda p: (
                        int(getattr(p, "priority", 100) or 100),
                        str(getattr(p, "name", "") or ""),
                    ),
                )

                committed = False
                data = b""
                try:
                    data = path.read_bytes()
                except Exception:
                    continue

                for provider in providers_sorted:
                    storage_key: Optional[str] = None
                    instance_key = getattr(provider, "name", "") or ""
                    if instance_key:
                        try:
                            result = router.write(instance_key, io.BytesIO(data), {"key_hint": key_hint})
                            storage_key = str(result.get("object_id") or "")
                        except Exception:
                            storage_key = None
                    if not storage_key:
                        try:
                            storage_key = provider.upload(data, key_hint)
                        except Exception:
                            storage_key = None
                    if not storage_key:
                        continue
                    self._create_camera_recording(engine, device_id, provider.name, storage_key)
                    committed = True
                    break

                if committed:
                    self._write_preview_from_segment(device_id, path)
                    try:
                        path.unlink(missing_ok=True)
                    except Exception:
                        pass

    def _create_camera_recording(self, engine, device_id: int, provider_name: str, storage_key: str) -> None:
        CameraRecording.__table__.create(bind=engine, checkfirst=True)
        with Session(engine) as session:
            session.add(
                CameraRecording(
                    device_id=int(device_id),
                    storage_provider=str(provider_name or "")[:100],
                    storage_key=str(storage_key or "")[:512],
                )
            )
            session.commit()

    def _write_preview_from_segment(self, device_id: int, segment_path: Path) -> None:
        preview_base = str(self.app.config.get("PREVIEW_CACHE_DIR", "/var/lib/pentavision/previews"))
        if not preview_base:
            return
        out_dir = Path(preview_base)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            return
        tmp_path = out_dir / f"{device_id}.jpg.tmp"
        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-ss",
            "0.5",
            "-i",
            str(segment_path),
            "-frames:v",
            "1",
            "-q:v",
            "5",
            str(tmp_path),
        ]
        try:
            res = subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception:
            return
        if res.returncode != 0:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            return
        try:
            if tmp_path.exists():
                jpg_bytes = tmp_path.read_bytes()
                write_frame(self.app, device_id, jpg_bytes)
                tmp_path.unlink(missing_ok=True)
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

    def _parse_device_id(self, filename: str) -> Optional[int]:
        try:
            head = filename.split("_", 1)[0]
            return int(head)
        except Exception:
            return None

    def _parse_timestamp(self, filename: str) -> str:
        try:
            rest = filename.split("_", 1)[1]
            ts = rest.split(".", 1)[0]
            return ts
        except Exception:
            return ""


def start_ingest_service(app: Flask) -> None:
    enabled_raw = str(app.config.get("INGEST_ENABLED", "0") or "0").strip().lower()
    if enabled_raw not in {"1", "true", "yes", "on"}:
        return

    manager = IngestManager(app)
    app.extensions["ingest_manager"] = manager
    manager.start()

    uploader = SegmentUploader(app, manager)
    uploader.start()
