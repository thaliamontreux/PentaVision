from __future__ import annotations

import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from flask import Flask
from sqlalchemy.orm import Session

from .camera_utils import build_camera_url
from .db import get_record_engine
from .models import (
    CameraDevice,
    CameraDlnaMedia,
    CameraUrlPattern,
    DlnaSettings,
)


def _normalize_bool(value: str) -> bool:
    if not value:
        return False
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "on"}


def _mask_url_password(url: str) -> str:
    if not url:
        return url
    from urllib.parse import urlparse, urlunparse

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


def _slugify_title(title: str, device_id: int) -> str:
    text = (title or "").strip().lower()
    if not text:
        return f"camera{device_id}"
    parts = []
    for ch in text:
        if ch.isalnum():
            parts.append(ch)
        elif ch in {" ", "-", "_"}:
            parts.append("_")
    slug = "".join(parts).strip("_")
    return slug or f"camera{device_id}"


def _build_media_path(app: Flask, device_id: int, title: str) -> Path:
    instance_path = Path(app.instance_path)
    base_dir = instance_path / "dlna" / "media"
    base_dir.mkdir(parents=True, exist_ok=True)
    slug = _slugify_title(title, device_id)
    filename = f"camera_{device_id}_{slug}.ts"
    return base_dir / filename


class DlnaMediaWorker(threading.Thread):
    def __init__(
        self,
        app: Flask,
        device_id: int,
        camera_url: str,
        media_path: Path,
    ) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.device_id = device_id
        self.camera_url = camera_url
        self.media_path = media_path
        self._running = True
        self._proc: Optional[subprocess.Popen[str]] = None
        self._backoff = 1.0

    def stop(self) -> None:
        self._running = False
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
        except Exception:
            pass

    def run(self) -> None:
        with self.app.app_context():
            while self._running:
                try:
                    self._run_once()
                    self._backoff = 1.0
                except Exception:
                    delay = min(self._backoff, 30.0)
                    time.sleep(delay)
                    self._backoff = min(self._backoff * 2.0, 30.0)

    def _run_once(self) -> None:
        engine = get_record_engine()
        if engine is None:
            time.sleep(30.0)
            return

        with Session(engine) as session_db:
            CameraDlnaMedia.__table__.create(bind=engine, checkfirst=True)
            row = (
                session_db.query(CameraDlnaMedia)
                .filter(CameraDlnaMedia.device_id == self.device_id)
                .first()
            )
            if row is None or getattr(row, "is_enabled", 0) != 1:
                self._running = False
                return
            now = datetime.now(timezone.utc)
            row.last_started_at = now
            row.last_error = None
            session_db.add(row)
            session_db.commit()

        self.media_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if self.media_path.exists():
                self.media_path.unlink()
        except Exception:
            pass

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
            self.camera_url,
            "-threads",
            str(threads),
            "-c",
            "copy",
            "-f",
            "mpegts",
            str(self.media_path),
        ]

        masked_url = _mask_url_password(self.camera_url)
        proc: Optional[subprocess.Popen[str]] = None
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._proc = proc
        except FileNotFoundError as exc:
            self._update_error(f"ffmpeg executable not found: {exc}")
            raise
        except Exception as exc:
            self._update_error(str(exc))
            raise

        try:
            stderr = proc.stderr
            if stderr is None:
                proc.wait()
            else:
                for line in stderr:
                    if not self._running:
                        break
                    text = (line or "").strip()
                    if not text:
                        continue
                    try:
                        self.app.logger.warning(
                            "DLNA media ffmpeg device=%s url=%s: %s",
                            self.device_id,
                            masked_url,
                            text,
                        )
                    except Exception:
                        pass
        finally:
            returncode: Optional[int]
            try:
                returncode = proc.poll() if proc is not None else None
            except Exception:
                returncode = None
            if proc is not None and returncode is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                except Exception:
                    try:
                        proc.kill()
                        proc.wait(timeout=5)
                    except Exception:
                        pass
            if returncode not in (0, None):
                self._update_error(f"ffmpeg exited with code {returncode}")

    def _update_error(self, message: str) -> None:
        engine = get_record_engine()
        if engine is None:
            return
        with Session(engine) as session_db:
            CameraDlnaMedia.__table__.create(bind=engine, checkfirst=True)
            row = (
                session_db.query(CameraDlnaMedia)
                .filter(CameraDlnaMedia.device_id == self.device_id)
                .first()
            )
            if row is None:
                return
            row.last_error = (message or "")[:512]
            session_db.add(row)
            session_db.commit()


class DlnaMediaManager:
    def __init__(self, app: Flask) -> None:
        self.app = app
        self._workers: Dict[int, DlnaMediaWorker] = {}
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def run(self) -> None:
        with self.app.app_context():
            while True:
                try:
                    self._sync_workers()
                except Exception:
                    time.sleep(5.0)
                time.sleep(10.0)

    def _sync_workers(self) -> None:
        engine = get_record_engine()
        if engine is None:
            return

        with Session(engine) as session_db:
            DlnaSettings.__table__.create(bind=engine, checkfirst=True)
            CameraDlnaMedia.__table__.create(bind=engine, checkfirst=True)
            settings = (
                session_db.query(DlnaSettings)
                .order_by(DlnaSettings.id)
                .first()
            )
            devices = session_db.query(CameraDevice).all()
            patterns = session_db.query(CameraUrlPattern).all()
            media_rows = (
                session_db.query(CameraDlnaMedia)
                .filter(CameraDlnaMedia.is_enabled == 1)
                .all()
            )

        patterns_index = {p.id: p for p in patterns}
        devices_index = {d.id: d for d in devices}

        desired: Dict[int, tuple[str, str]] = {}
        if settings is not None and getattr(settings, "enabled", 0):
            for media in media_rows:
                device = devices_index.get(media.device_id)
                if device is None or not getattr(device, "is_active", 1):
                    continue
                pattern = None
                if getattr(device, "pattern_id", None):
                    pattern = patterns_index.get(device.pattern_id)
                camera_url = build_camera_url(device, pattern)
                if not camera_url:
                    continue
                raw_title = (media.title or "").strip()
                fallback_title = device.name or f"Camera {device.id}"
                title = raw_title or fallback_title
                media_path = _build_media_path(self.app, device.id, title)
                desired[device.id] = (camera_url, str(media_path))

        with self._lock:
            for device_id, (camera_url, media_path_str) in desired.items():
                worker = self._workers.get(device_id)
                needs_new = False
                if worker is None or not worker.is_alive():
                    needs_new = True
                elif (
                    worker.camera_url != camera_url
                    or str(worker.media_path) != media_path_str
                ):
                    worker.stop()
                    needs_new = True
                if needs_new:
                    new_worker = DlnaMediaWorker(
                        self.app,
                        device_id,
                        camera_url,
                        Path(media_path_str),
                    )
                    new_worker.start()
                    self._workers[device_id] = new_worker

            for device_id in list(self._workers.keys()):
                if device_id not in desired:
                    worker = self._workers.pop(device_id)
                    worker.stop()


def start_dlna_media_service(app: Flask) -> None:
    raw = str(app.config.get("DLNA_ENABLED", "0") or "0")
    if not _normalize_bool(raw):
        return
    manager = DlnaMediaManager(app)
    app.extensions["dlna_media_manager"] = manager
    manager.start()
