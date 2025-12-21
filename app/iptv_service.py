from __future__ import annotations

import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Optional
from urllib.parse import urlparse, urlunparse

from flask import Flask
from sqlalchemy.orm import Session

from .camera_utils import build_camera_url
from .db import get_record_engine
from .models import CameraDevice, CameraUrlPattern
from .models_iptv import CameraIptvChannel


def _normalize_bool(value: str) -> bool:
    if not value:
        return False
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "on"}


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


def _build_udp_url(multicast_address: str, port: int, ttl: Optional[int]) -> str:
    addr = (multicast_address or "").strip()
    if not addr:
        raise ValueError("Multicast address is required")
    port_value = int(port or 0)
    if port_value <= 0 or port_value > 65535:
        raise ValueError("Port must be between 1 and 65535")
    ttl_value = int(ttl or 0) or 4
    return f"udp://{addr}:{port_value}?ttl={ttl_value}&pkt_size=1316"


class IptvWorker(threading.Thread):
    def __init__(
        self,
        app: Flask,
        channel_id: int,
        device_id: int,
        camera_url: str,
        multicast_address: str,
        port: int,
        ttl: Optional[int],
    ) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.channel_id = channel_id
        self.device_id = device_id
        self.camera_url = camera_url
        self.multicast_address = multicast_address
        self.port = port
        self.ttl = ttl
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
            CameraIptvChannel.__table__.create(bind=engine, checkfirst=True)
            row = session_db.get(CameraIptvChannel, self.channel_id)
            if row is None or getattr(row, "is_enabled", 0) != 1:
                self._running = False
                return
            now = datetime.now(timezone.utc)
            row.last_started_at = now
            row.last_error = None
            session_db.add(row)
            session_db.commit()

        try:
            udp_url = _build_udp_url(self.multicast_address, self.port, self.ttl)
        except Exception as exc:
            self._update_error(str(exc))
            self._running = False
            return

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
            "-fflags",
            "nobuffer",
            "-flags",
            "low_delay",
            "-probesize",
            "32",
            "-analyzeduration",
            "0",
            "-i",
            self.camera_url,
            "-threads",
            str(threads),
            "-c",
            "copy",
            "-f",
            "mpegts",
            "-muxdelay",
            "0.1",
            "-muxpreload",
            "0",
            udp_url,
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
                            "IPTV ffmpeg device=%s channel=%s url=%s: %s",
                            self.device_id,
                            self.channel_id,
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
            CameraIptvChannel.__table__.create(bind=engine, checkfirst=True)
            row = session_db.get(CameraIptvChannel, self.channel_id)
            if row is None:
                return
            row.last_error = (message or "")[:512]
            session_db.add(row)
            session_db.commit()


class IptvManager:
    def __init__(self, app: Flask) -> None:
        self.app = app
        self._workers: Dict[int, IptvWorker] = {}
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
            CameraIptvChannel.__table__.create(bind=engine, checkfirst=True)
            devices = session_db.query(CameraDevice).all()
            patterns = session_db.query(CameraUrlPattern).all()
            channels = (
                session_db.query(CameraIptvChannel)
                .filter(CameraIptvChannel.is_enabled == 1)
                .all()
            )

        patterns_index = {p.id: p for p in patterns}
        devices_index = {d.id: d for d in devices}

        desired: Dict[int, tuple[int, str, str, int, Optional[int]]] = {}
        for channel in channels:
            device = devices_index.get(channel.device_id)
            if device is None or not getattr(device, "is_active", 1):
                continue
            pattern = None
            if getattr(device, "pattern_id", None):
                pattern = patterns_index.get(device.pattern_id)
            camera_url = build_camera_url(device, pattern)
            if not camera_url:
                continue
            desired[channel.id] = (
                device.id,
                camera_url,
                channel.multicast_address,
                channel.port,
                channel.ttl,
            )

        with self._lock:
            for channel_id, (
                device_id,
                camera_url,
                multicast_address,
                port,
                ttl,
            ) in desired.items():
                worker = self._workers.get(channel_id)
                needs_new = False
                if worker is None or not worker.is_alive():
                    needs_new = True
                elif (
                    worker.camera_url != camera_url
                    or worker.multicast_address != multicast_address
                    or worker.port != port
                    or worker.ttl != ttl
                    or worker.device_id != device_id
                ):
                    worker.stop()
                    needs_new = True
                if needs_new:
                    new_worker = IptvWorker(
                        self.app,
                        channel_id,
                        device_id,
                        camera_url,
                        multicast_address,
                        port,
                        ttl,
                    )
                    new_worker.start()
                    self._workers[channel_id] = new_worker

            for channel_id in list(self._workers.keys()):
                if channel_id not in desired:
                    worker = self._workers.pop(channel_id)
                    worker.stop()


def start_iptv_service(app: Flask) -> None:
    return
