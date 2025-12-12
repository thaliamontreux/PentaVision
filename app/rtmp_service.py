from __future__ import annotations

import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from flask import Flask
from sqlalchemy.orm import Session

from .db import get_record_engine
from .models import CameraDevice, CameraRtmpOutput


def _normalize_bool(value: str) -> bool:
    if not value:
        return False
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "on"}


class RtmpWorker(threading.Thread):
    def __init__(
        self,
        app: Flask,
        output_id: int,
        device_id: int,
        camera_url: str,
        target_url: str,
    ) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.output_id = output_id
        self.device_id = device_id
        self.camera_url = camera_url
        self.target_url = target_url
        self._running = True
        self._backoff = 1.0

    def stop(self) -> None:
        self._running = False

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
        with Session(engine) as session:
            row = session.get(CameraRtmpOutput, self.output_id)
            if row is None or not getattr(row, "is_active", 1):
                self._running = False
                return
            row.last_started_at = datetime.now(timezone.utc)
            row.last_error = None
            session.add(row)
            session.commit()
        # Derive preview source configuration. We restream from the
        # PentaVision preview frames written by the video worker into
        # PREVIEW_CACHE_DIR instead of opening a separate RTSP session
        # to the camera.
        preview_dir = str(
            self.app.config.get(
                "PREVIEW_CACHE_DIR",
                "/var/lib/pentavision/previews",
            )
        )
        try:
            fps = float(self.app.config.get("RTMP_INPUT_FPS", 0.0) or 0.0)
        except (TypeError, ValueError):
            fps = 0.0
        if fps <= 0.0:
            try:
                fps = float(
                    self.app.config.get("PREVIEW_CAPTURE_FPS", 10.0) or 10.0
                )
            except (TypeError, ValueError):
                fps = 10.0
        if fps <= 0.0:
            fps = 10.0
        interval = 1.0 / fps

        src_path = Path(preview_dir) / f"{self.device_id}.jpg"

        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-re",
            "-f",
            "mjpeg",
            "-i",
            "pipe:0",
            "-an",
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-tune",
            "zerolatency",
            "-pix_fmt",
            "yuv420p",
            "-f",
            "flv",
            self.target_url,
        ]

        proc: Optional[subprocess.Popen[bytes]] = None
        feeder: Optional[threading.Thread] = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            self._update_error(f"ffmpeg executable not found: {exc}")
            raise
        except Exception as exc:
            self._update_error(str(exc))
            raise

        def _feed_frames() -> None:
            if proc is None or proc.stdin is None:
                return
            stdin = proc.stdin
            while self._running:
                try:
                    if not src_path.exists():
                        time.sleep(interval)
                        continue
                    try:
                        data = src_path.read_bytes()
                    except OSError:
                        time.sleep(interval)
                        continue
                    if not data:
                        time.sleep(interval)
                        continue
                    try:
                        stdin.write(data)
                        stdin.flush()
                    except BrokenPipeError:
                        break
                    except Exception:
                        time.sleep(interval)
                        continue
                    time.sleep(interval)
                except Exception:
                    time.sleep(interval)
                    continue

        feeder = threading.Thread(target=_feed_frames, daemon=True)
        feeder.start()

        try:
            stderr = proc.stderr
            if stderr is None:
                proc.wait()
            else:
                for raw_line in stderr:
                    if not self._running:
                        break
                    try:
                        text = raw_line.decode("utf-8", "ignore").strip()
                    except Exception:
                        text = ""
                    if not text:
                        continue
                    try:
                        self.app.logger.warning(
                            "RTMP ffmpeg device=%s output=%s: %s",
                            self.device_id,
                            self.output_id,
                            text,
                        )
                    except Exception:
                        pass
        finally:
            self._running = False
            returncode: Optional[int]
            try:
                returncode = proc.poll() if proc is not None else None
            except Exception:
                returncode = None
            if feeder is not None and feeder.is_alive():
                try:
                    feeder.join(timeout=5.0)
                except Exception:
                    pass
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
        with Session(engine) as session:
            row = session.get(CameraRtmpOutput, self.output_id)
            if row is None:
                return
            row.last_error = (message or "")[:512]
            session.add(row)
            session.commit()


class RtmpManager:
    def __init__(self, app: Flask) -> None:
        self.app = app
        self._workers: Dict[int, RtmpWorker] = {}
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
        with Session(engine) as session:
            CameraRtmpOutput.__table__.create(bind=engine, checkfirst=True)
            devices = session.query(CameraDevice).all()
            outputs = (
                session.query(CameraRtmpOutput)
                .filter(CameraRtmpOutput.is_active == 1)
                .all()
            )
        devices_index = {d.id: d for d in devices}
        desired: Dict[int, tuple[int, str]] = {}
        for output in outputs:
            device = devices_index.get(output.device_id)
            if device is None or not getattr(device, "is_active", 1):
                continue
            desired[output.id] = (device.id, output.target_url)
        with self._lock:
            for output_id, (device_id, target_url) in desired.items():
                worker = self._workers.get(output_id)
                needs_new = False
                if worker is None or not worker.is_alive():
                    needs_new = True
                elif (
                    worker.target_url != target_url
                    or worker.device_id != device_id
                ):
                    worker.stop()
                    needs_new = True
                if needs_new:
                    new_worker = RtmpWorker(
                        self.app,
                        output_id,
                        device_id,
                        f"device-{device_id}",
                        target_url,
                    )
                    new_worker.start()
                    self._workers[output_id] = new_worker
            for output_id in list(self._workers.keys()):
                if output_id not in desired:
                    worker = self._workers.pop(output_id)
                    worker.stop()


def start_rtmp_service(app: Flask) -> None:
    raw = str(app.config.get("RTMP_ENABLED", "0") or "0")
    if not _normalize_bool(raw):
        return
    manager = RtmpManager(app)
    app.extensions["rtmp_manager"] = manager
    manager.start()
