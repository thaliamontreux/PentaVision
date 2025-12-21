from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from typing import Dict, Optional
from urllib.parse import urlparse, urlunparse

from flask import Flask
from sqlalchemy.orm import Session

from .camera_utils import build_camera_url
from .db import get_record_engine
from .models import CameraDevice, CameraUrlPattern
from .preview_history import write_frame


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


class CameraStream(threading.Thread):
    def __init__(self, app: Flask, device_id: int, url: str) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.device_id = device_id
        self.url = url
        self._lock = threading.Lock()
        self._last_frame: Optional[bytes] = None
        self._last_frame_time: Optional[float] = None
        self._last_full_frame: Optional[bytes] = None
        self._last_full_frame_time: Optional[float] = None
        self._last_error: Optional[dict] = None
        self._last_error_time: Optional[float] = None
        self._running = True
        self._ffmpeg_process: Optional[subprocess.Popen] = None
        self._ffmpeg_thread: Optional[threading.Thread] = None
        self._permanent_failure = False
        self._preview_dir: str = str(
            app.config.get("PREVIEW_CACHE_DIR", "/var/lib/pentavision/previews")
        )
        self._preview_dir_ready = False
        raw_diag = str(app.config.get("STREAM_FFMPEG_DIAGNOSTICS", "0") or "0")
        self._enable_ffmpeg_diag = raw_diag.strip().lower() not in {"0", "false", "no", ""}
        raw_use_gst = str(app.config.get("USE_GSTREAMER_CAPTURE", "0") or "0")
        self._use_gstreamer = raw_use_gst.strip().lower() in {"1", "true", "yes", "on"}
        raw_fullres = str(app.config.get("SESSION_ENABLE_FULLRES_STREAM", "0") or "0")
        self._enable_fullres = raw_fullres.strip().lower() in {"1", "true", "yes", "on"}
        try:
            latency_ms = int(app.config.get("GST_RTSP_LATENCY_MS", 200) or 200)
        except (TypeError, ValueError):
            latency_ms = 200
        if latency_ms < 0:
            latency_ms = 0
        self._gst_latency_ms = latency_ms

    def stop(self) -> None:
        self._running = False
        proc = self._ffmpeg_process
        self._ffmpeg_process = None
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass

    def get_frame(self) -> Optional[bytes]:
        with self._lock:
            return self._last_frame

    def get_last_frame_time(self) -> Optional[float]:
        with self._lock:
            return self._last_frame_time

    def get_full_frame(self) -> Optional[bytes]:
        """Return the most recent full-resolution JPEG frame, if available.

        Falls back to the scaled preview frame if a full-resolution frame has
        not been captured yet.
        """

        with self._lock:
            return self._last_full_frame or self._last_frame

    def get_last_full_frame_time(self) -> Optional[float]:
        with self._lock:
            return self._last_full_frame_time

    def get_last_error_time(self) -> Optional[float]:
        with self._lock:
            return self._last_error_time

    def get_last_error(self) -> Optional[dict]:
        with self._lock:
            if self._last_error is None:
                return None
            return dict(self._last_error)

    def _set_error(self, stage: str, message: str, permanent: bool = False) -> None:
        parsed = urlparse(self.url)
        ip = parsed.hostname or ""
        ts = time.time()
        info = {
            "device_id": self.device_id,
            "stage": stage,
            "message": message,
            "url": _mask_url_password(self.url),
            "ip": ip,
            "timestamp": ts,
            "permanent": permanent,
        }
        should_log = True
        with self._lock:
            prev = self._last_error
            prev_ts = self._last_error_time
            self._last_error = info
            self._last_error_time = ts
            if permanent:
                self._permanent_failure = True
            if (
                prev
                and prev.get("stage") == stage
                and prev.get("ip") == ip
                and prev.get("message") == message
                and prev_ts is not None
                and ts - prev_ts < 10.0
            ):
                should_log = False

        if should_log:
            try:
                self.app.logger.warning(
                    "CameraStream error device=%s ip=%s stage=%s msg=%s url=%s",
                    self.device_id,
                    ip,
                    stage,
                    message,
                    info["url"],
                )
                print(
                    f"CameraStream error device={self.device_id} ip={ip} stage={stage} msg={message} url={info['url']}",
                    file=sys.stderr,
                    flush=True,
                )
            except Exception:
                # Logging must never crash the stream thread.
                pass

    def has_permanent_failure(self) -> bool:
        with self._lock:
            return self._permanent_failure

    def _ffmpeg_logger(self) -> None:
        parsed = urlparse(self.url)
        ip = parsed.hostname or ""
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
            self.url,
            "-an",
            "-f",
            "null",
            "-",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            # ffmpeg is not available; log once and give up on tagged diagnostics.
            self._set_error("ffmpeg", "ffmpeg executable not found for diagnostics")
            return
        except Exception:
            # Do not crash the stream thread if ffmpeg cannot be started.
            return

        self._ffmpeg_process = proc
        stderr = proc.stderr
        if stderr is None:
            return

        try:
            for line in stderr:
                if not self._running:
                    break
                text = line.rstrip("\r\n")
                if not text:
                    continue
                if "Application provided invalid, non monotonically increasing dts to muxer" in text:
                    continue
                try:
                    print(
                        f"[device={self.device_id} ip={ip}] {text}",
                        file=sys.stderr,
                        flush=True,
                    )
                except Exception:
                    # Printing diagnostics must never crash the logger thread.
                    pass
        finally:
            try:
                proc.terminate()
            except Exception:
                pass

    def run(self) -> None:  # pragma: no cover - realtime streaming
        import cv2

        if self._ffmpeg_thread is None and self._enable_ffmpeg_diag:
            thread = threading.Thread(target=self._ffmpeg_logger, daemon=True)
            self._ffmpeg_thread = thread
            thread.start()

        with self.app.app_context():
            use_gst = getattr(self, "_use_gstreamer", False)
            gst_latency_ms = getattr(self, "_gst_latency_ms", 200)

            def _open_capture():
                if use_gst:
                    pipeline = (
                        f"rtspsrc location={self.url} latency={gst_latency_ms} protocols=tcp ! "
                        "rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! "
                        "appsink sync=false drop=true max-buffers=1"
                    )
                    cap = cv2.VideoCapture(pipeline, cv2.CAP_GSTREAMER)
                    if cap.isOpened():
                        return cap
                    try:
                        self._set_error(
                            "open",
                            "GStreamer pipeline failed to open; falling back to default backend",
                        )
                    except Exception:
                        pass
                    cap.release()
                return cv2.VideoCapture(self.url)

            backoff = 1.0
            capture_fps = float(self.app.config.get("PREVIEW_CAPTURE_FPS", 0.0) or 0.0)
            capture_interval = 1.0 / capture_fps if capture_fps > 0.0 else 0.0
            last_capture = 0.0
            open_failures = 0
            while self._running:
                cap = _open_capture()
                if not cap.isOpened():
                    open_failures += 1
                    if open_failures >= 5:
                        self._set_error(
                            "open",
                            (
                                "RTSP DESCRIBE or connection failed "
                                f"{open_failures} times (giving up)"
                            ),
                            permanent=True,
                        )
                        cap.release()
                        break
                    self._set_error(
                        "open",
                        "RTSP DESCRIBE or connection failed (cap not opened)",
                    )
                    cap.release()
                    time.sleep(min(backoff, 10.0))
                    backoff = min(backoff * 2.0, 10.0)
                    continue

                backoff = 1.0
                open_failures = 0
                try:
                    while self._running:
                        if capture_interval > 0.0:
                            now = time.time()
                            delay = capture_interval - (now - last_capture)
                            if delay > 0:
                                time.sleep(delay)
                            last_capture = time.time()
                        success, frame = cap.read()
                        if not success:
                            self._set_error("decode", "Failed to read frame from RTSP stream")
                            break
                        # Optionally encode a full-resolution JPEG for high-quality
                        # consumers (e.g. the dedicated session view). This can be
                        # CPU intensive, so it is disabled by default and controlled
                        # via SESSION_ENABLE_FULLRES_STREAM.
                        full_jpg_bytes: Optional[bytes] = None
                        if getattr(self, "_enable_fullres", False):
                            try:
                                ok_full, buffer_full = cv2.imencode(".jpg", frame)
                            except Exception:
                                ok_full = False
                            if ok_full:
                                full_jpg_bytes = buffer_full.tobytes()
                        max_width = int(self.app.config.get("PREVIEW_MAX_WIDTH", 0) or 0)
                        max_height = int(self.app.config.get("PREVIEW_MAX_HEIGHT", 0) or 0)
                        if (max_width > 0 or max_height > 0) and frame is not None:
                            h, w = frame.shape[:2]
                            scale_w = (
                                float(max_width) / float(w)
                                if max_width > 0 and w > max_width
                                else 1.0
                            )
                            scale_h = (
                                float(max_height) / float(h)
                                if max_height > 0 and h > max_height
                                else 1.0
                            )
                            scale = min(scale_w, scale_h)
                            if scale < 1.0:
                                new_size = (int(w * scale), int(h * scale))
                                if new_size[0] > 0 and new_size[1] > 0:
                                    frame = cv2.resize(
                                        frame,
                                        new_size,
                                        interpolation=cv2.INTER_AREA,
                                    )
                        ok, buffer = cv2.imencode(".jpg", frame)
                        if not ok:
                            self._set_error("encode", "Failed to encode frame as JPEG")
                            continue
                        jpg_bytes = buffer.tobytes()
                        now_ts = time.time()
                        with self._lock:
                            if full_jpg_bytes is not None:
                                self._last_full_frame = full_jpg_bytes
                                self._last_full_frame_time = now_ts
                            self._last_frame = jpg_bytes
                            self._last_frame_time = now_ts
                        # Also persist the latest preview frame to disk so that
                        # web workers running in separate processes (without a
                        # local CameraStreamManager) can serve previews.
                        if self._preview_dir:
                            try:
                                write_frame(self.app, self.device_id, jpg_bytes, ts=now_ts)
                            except Exception:
                                # Disk preview caching must never break streaming.
                                pass
                finally:
                    cap.release()
                time.sleep(1.0)


class CameraStreamManager:
    def __init__(self, app: Flask) -> None:
        self.app = app
        self._streams: Dict[int, CameraStream] = {}
        self._urls: Dict[int, str] = {}
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._permanent_failures: Dict[int, dict] = {}

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        with self._lock:
            for stream in self._streams.values():
                stream.stop()

    def get_frame(self, device_id: int) -> Optional[bytes]:
        with self._lock:
            stream = self._streams.get(device_id)
        if stream is None:
            return None
        return stream.get_frame()

    def get_full_frame(self, device_id: int) -> Optional[bytes]:
        """Return a full-resolution frame for the given device, if available.

        Falls back to the scaled preview frame to avoid breaking callers when
        full-resolution data has not yet been captured.
        """

        with self._lock:
            stream = self._streams.get(device_id)
        if stream is None:
            return None
        if hasattr(stream, "get_full_frame"):
            full = stream.get_full_frame()
            if full is not None:
                return full
        return stream.get_frame()

    def get_status(self) -> Dict[int, dict]:
        with self._lock:
            status: Dict[int, dict] = {}
            for device_id, stream in self._streams.items():
                status[device_id] = {
                    "url": _mask_url_password(self._urls.get(device_id, "")),
                    "thread_alive": stream.is_alive(),
                    "last_frame_ts": stream.get_last_frame_time(),
                    "last_error_ts": stream.get_last_error_time(),
                    "last_error": stream.get_last_error(),
                    "permanent_failure": getattr(
                        stream,
                        "has_permanent_failure",
                        lambda: False,
                    )(),
                }
        return status

    def run(self) -> None:  # pragma: no cover - background thread
        with self.app.app_context():
            while True:
                try:
                    self._sync_streams()
                except Exception:  # noqa: BLE001
                    time.sleep(5.0)
                time.sleep(10.0)

    def _sync_streams(self) -> None:
        engine = get_record_engine()
        if engine is None:
            return

        with Session(engine) as session_db:
            devices = session_db.query(CameraDevice).all()
            patterns = session_db.query(CameraUrlPattern).all()

        patterns_index = {p.id: p for p in patterns}

        desired: Dict[int, str] = {}
        for device in devices:
            if not getattr(device, "is_active", 1):
                continue
            pattern = None
            if getattr(device, "pattern_id", None):
                pattern = patterns_index.get(device.pattern_id)
            url = build_camera_url(device, pattern)
            if not url:
                continue
            desired[device.id] = url

        with self._lock:
            for device_id, url in desired.items():
                stream = self._streams.get(device_id)
                existing_url = self._urls.get(device_id)
                if (
                    stream is not None
                    and existing_url == url
                    and getattr(stream, "has_permanent_failure", None)
                    and stream.has_permanent_failure()
                ):
                    self._permanent_failures[device_id] = (
                        stream.get_last_error() or {}
                    )
                    continue
                if stream is not None and existing_url != url:
                    stream.stop()
                    new_stream = CameraStream(self.app, device_id, url)
                    new_stream.start()
                    self._streams[device_id] = new_stream
                    self._urls[device_id] = url
                    self._permanent_failures.pop(device_id, None)
                    continue
                if stream is None or not stream.is_alive():
                    new_stream = CameraStream(self.app, device_id, url)
                    new_stream.start()
                    self._streams[device_id] = new_stream
                    self._urls[device_id] = url

            for device_id in list(self._streams.keys()):
                if device_id not in desired:
                    stream = self._streams.pop(device_id)
                    stream.stop()
                    self._urls.pop(device_id, None)


def start_stream_service(app: Flask) -> None:
    manager = CameraStreamManager(app)
    app.extensions["camera_stream_manager"] = manager
    manager.start()


def get_stream_manager(app: Flask) -> Optional[CameraStreamManager]:
    manager = app.extensions.get("camera_stream_manager")
    if isinstance(manager, CameraStreamManager):
        return manager
    return None
