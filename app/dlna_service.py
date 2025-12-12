from __future__ import annotations

import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Flask
from sqlalchemy.orm import Session

from .db import get_record_engine
from .models import DlnaSettings
from .net_utils import get_ipv4_interfaces


def _normalize_bool(value: str) -> bool:
    if not value:
        return False
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "on"}


class DlnaManager:
    def __init__(self, app: Flask) -> None:
        self.app = app
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen[str]] = None
        self._current_interface: Optional[str] = None

    def start(self) -> None:
        self._thread.start()

    def run(self) -> None:
        with self.app.app_context():
            while True:
                try:
                    self._sync()
                except Exception:
                    time.sleep(5.0)
                time.sleep(10.0)

    def _sync(self) -> None:
        engine = get_record_engine()
        if engine is None:
            return

        with Session(engine) as session_db:
            DlnaSettings.__table__.create(bind=engine, checkfirst=True)
            settings = (
                session_db.query(DlnaSettings)
                .order_by(DlnaSettings.id)
                .first()
            )
        if settings is None:
            return

        self._check_process(engine)

        enabled = bool(getattr(settings, "enabled", 0))
        interface_name = settings.interface_name or ""

        with self._lock:
            running = self._proc is not None and self._proc.poll() is None
            config_changed = interface_name and interface_name != self._current_interface

            if enabled and (not running or config_changed):
                self._stop_locked()
                self._start_process(engine, settings)
            elif not enabled and running:
                self._stop_locked()

    def _check_process(self, engine) -> None:
        with self._lock:
            proc = self._proc
        if proc is None:
            return
        try:
            code = proc.poll()
        except Exception:
            code = None
        if code is None:
            return

        with self._lock:
            self._proc = None
        if engine is None:
            return
        with Session(engine) as session_db:
            settings = (
                session_db.query(DlnaSettings)
                .order_by(DlnaSettings.id)
                .first()
            )
            if settings is None:
                return
            if code != 0:
                settings.last_error = f"MiniDLNA exited with code {code}"[:512]
            session_db.add(settings)
            session_db.commit()

    def _start_process(self, engine, settings: DlnaSettings) -> None:
        interfaces = get_ipv4_interfaces()
        name = (settings.interface_name or "").strip()
        match = None
        for item in interfaces:
            if item.get("name") == name:
                match = item
                break
        if not match:
            with Session(engine) as session_db:
                row = (
                    session_db.query(DlnaSettings)
                    .order_by(DlnaSettings.id)
                    .first()
                )
                if row is None:
                    return
                row.last_error = "Selected interface is not available or has no IPv4 address"[:512]
                session_db.add(row)
                session_db.commit()
            return

        ip = match.get("ip") or ""
        network = match.get("network") or ""

        instance_path = Path(self.app.instance_path)
        base_dir = instance_path / "dlna"
        db_dir = base_dir / "db"
        log_dir = base_dir / "log"
        media_dir = base_dir / "media"
        for p in (base_dir, db_dir, log_dir, media_dir):
            p.mkdir(parents=True, exist_ok=True)

        friendly = str(self.app.config.get("DLNA_FRIENDLY_NAME", "PentaVision DLNA") or "PentaVision DLNA")
        minidlna_bin = str(self.app.config.get("MINIDLNA_BIN", "minidlnad") or "minidlnad")

        conf_path = base_dir / "minidlna.conf"
        lines = [
            f"media_dir=V,{media_dir}",
            f"db_dir={db_dir}",
            f"log_dir={log_dir}",
            f"friendly_name={friendly}",
            f"network_interface={name}",
            "inotify=yes",
        ]
        conf_text = "\n".join(str(x) for x in lines) + "\n"
        conf_path.write_text(conf_text, encoding="utf-8")

        env = os.environ.copy()
        try:
            proc = subprocess.Popen(
                [minidlna_bin, "-d", "-f", str(conf_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
        except FileNotFoundError as exc:
            with Session(engine) as session_db:
                row = (
                    session_db.query(DlnaSettings)
                    .order_by(DlnaSettings.id)
                    .first()
                )
                if row is None:
                    return
                row.last_error = f"MiniDLNA executable not found: {exc}"[:512]
                session_db.add(row)
                session_db.commit()
            return
        except Exception as exc:
            with Session(engine) as session_db:
                row = (
                    session_db.query(DlnaSettings)
                    .order_by(DlnaSettings.id)
                    .first()
                )
                if row is None:
                    return
                row.last_error = str(exc)[:512]
                session_db.add(row)
                session_db.commit()
            return

        now = datetime.now(timezone.utc)
        with Session(engine) as session_db:
            row = (
                session_db.query(DlnaSettings)
                .order_by(DlnaSettings.id)
                .first()
            )
            if row is None:
                return
            row.bind_address = ip or None
            row.network_cidr = network or None
            row.last_started_at = now
            row.last_error = None
            row.enabled = 1
            row.updated_at = now
            session_db.add(row)
            session_db.commit()

        with self._lock:
            self._proc = proc
            self._current_interface = name

    def _stop_locked(self) -> None:
        proc = self._proc
        self._proc = None
        self._current_interface = None
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


def start_dlna_service(app: Flask) -> None:
    raw = str(app.config.get("DLNA_ENABLED", "0") or "0")
    if not _normalize_bool(raw):
        return
    manager = DlnaManager(app)
    app.extensions["dlna_manager"] = manager
    manager.start()
