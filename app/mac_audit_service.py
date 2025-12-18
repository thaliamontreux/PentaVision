from __future__ import annotations

import threading
import time

from flask import Flask
from sqlalchemy.orm import Session

from .db import get_record_engine
from .logging_utils import log_event
from .mac_utils import detect_mac_for_ip, normalize_mac
from .models import CameraDevice


class MacAuditWorker(threading.Thread):
    def __init__(self, app: Flask, interval_seconds: int = 12 * 60 * 60) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.interval_seconds = max(60, int(interval_seconds))

    def run(self) -> None:
        while True:
            try:
                with self.app.app_context():
                    self._audit_once()
            except Exception:
                pass
            time.sleep(self.interval_seconds)

    def _audit_once(self) -> None:
        engine = get_record_engine()
        if engine is None:
            return

        with Session(engine) as session:
            devices = session.query(CameraDevice).all()
            for device in devices:
                ip = str(getattr(device, "ip_address", "") or "").strip()
                if not ip:
                    continue

                previous = normalize_mac(str(getattr(device, "mac_address", "") or ""))
                detected = normalize_mac(detect_mac_for_ip(ip))
                if not detected:
                    continue

                if previous and detected and previous != detected:
                    log_event(
                        "CAMERA_MAC_CHANGED",
                        details=f"device_id={device.id}, ip={ip}, old_mac={previous}, new_mac={detected}, source=periodic",
                    )
                    device.mac_address = detected
                    session.add(device)
                if (not previous) and detected:
                    device.mac_address = detected
                    session.add(device)
            session.commit()


def start_mac_audit_service(app: Flask) -> None:
    worker = MacAuditWorker(app)
    worker.start()
