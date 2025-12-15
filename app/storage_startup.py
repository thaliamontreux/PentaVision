from __future__ import annotations

import io
import threading
import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .db import get_record_engine
from .models import StorageModule, StorageModuleEvent, StorageModuleWriteStat
from .storage_csal import get_storage_router


def _record_write_stat(
    module_id: int | None,
    module_name: str,
    ok: bool,
    bytes_written: int | None,
    storage_key: str | None,
    error: str | None,
) -> None:
    engine = get_record_engine()
    if engine is None:
        return

    StorageModuleWriteStat.__table__.create(bind=engine, checkfirst=True)
    StorageModuleEvent.__table__.create(bind=engine, checkfirst=True)

    with Session(engine) as session:
        try:
            session.add(
                StorageModuleWriteStat(
                    module_id=int(module_id) if module_id is not None else None,
                    module_name=str(module_name or "")[:160],
                    device_id=None,
                    storage_key=str(storage_key or "")[:512] if storage_key else None,
                    bytes_written=int(bytes_written) if bytes_written is not None else None,
                    ok=1 if ok else 0,
                    error=str(error)[:512] if error else None,
                )
            )
            if not ok and error:
                session.add(
                    StorageModuleEvent(
                        module_id=int(module_id) if module_id is not None else None,
                        module_name=str(module_name or "")[:160],
                        level="error",
                        event_type="startup_test_write",
                        message=str(error)[:1024],
                        stream_id=None,
                    )
                )
            session.commit()
        except Exception:  # noqa: BLE001
            return


def run_startup_storage_test_write(app) -> None:
    engine = get_record_engine()
    if engine is None:
        return

    StorageModule.__table__.create(bind=engine, checkfirst=True)

    with Session(engine) as session:
        modules = (
            session.query(StorageModule)
            .filter(StorageModule.is_enabled == 1)
            .order_by(getattr(StorageModule, "priority", StorageModule.id), StorageModule.id)
            .all()
        )

    router = get_storage_router(app)
    payload = (
        "pentastar-startup-test "
        + datetime.now(timezone.utc).isoformat()
        + "\n"
    ).encode("utf-8")

    for m in modules:
        module_id = int(getattr(m, "id", 0) or 0)
        module_name = str(getattr(m, "name", "") or "")
        if not module_name:
            continue

        instance_key = str(module_id)
        storage_key = None
        try:
            stream = io.BytesIO(payload)
            result = router.write(instance_key, stream, {"key_hint": "startup_test"})
            storage_key = str(result.get("object_id") or "")
            _record_write_stat(
                module_id=module_id,
                module_name=module_name,
                ok=True,
                bytes_written=len(payload),
                storage_key=storage_key or None,
                error=None,
            )
        except Exception as exc:  # noqa: BLE001
            _record_write_stat(
                module_id=module_id,
                module_name=module_name,
                ok=False,
                bytes_written=len(payload),
                storage_key=storage_key,
                error=str(exc),
            )


def start_storage_startup_checks(app) -> None:
    def _runner() -> None:
        try:
            time.sleep(1.0)
            with app.app_context():
                run_startup_storage_test_write(app)
        except Exception:  # noqa: BLE001
            return

    t = threading.Thread(target=_runner, name="pv-storage-startup", daemon=True)
    t.start()
