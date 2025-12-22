#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

_HERE = Path(__file__).resolve()
for _candidate in (_HERE.parent, *_HERE.parents):
    try:
        # Standard repo layout: <repo_root>/app/__init__.py
        if (_candidate / "app" / "__init__.py").exists():
            sys.path.insert(0, str(_candidate))
            break
        # Alt layout (common on servers): script is under <repo_root>/app/scripts/
        # and the python package directory is <repo_root>/app/.
        if (
            _candidate.name == "app"
            and (_candidate / "__init__.py").exists()
            and _candidate.parent.exists()
        ):
            sys.path.insert(0, str(_candidate.parent))
            break
    except Exception:
        continue

from app import create_app
from app.db import get_record_engine
from app.models import (
    CameraDevice,
    CameraRecording,
    CameraStoragePolicy,
    CameraStorageScheduleEntry,
    StorageModule,
    StorageModuleWriteStat,
)
from app.recording_service import _get_active_storage_targets, _should_record_now
from app.views import build_camera_url


@dataclass
class CameraDiag:
    device_id: int
    name: str
    is_active: bool
    url_ok: bool
    should_record_now: bool
    schedule_entries_enabled: int
    active_schedule_targets: Optional[list[str]]
    storage_policy_targets: Optional[list[str]]
    last_recording_at: Optional[str]
    last_write_stat_at: Optional[str]
    last_write_stat_ok: Optional[bool]
    last_write_stat_error: Optional[str]
    shm_index_updated_at: Optional[str]
    shm_last_segment_at: Optional[str]
    shm_segments_count: Optional[int]


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _parse_iso_z(s: str) -> Optional[datetime]:
    raw = (s or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _find_latest_ingest_index(camera_dir_key: str) -> Optional[Path]:
    base = Path("/dev/shm") / "pentavision" / "ingest"
    cam_dir = base / f"camera_{camera_dir_key}"
    if not cam_dir.exists() or not cam_dir.is_dir():
        return None

    newest: tuple[float, Path] | None = None
    try:
        for session_dir in cam_dir.glob("session_*"):
            idx = session_dir / "index.json"
            if not idx.exists() or not idx.is_file():
                continue
            try:
                mtime = idx.stat().st_mtime
            except Exception:
                continue
            if newest is None or mtime > newest[0]:
                newest = (mtime, idx)
    except Exception:
        return None

    return newest[1] if newest else None


def _read_ingest_index(idx_path: Path) -> dict[str, Any] | None:
    try:
        raw = idx_path.read_text(encoding="utf-8")
    except Exception:
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _get_dir_key_for_device(device: CameraDevice) -> str:
    raw_key = str(getattr(device, "mac_address", "") or "").strip()
    raw_key = raw_key.lower().replace(":", "").replace("-", "")
    if raw_key:
        return raw_key
    return str(int(getattr(device, "id", 0) or 0))


def _disk_usage_mb(path: str) -> tuple[Optional[int], Optional[int]]:
    try:
        usage = os.statvfs(path)
        total = int(usage.f_frsize * usage.f_blocks)
        free = int(usage.f_frsize * usage.f_bavail)
        return int(total / (1024 * 1024)), int(free / (1024 * 1024))
    except Exception:
        return None, None


def main() -> int:
    parser = argparse.ArgumentParser(description="PentaVision recording diagnostics")
    parser.add_argument(
        "--minutes",
        type=int,
        default=60,
        help="Lookback window for last recording/write stat (default: 60)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of human-readable text",
    )
    args = parser.parse_args()

    app = create_app()
    record_engine = get_record_engine()
    if record_engine is None:
        print("ERROR: record database engine is not configured (RECORD_DB_URL).")
        return 2

    now_utc = datetime.now(timezone.utc)
    lookback = now_utc - timedelta(minutes=max(1, int(args.minutes)))

    shm_total_mb, shm_free_mb = _disk_usage_mb("/dev/shm")

    diags: list[CameraDiag] = []

    with app.app_context():
        with Session(record_engine) as session:
            CameraDevice.__table__.create(bind=record_engine, checkfirst=True)
            CameraStorageScheduleEntry.__table__.create(bind=record_engine, checkfirst=True)
            CameraStoragePolicy.__table__.create(bind=record_engine, checkfirst=True)
            CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
            StorageModule.__table__.create(bind=record_engine, checkfirst=True)
            StorageModuleWriteStat.__table__.create(bind=record_engine, checkfirst=True)

            devices = session.query(CameraDevice).order_by(CameraDevice.id).all()
            modules = session.query(StorageModule).order_by(StorageModule.id).all()

            enabled_modules = [
                {
                    "id": int(m.id),
                    "name": str(getattr(m, "name", "") or ""),
                    "label": str(getattr(m, "label", "") or ""),
                    "provider_type": str(getattr(m, "provider_type", "") or ""),
                    "is_enabled": bool(getattr(m, "is_enabled", 0)),
                }
                for m in modules
            ]

            for d in devices:
                device_id = int(getattr(d, "id", 0) or 0)
                is_active = bool(getattr(d, "is_active", 1))
                name = str(getattr(d, "name", "") or f"#{device_id}")

                url = None
                try:
                    url = build_camera_url(d, None)
                except Exception:
                    url = None
                url_ok = bool(str(url or "").strip())

                try:
                    should_now = bool(_should_record_now(app, device_id))
                except Exception:
                    should_now = False

                try:
                    entries_enabled = (
                        session.query(CameraStorageScheduleEntry)
                        .filter(CameraStorageScheduleEntry.device_id == device_id)
                        .filter(CameraStorageScheduleEntry.is_enabled != 0)
                        .count()
                    )
                except Exception:
                    entries_enabled = 0

                active_targets: Optional[list[str]] = None
                try:
                    targets_set = _get_active_storage_targets(app, device_id)
                    if targets_set is None:
                        active_targets = None
                    else:
                        active_targets = sorted(list(targets_set))
                except Exception:
                    active_targets = None

                policy_targets: Optional[list[str]] = None
                try:
                    pol = (
                        session.query(CameraStoragePolicy)
                        .filter(CameraStoragePolicy.device_id == device_id)
                        .first()
                    )
                    raw = str(getattr(pol, "storage_targets", "") or "").strip() if pol else ""
                    if raw:
                        policy_targets = sorted({t.strip() for t in raw.split(",") if t.strip()})
                except Exception:
                    policy_targets = None

                last_rec = (
                    session.query(CameraRecording)
                    .filter(CameraRecording.device_id == device_id)
                    .filter(CameraRecording.created_at >= lookback)
                    .order_by(desc(CameraRecording.created_at))
                    .first()
                )

                last_stat = (
                    session.query(StorageModuleWriteStat)
                    .filter(StorageModuleWriteStat.device_id == device_id)
                    .filter(StorageModuleWriteStat.created_at >= lookback)
                    .order_by(desc(StorageModuleWriteStat.created_at))
                    .first()
                )

                dir_key = _get_dir_key_for_device(d)
                idx_path = _find_latest_ingest_index(dir_key)
                shm_index_updated_at = None
                shm_last_segment_at = None
                shm_segments_count = None
                if idx_path is not None:
                    idx = _read_ingest_index(idx_path)
                    if idx:
                        shm_index_updated_at = idx.get("updated_at")
                        segs = idx.get("segments")
                        if isinstance(segs, list):
                            shm_segments_count = len(segs)
                            last_ts = None
                            for seg in reversed(segs[-10:]):
                                if not isinstance(seg, dict):
                                    continue
                                ts = _parse_iso_z(str(seg.get("created_at") or ""))
                                if ts is not None:
                                    last_ts = ts
                                    break
                            shm_last_segment_at = _iso(last_ts)

                diags.append(
                    CameraDiag(
                        device_id=device_id,
                        name=name,
                        is_active=is_active,
                        url_ok=url_ok,
                        should_record_now=should_now,
                        schedule_entries_enabled=_safe_int(entries_enabled),
                        active_schedule_targets=active_targets,
                        storage_policy_targets=policy_targets,
                        last_recording_at=_iso(getattr(last_rec, "created_at", None)) if last_rec else None,
                        last_write_stat_at=_iso(getattr(last_stat, "created_at", None)) if last_stat else None,
                        last_write_stat_ok=(bool(getattr(last_stat, "ok", 0)) if last_stat else None),
                        last_write_stat_error=(str(getattr(last_stat, "error", "") or "")[:200] if last_stat else None),
                        shm_index_updated_at=str(shm_index_updated_at or "") or None,
                        shm_last_segment_at=shm_last_segment_at,
                        shm_segments_count=shm_segments_count,
                    )
                )

    if args.json:
        payload = {
            "ts": now_utc.isoformat(),
            "lookback_minutes": int(args.minutes),
            "shm_total_mb": shm_total_mb,
            "shm_free_mb": shm_free_mb,
            "recording_enabled": bool(app.config.get("RECORDING_ENABLED")),
            "ingest_enabled": bool(app.config.get("INGEST_ENABLED")),
            "storage_targets_env": str(app.config.get("STORAGE_TARGETS") or ""),
            "local_storage_path_env": str(app.config.get("LOCAL_STORAGE_PATH") or ""),
            "cameras": [c.__dict__ for c in diags],
        }
        print(json.dumps(payload, indent=2)[:5_000_000])
        return 0

    print("PentaVision Recording Diagnostics")
    print(f"Time (UTC): {now_utc.isoformat()}")
    print(f"Lookback: last {int(args.minutes)} minutes")
    print(
        "Config: "
        f"INGEST_ENABLED={app.config.get('INGEST_ENABLED')} "
        f"RECORDING_ENABLED={app.config.get('RECORDING_ENABLED')} "
        f"SHM_PROCESSING_REQUIRED={app.config.get('SHM_PROCESSING_REQUIRED')} "
        f"USE_SHM_INGEST={app.config.get('USE_SHM_INGEST')}"
    )
    print(f"/dev/shm: total_mb={shm_total_mb} free_mb={shm_free_mb}")
    print()

    # Summary counts
    active = [c for c in diags if c.is_active]
    should = [c for c in active if c.should_record_now]
    writing = [c for c in active if c.last_recording_at or c.last_write_stat_at]
    print(f"Cameras: total={len(diags)} active={len(active)}")
    print(f"Should record now (per schedule): {len(should)}")
    print(f"Has recent recording/write stat within lookback: {len(writing)}")
    print()

    # Detail per camera
    for c in diags:
        status_bits = []
        if not c.is_active:
            status_bits.append("inactive")
        if not c.url_ok:
            status_bits.append("url-missing")
        if c.schedule_entries_enabled and not c.should_record_now:
            status_bits.append("no-active-storage-schedule")
        if c.should_record_now:
            status_bits.append("should-record")
        if c.last_write_stat_at:
            status_bits.append("wrote")
        if c.last_write_stat_ok is False:
            status_bits.append("write-failed")
        if c.last_recording_at:
            status_bits.append("db-recording")
        if c.shm_last_segment_at:
            status_bits.append("shm-segment")

        print(f"[{c.device_id}] {c.name} :: {', '.join(status_bits) if status_bits else 'ok'}")
        print(f"  schedule_entries_enabled={c.schedule_entries_enabled}")
        print(f"  active_schedule_targets={c.active_schedule_targets}")
        print(f"  storage_policy_targets={c.storage_policy_targets}")
        print(f"  should_record_now={c.should_record_now}")
        print(f"  last_db_recording_at={c.last_recording_at}")
        print(
            "  last_write_stat_at="
            f"{c.last_write_stat_at} ok={c.last_write_stat_ok} err={c.last_write_stat_error}"
        )
        print(
            "  shm_index_updated_at="
            f"{c.shm_index_updated_at} shm_last_segment_at={c.shm_last_segment_at} shm_segments_count={c.shm_segments_count}"
        )
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
