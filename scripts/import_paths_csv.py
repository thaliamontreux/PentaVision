from __future__ import annotations

import argparse
import csv
import sys
from typing import Dict, Any
from urllib.parse import urlparse

from sqlalchemy import MetaData, Table, create_engine
from sqlalchemy.orm import Session

from app.config import load_config


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Import camera URL patterns from paths.csv, converting rtsp_url to "
            "path-only patterns and optionally replacing existing patterns."
        ),
    )
    parser.add_argument(
        "--csv",
        default="paths.csv",
        help="Path to paths.csv (default: ./paths.csv)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Apply changes to the database. Without this flag the script runs "
            "in dry-run mode and only prints what would change."
        ),
    )
    parser.add_argument(
        "--clear-existing",
        action="store_true",
        help=(
            "When used with --apply, delete all existing rows in "
            "camera_url_patterns before importing."
        ),
    )
    return parser.parse_args()


def _load_record_engine():
    config = load_config()
    url = config.get("RECORD_DB_URL") or ""
    if not url:
        print("RECORD_DB_URL is not configured.", file=sys.stderr)
        raise SystemExit(1)
    try:
        engine = create_engine(url, future=True)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to create engine: {exc}", file=sys.stderr)
        raise SystemExit(1)
    return engine


def _path_only_from_rtsp(rtsp_url: str) -> str:
    """Convert a full rtsp:// URL into a path-only pattern.

    Leaves any {{ }} tokens intact, strips scheme/host/port/userinfo. If the
    value does not look like a full URL, it is treated as a path already.
    """

    value = (rtsp_url or "").strip()
    if not value:
        return value

    # If this looks like a full URL, parse and keep only path + query.
    if "://" in value:
        try:
            parsed = urlparse(value)
        except Exception:  # noqa: BLE001
            # Fall back to treating the whole thing as a path.
            path = value
        else:
            path = parsed.path or ""
            if parsed.query:
                path = f"{path}?{parsed.query}"
    else:
        path = value

    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path.lstrip("/")

    # Collapse accidental duplicate slashes and trim spaces after leading '/'.
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path[1] == " ":
        path = "/" + path[1:].lstrip()

    return path


def _load_csv_rows(csv_path: str) -> Any:
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    return rows


def main() -> int:
    args = _parse_args()
    apply_changes = args.apply
    csv_path = args.csv

    try:
        rows = _load_csv_rows(csv_path)
    except FileNotFoundError:
        print(f"CSV file not found: {csv_path}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to read CSV: {exc}", file=sys.stderr)
        return 1

    if not rows:
        print("No rows found in CSV; nothing to do.")
        return 0

    engine = _load_record_engine()
    metadata = MetaData()
    patterns = Table("camera_url_patterns", metadata, autoload_with=engine)

    colnames = {c.name for c in patterns.columns}

    total = 0
    created = 0

    with Session(engine) as session:
        if apply_changes and args.clear_existing:
            print("Clearing existing camera_url_patterns...")
            session.execute(patterns.delete())

        for row in rows:
            total += 1

            company = (row.get("company") or "").strip()
            model = (row.get("model") or "").strip()
            rtsp_url = (row.get("rtsp_url") or "").strip()

            if not company or not rtsp_url:
                # Skip incomplete rows.
                continue

            path_only = _path_only_from_rtsp(rtsp_url)
            if not path_only:
                continue

            values: Dict[str, Any] = {
                "manufacturer": company,
                "model_or_note": model or None,
                "protocol": "RTSP",
                "rtsp_url_pattern": path_only,
            }

            # We always want auth placeholders from paths.csv patterns.
            if "use_auth" in colnames:
                values["use_auth"] = 1

            # Map extra metadata fields if the columns exist.
            if "source" in colnames:
                values["source"] = "paths.csv"
            if "is_active" in colnames:
                values["is_active"] = 1

            mapping = {
                "device_type": (row.get("type") or "").strip() or None,
                "oui_regex": (row.get("oui_regex") or "").strip() or None,
                "video_encoding": (row.get("video_encoding") or "").strip() or None,
                "default_port": int(row["port"]) if (row.get("port") or "").strip().isdigit() else None,
                "streams_raw": (row.get("streams") or "").strip() or None,
                "channels_raw": (row.get("channels") or "").strip() or None,
                "stream_names_raw": (row.get("stream_names") or "").strip() or None,
                "channel_names_raw": (row.get("channel_names") or "").strip() or None,
                "low_res_stream": (row.get("low_res_stream") or "").strip() or None,
                "high_res_stream": (row.get("high_res_stream") or "").strip() or None,
                "default_username": (row.get("username") or "").strip() or None,
                "default_password": (row.get("password") or "").strip() or None,
                "manual_url": (row.get("user_manual_url") or "").strip() or None,
            }

            for col, val in mapping.items():
                if col in colnames and val is not None and val != "":
                    values[col] = val

            if "digest_auth_supported" in colnames:
                flag_raw = (row.get("is_digest_auth_supported") or "").strip().lower()
                if flag_raw:
                    values["digest_auth_supported"] = 1 if flag_raw in {"1", "true", "yes", "on"} else 0

            if apply_changes:
                session.execute(patterns.insert().values(**values))
                created += 1
            else:
                created += 1
                print(f"[DRY-RUN] would create pattern: {company} | {model} | {path_only}")

        if apply_changes:
            session.commit()
        else:
            print("Dry-run only; no changes were written. Use --apply to modify the DB.")

    print("--- Import summary ---")
    print(f"CSV rows read: {total}")
    print(f"Patterns created: {created}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
