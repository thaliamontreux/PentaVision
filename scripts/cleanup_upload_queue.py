#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

_HERE = Path(__file__).resolve()
for _candidate in (_HERE.parent, *_HERE.parents):
    try:
        if (_candidate / "app" / "__init__.py").exists():
            sys.path.insert(0, str(_candidate))
            break
        if (
            _candidate.name == "app"
            and (_candidate / "__init__.py").exists()
            and _candidate.parent.exists()
        ):
            sys.path.insert(0, str(_candidate.parent))
            break
    except Exception:
        continue

from app import create_app  # noqa: E402
from app.db import get_record_engine  # noqa: E402
from app.models import UploadQueueItem  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Purge old rows from the RecordDB upload_queue table"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Retention in days (delete rows older than this). Default: 7.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Rows per delete batch. Default: 500.",
    )
    parser.add_argument(
        "--max-batches",
        type=int,
        default=200,
        help="Maximum batches to run per execution. Default: 200.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually delete rows (otherwise dry-run).",
    )
    args = parser.parse_args()

    days = int(args.days)
    if days < 0:
        print("ERROR: --days must be >= 0")
        return 2

    app = create_app()
    with app.app_context():
        engine = get_record_engine()

    if engine is None:
        print("ERROR: record database engine is not configured (RECORD_DB_URL).")
        return 2

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Ensure table exists (safe no-op if it already does)
    with Session(engine) as session:
        UploadQueueItem.__table__.create(bind=engine, checkfirst=True)

        try:
            db_name = engine.url.database
        except Exception:
            db_name = None

        print("RecordDB database:", db_name or "(unknown)")
        print("Cutoff UTC:", cutoff.isoformat())
        print("Mode:", "EXECUTE" if args.execute else "DRY-RUN")

        # Stats before
        total_rows = (
            session.execute(select(func.count()).select_from(UploadQueueItem)).scalar()
            or 0
        )
        old_rows = (
            session.execute(
                select(func.count())
                .select_from(UploadQueueItem)
                .where(UploadQueueItem.created_at < cutoff)
            ).scalar()
            or 0
        )

        # Not all DBs support octet_length; try a best-effort estimate.
        old_bytes = None
        try:
            old_bytes = session.execute(
                select(func.coalesce(func.sum(func.length(UploadQueueItem.payload)), 0)).where(
                    UploadQueueItem.created_at < cutoff
                )
            ).scalar()
        except Exception:
            old_bytes = None

        print(f"Total rows: {int(total_rows)}")
        if old_bytes is None:
            print(f"Rows older than cutoff: {int(old_rows)}")
        else:
            mb = float(int(old_bytes)) / (1024.0 * 1024.0)
            print(f"Rows older than cutoff: {int(old_rows)} (~{mb:.1f} MiB payload)")

        if not args.execute:
            return 0

        deleted_total = 0
        for _ in range(int(args.max_batches)):
            ids = (
                session.query(UploadQueueItem.id)
                .filter(UploadQueueItem.created_at < cutoff)
                .order_by(UploadQueueItem.id)
                .limit(int(args.batch_size))
                .all()
            )
            if not ids:
                break

            id_list = [int(r[0]) for r in ids]
            session.execute(
                delete(UploadQueueItem).where(UploadQueueItem.id.in_(id_list))
            )
            session.commit()
            deleted_total += len(id_list)

        print(f"Deleted rows: {deleted_total}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
