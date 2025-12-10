from __future__ import annotations

import argparse
import sys
from typing import List, Tuple
from urllib.parse import urlparse, urlunparse

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.config import load_config
from app.models import CameraUrlPattern


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Split and normalize camera URL patterns that contain multiple URLs "
            "separated by ';' and fix leading '//' or spaces in paths."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Apply changes to the database. Without this flag the script runs "
            "in dry-run mode and only prints what would change."
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


def _normalize_path(path: str) -> str:
    """Normalize a URL path or a path-only pattern.

    - Trim whitespace.
    - Ensure the path starts with a single '/'.
    - Collapse any duplicate slashes '//' inside the path to a single '/'.
    - Remove spaces immediately after the leading '/'.
    """

    if not path:
        return path

    path = path.strip()

    # Ensure a single leading '/'.
    if not path.startswith("/"):
        path = "/" + path

    # Collapse duplicate slashes in the path portion.
    # This may need to run more than once if there are "///" sequences.
    while "//" in path:
        path = path.replace("//", "/")

    # Remove any spaces immediately after the first '/': '/ foo' -> '/foo'.
    if len(path) > 1 and path[1] == " ":
        rest = path[1:].lstrip()
        path = "/" + rest

    return path


def _normalize_segment(segment: str) -> str:
    """Normalize a single URL segment (full URL or path-only)."""

    text = (segment or "").strip()
    if not text:
        return text

    # If this looks like a full URL, normalize only the path component.
    if "://" in text:
        try:
            parsed = urlparse(text)
        except Exception:  # noqa: BLE001
            # Fall back to treating the whole string as a path-only pattern.
            return _normalize_path(text)

        if parsed.scheme and parsed.netloc:
            new_path = _normalize_path(parsed.path or "")
            return urlunparse(parsed._replace(path=new_path))

    # Otherwise treat as a path-only pattern.
    return _normalize_path(text)


def _split_and_normalize_pattern(
    pattern_text: str,
) -> Tuple[List[str], bool]:
    """Return a list of normalized pattern strings and a flag indicating split.

    If the input contains ';', it will be split into multiple segments. Each
    segment is normalized (paths cleaned, duplicate slashes removed, etc.).
    If there is no ';', this returns a single-element list containing the
    normalized pattern.
    """

    text = (pattern_text or "").strip()
    if not text:
        return [], False

    if ";" in text:
        raw_parts = [part.strip() for part in text.split(";")]
        parts = [p for p in raw_parts if p]
        normalized = [_normalize_segment(p) for p in parts]
        return normalized, True

    normalized_single = _normalize_segment(text)
    return [normalized_single], False


def main() -> int:
    args = _parse_args()
    apply_changes = args.apply

    engine = _load_record_engine()

    total_patterns = 0
    split_rows = 0
    updated_rows = 0
    created_rows = 0
    deleted_rows = 0

    with Session(engine) as session:
        stmt = select(CameraUrlPattern).order_by(CameraUrlPattern.id)
        patterns = list(session.execute(stmt).scalars())

        for pattern in patterns:
            total_patterns += 1
            original = pattern.rtsp_url_pattern or ""

            new_patterns, did_split = _split_and_normalize_pattern(original)
            if not new_patterns:
                continue

            # No changes at all.
            if (not did_split) and len(new_patterns) == 1 and new_patterns[0] == original:
                continue

            manufacturer = pattern.manufacturer
            base_model = (pattern.model_or_note or "").strip() or "Variant"

            if did_split and len(new_patterns) > 1:
                split_rows += 1
                print(
                    f"[SPLIT] id={pattern.id} manufacturer='{manufacturer}' "
                    f"model='{pattern.model_or_note}' -> {len(new_patterns)} entries",
                )

                if apply_changes:
                    for idx, p_text in enumerate(new_patterns, start=1):
                        model = f"{base_model} {idx}"
                        new_obj = CameraUrlPattern(
                            manufacturer=manufacturer,
                            model_or_note=model,
                            protocol=pattern.protocol,
                            rtsp_url_pattern=p_text,
                            use_auth=pattern.use_auth,
                            source=pattern.source,
                            is_active=pattern.is_active,
                        )
                        session.add(new_obj)
                    session.delete(pattern)
                    created_rows += len(new_patterns)
                    deleted_rows += 1
                else:
                    for idx, p_text in enumerate(new_patterns, start=1):
                        model = f"{base_model} {idx}"
                        print(
                            f"  would create: manufacturer='{manufacturer}', "
                            f"model='{model}', pattern='{p_text}'",
                        )
                    print(f"  would delete original id={pattern.id} pattern='{original}'")
            else:
                # Single normalized pattern, but different from the original.
                new_text = new_patterns[0]
                if new_text == original:
                    continue

                updated_rows += 1
                print(
                    f"[NORMALIZE] id={pattern.id} manufacturer='{manufacturer}' "
                    f"model='{pattern.model_or_note}'",
                )
                print(f"  '{original}' -> '{new_text}'")

                if apply_changes:
                    pattern.rtsp_url_pattern = new_text
                    session.add(pattern)

        if apply_changes:
            session.commit()
        else:
            print("Dry-run only; no changes were written. Use --apply to modify the DB.")

    print("--- Summary ---")
    print(f"Total patterns scanned: {total_patterns}")
    print(f"Rows split into multiple patterns: {split_rows}")
    print(f"Rows normalized in-place: {updated_rows}")
    print(f"New patterns created: {created_rows}")
    print(f"Original multi-URL rows deleted: {deleted_rows}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
