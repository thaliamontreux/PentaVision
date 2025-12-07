from __future__ import annotations

from typing import Optional

from flask import Request, has_request_context, request
from sqlalchemy.orm import Session

from .db import get_user_engine
from .models import AuditEvent


def _client_ip() -> Optional[str]:
    if not has_request_context():
        return None
    req: Request = request
    # Simple best-effort: honor common proxy header if present, else remote_addr.
    forwarded = req.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the list
        return forwarded.split(",")[0].strip()
    return req.remote_addr


def log_event(event_type: str, user_id: Optional[int] = None, details: str = "") -> None:
    """Persist a security/audit event to the user database.

    This is best-effort: if the DB is not configured or an error occurs, the
    function will return silently so it never breaks the main request flow.
    """

    engine = get_user_engine()
    if engine is None:
        return

    ip = _client_ip()

    try:
        with Session(engine) as session:
            event = AuditEvent(user_id=user_id, event_type=event_type, ip=ip, details=details)
            session.add(event)
            session.commit()
    except Exception:  # noqa: BLE001
        # Do not raise from logging path.
        return
