from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Optional

from flask import Blueprint, jsonify, request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_user_engine
from .logging_utils import pv_log
from .models import User
from .security import login_user, seed_system_admin_role_for_email


bp = Blueprint("diagnostics", __name__, url_prefix="/api/diagnostics")


def _client_ip() -> str:
    ip = (
        request.headers.get("X-Forwarded-For")
        or request.headers.get("X-Real-IP")
        or request.remote_addr
        or ""
    )
    return str(ip).split(",")[0].strip()


def _ip_is_allowed(*, local_only: bool, allowed_cidrs: str) -> bool:
    ip_text = _client_ip()
    try:
        ip_obj = ip_address(ip_text)
    except ValueError:
        return False

    if local_only:
        return ip_obj.is_loopback

    raw = str(allowed_cidrs or "").strip()
    if not raw:
        return True

    for part in raw.split(","):
        cidr = part.strip()
        if not cidr:
            continue
        try:
            if ip_obj in ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


@bp.post("/session")
def diagnostics_session():
    try:
        from flask import current_app

        enabled = bool(current_app.config.get("DIAGNOSTICS_ENABLED"))
        token_expected = str(
            current_app.config.get("DIAGNOSTICS_TOKEN") or ""
        ).strip()
        email = (
            str(current_app.config.get("DIAGNOSTICS_USER_EMAIL") or "")
            .strip()
            .lower()
        )
        grant_system_admin = bool(
            current_app.config.get("DIAGNOSTICS_GRANT_SYSTEM_ADMIN")
        )
        local_only = bool(current_app.config.get("DIAGNOSTICS_LOCAL_ONLY"))
        allowed_cidrs = str(
            current_app.config.get("DIAGNOSTICS_ALLOWED_CIDRS") or ""
        ).strip()
    except Exception:
        return jsonify({"error": "diagnostics unavailable"}), 500

    if not enabled:
        return jsonify({"error": "diagnostics disabled"}), 404

    if not token_expected or not email:
        return jsonify({"error": "diagnostics not configured"}), 500

    token_provided = str(request.headers.get("X-PV-Diag-Token") or "").strip()
    if not token_provided:
        auth = str(request.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            token_provided = auth.split(" ", 1)[1].strip()

    if token_provided != token_expected:
        try:
            pv_log(
                "security",
                "warn",
                "diagnostics_token_rejected",
                component="diagnostics",
                ip=_client_ip()[:64],
            )
        except Exception:
            pass
        return jsonify({"error": "invalid token"}), 401

    if not _ip_is_allowed(local_only=local_only, allowed_cidrs=allowed_cidrs):
        try:
            pv_log(
                "security",
                "warn",
                "diagnostics_ip_rejected",
                component="diagnostics",
                ip=_client_ip()[:64],
            )
        except Exception:
            pass
        return jsonify({"error": "ip not allowed"}), 403

    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    user: Optional[User] = None
    with Session(engine, expire_on_commit=False) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            return jsonify({"error": "diagnostics user not found"}), 500

        # Detach so it can live past the session.
        session_db.expunge(user)

    if grant_system_admin:
        try:
            seed_system_admin_role_for_email(email)
        except Exception:
            pass

    login_user(user)
    try:
        pv_log(
            "security",
            "info",
            "diagnostics_session_created",
            component="diagnostics",
            ip=_client_ip()[:64],
            user_id=int(user.id),
            email=str(user.email or "")[:256],
        )
    except Exception:
        pass

    return jsonify({"ok": True, "email": user.email}), 200
