from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Iterable, Optional, Set
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import abort, g, jsonify, redirect, request, session, url_for
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import get_property_engine, get_user_engine
from .logging_utils import evaluate_ip_access_policies
from .models import (
    Property,
    PropertyUser,
    Role,
    SiteThemeSettings,
    User,
    UserProperty,
    UserRole,
)


_SESSION_USER_ID_KEY = "user_id"
_SESSION_PROPERTY_USER_ID_KEY = "property_user_id"
_SESSION_PROPERTY_UID_KEY = "property_uid"
_SESSION_ADMIN_PROPERTY_UID_KEY = "admin_property_uid"
_GLOBAL_CSRF_KEY = "global_csrf"


def get_current_user() -> Optional[User]:
    user = getattr(g, "current_user", None)
    if user is not None:
        return user

    user_id = session.get(_SESSION_USER_ID_KEY)
    user_obj: Optional[User] = None
    engine = get_user_engine()
    if user_id is not None and engine is not None:
        try:
            uid = int(user_id)
        except (TypeError, ValueError):
            uid = None
        if uid is not None:
            with Session(engine) as db:
                user_obj = db.get(User, uid)
                if user_obj is not None:
                    # Detach the instance from the session so later attribute
                    # access (e.g. in templates) does not try to refresh
                    # against a closed session, which would raise
                    # DetachedInstanceError.
                    db.expunge(user_obj)

    g.current_user = user_obj
    return user_obj


def get_current_property_user() -> Optional[PropertyUser]:
    user = getattr(g, "current_property_user", None)
    if user is not None:
        return user

    user_id = session.get(_SESSION_PROPERTY_USER_ID_KEY)
    prop_uid = session.get(_SESSION_PROPERTY_UID_KEY)
    user_obj: Optional[PropertyUser] = None

    if user_id is not None:
        if prop_uid:
            tenant_engine = get_property_engine(str(prop_uid))
            if tenant_engine is not None:
                with Session(tenant_engine) as db:
                    try:
                        PropertyUser.__table__.create(
                            bind=tenant_engine,
                            checkfirst=True,
                        )
                    except Exception:  # noqa: BLE001
                        pass
                    user_obj = db.get(PropertyUser, int(user_id))
                    if user_obj is not None:
                        db.expunge(user_obj)
        else:
            # Backwards-compatible fallback for older sessions.
            engine = get_user_engine()
            if engine is not None:
                with Session(engine) as db:
                    try:
                        PropertyUser.__table__.create(
                            bind=engine,
                            checkfirst=True,
                        )
                    except Exception:  # noqa: BLE001
                        pass
                    user_obj = db.get(PropertyUser, int(user_id))
                    if user_obj is not None:
                        db.expunge(user_obj)
    g.current_property_user = user_obj
    return user_obj


def login_user(user: User) -> None:
    # Clear any existing session state to reduce fixation risk.
    session.clear()
    session[_SESSION_USER_ID_KEY] = int(user.id)


def login_property_user(user: PropertyUser, property_uid: Optional[str] = None) -> None:
    session.clear()
    session[_SESSION_PROPERTY_USER_ID_KEY] = int(user.id)
    if property_uid:
        session[_SESSION_PROPERTY_UID_KEY] = str(property_uid or "").strip()


def get_admin_active_property() -> Optional[Property]:
    prop = getattr(g, "admin_active_property", None)
    if prop is not None:
        return prop

    user = get_current_user()
    if not (
        user_has_role(user, "System Administrator")
        or user_has_role(user, "Property Administrator")
    ):
        g.admin_active_property = None
        return None

    uid = session.get(_SESSION_ADMIN_PROPERTY_UID_KEY)
    uid_norm = str(uid or "").strip().lower()
    if not uid_norm:
        g.admin_active_property = None
        return None

    if re.fullmatch(r"[a-f0-9]{32}", uid_norm) is None:
        session.pop(_SESSION_ADMIN_PROPERTY_UID_KEY, None)
        g.admin_active_property = None
        return None

    engine = get_user_engine()
    if engine is None:
        g.admin_active_property = None
        return None

    prop_obj: Optional[Property] = None
    with Session(engine) as db:
        prop_obj = (
            db.query(Property)
            .filter(Property.uid == uid_norm)
            .first()
        )
        if prop_obj is not None:
            db.expunge(prop_obj)
    if prop_obj is None:
        session.pop(_SESSION_ADMIN_PROPERTY_UID_KEY, None)
    g.admin_active_property = prop_obj
    return prop_obj


def set_property_uid_for_session(property_uid: str) -> None:
    session[_SESSION_PROPERTY_UID_KEY] = str(property_uid or "").strip()


def set_admin_property_uid_for_session(property_uid: str) -> None:
    session[_SESSION_ADMIN_PROPERTY_UID_KEY] = str(property_uid or "").strip()


def clear_admin_property_uid_for_session() -> None:
    session.pop(_SESSION_ADMIN_PROPERTY_UID_KEY, None)


def logout_user() -> None:
    session.pop(_SESSION_USER_ID_KEY, None)
    session.pop(_SESSION_ADMIN_PROPERTY_UID_KEY, None)
    if hasattr(g, "current_user"):
        g.current_user = None


def logout_property_user() -> None:
    session.pop(_SESSION_PROPERTY_USER_ID_KEY, None)
    session.pop(_SESSION_PROPERTY_UID_KEY, None)
    if hasattr(g, "current_property_user"):
        g.current_property_user = None


def ensure_global_csrf_token() -> str:
    token = session.get(_GLOBAL_CSRF_KEY)
    if not token:
        import secrets

        token = secrets.token_urlsafe(32)
        session[_GLOBAL_CSRF_KEY] = token
    return token


def validate_global_csrf_token(token: Optional[str]) -> bool:
    if not token:
        return False
    return token == session.get(_GLOBAL_CSRF_KEY)


def _load_user_roles(user: User) -> Set[str]:
    roles: Set[str] = set()
    engine = get_user_engine()
    if engine is None:
        return roles
    with Session(engine) as db:
        rows = (
            db.query(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .filter(UserRole.user_id == user.id)
            .all()
        )
        roles = {name for (name,) in rows}
    return roles


def user_has_role(user: Optional[User], role_name: str) -> bool:
    if user is None:
        return False
    roles = getattr(g, "current_user_roles", None)
    if roles is None:
        roles = _load_user_roles(user)
        g.current_user_roles = roles
    return role_name in roles


def get_user_property_link(
    user: Optional[User], property_id: int
) -> Optional[UserProperty]:
    if user is None:
        return None
    engine = get_user_engine()
    if engine is None:
        return None
    with Session(engine) as db:
        return (
            db.query(UserProperty)
            .filter(
                UserProperty.user_id == user.id,
                UserProperty.property_id == property_id,
            )
            .first()
        )


def user_has_property_access(user: Optional[User], property_id: int) -> bool:
    """Return True if the user should have access to the given property.

    For now, System Administrators always have access. Other users must have
    at least one UserProperty link for the property. Future implementations
    can
    refine this using residency status, zones, and role overrides.
    """

    if user is None:
        return False
    if user_has_role(user, "System Administrator"):
        return True
    if user_has_role(user, "Property Administrator"):
        return True

    engine = get_user_engine()
    if engine is None:
        return False
    with Session(engine) as db:
        exists = (
            db.query(UserProperty.id)
            .filter(
                UserProperty.user_id == user.id,
                UserProperty.property_id == property_id,
            )
            .first()
        )
        return exists is not None


def require_login(view: Callable) -> Callable:
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        prop_user = get_current_property_user()
        if user is None and prop_user is None:
            next_url = request.path or url_for("main.index")
            return redirect(url_for("main.login", next=next_url))
        return view(*args, **kwargs)

    return wrapper


def require_roles(roles: Iterable[str]) -> Callable:
    role_set = set(roles)

    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if user is None:
                next_url = request.path or url_for("main.index")
                return redirect(url_for("main.login", next=next_url))
            current_roles = getattr(g, "current_user_roles", None)
            if current_roles is None:
                current_roles = _load_user_roles(user)
                g.current_user_roles = current_roles
            if not (current_roles & role_set):
                abort(403)
            return view(*args, **kwargs)

        return wrapper

    return decorator


def init_security(app) -> None:
    def _normalize_timezone_name(value: Optional[str]) -> str:
        raw = str(value or "").strip()
        if not raw:
            return "UTC"
        try:
            ZoneInfo(raw)
        except (ZoneInfoNotFoundError, ValueError):
            return "UTC"
        return raw

    def _current_timezone_name() -> str:
        user = get_current_user()
        return _normalize_timezone_name(
            getattr(user, "timezone", None) if user else None
        )

    def local_dt(value, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        if value is None:
            return ""
        tz_name = _current_timezone_name()
        try:
            tz = ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            tz = timezone.utc

        if isinstance(value, datetime):
            dt = value
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(tz).strftime(fmt)
        if hasattr(value, "strftime"):
            return value.strftime(fmt)
        return str(value)

    @app.before_request
    def _enforce_ip_access_policies():
        allowed, _reason = evaluate_ip_access_policies()
        if not allowed:
            accept_json = (
                request.accept_mimetypes["application/json"]
                >= request.accept_mimetypes["text/html"]
            )
            if (
                request.path.startswith("/auth/")
                or request.path.startswith("/api/")
                or accept_json
            ):
                return (
                    jsonify(
                        {
                            "error": (
                                "access from this IP or country is blocked"
                            )
                        }
                    ),
                    403,
                )
            return "Access from this IP or country is blocked.", 403

    @app.before_request
    def _load_current_user() -> None:  # pragma: no cover - request wiring
        get_current_user()
        get_current_property_user()

    @app.context_processor
    def _inject_user() -> dict:  # pragma: no cover - template wiring
        def _sanitize_theme(value: str | None) -> str:
            raw = str(value or "").strip()
            if not raw:
                return "default"
            if raw == "default":
                return "default"
            if (
                re.fullmatch(r"[a-z0-9_\-]{1,64}", raw)
                is None
            ):
                return "default"
            return raw

        def _load_theme_settings() -> tuple[str, str]:
            engine = get_user_engine()
            if engine is None:
                return "default", "default"
            with Session(engine) as db:
                try:
                    SiteThemeSettings.__table__.create(
                        bind=engine,
                        checkfirst=True,
                    )
                except Exception:  # noqa: BLE001
                    return "default", "default"

                row = (
                    db.query(SiteThemeSettings)
                    .order_by(SiteThemeSettings.id.desc())
                    .first()
                )
                if row is None:
                    row = SiteThemeSettings(
                        main_theme="default",
                        admin_theme="restricted_red",
                    )
                    db.add(row)
                    db.commit()
                main_theme = _sanitize_theme(
                    getattr(row, "main_theme", None)
                )
                admin_theme = _sanitize_theme(
                    getattr(row, "admin_theme", None)
                )
                return main_theme, admin_theme

        user = get_current_user() or get_current_property_user()
        global_user = get_current_user()
        active_admin_property = get_admin_active_property()
        main_theme, admin_theme = _load_theme_settings()

        is_property_manager = False
        if global_user is not None:
            if (
                user_has_role(global_user, "System Administrator")
                or user_has_role(global_user, "Property Administrator")
            ):
                is_property_manager = True
            else:
                engine = get_user_engine()
                if engine is not None:
                    with Session(engine) as db:
                        exists = (
                            db.query(UserProperty.id)
                            .filter(
                                UserProperty.user_id
                                == int(global_user.id),
                            )
                            .first()
                        )
                        is_property_manager = exists is not None
        return {
            "current_user": user,
            "global_csrf_token": ensure_global_csrf_token(),
            "is_system_admin": user_has_role(
                global_user,
                "System Administrator",
            ),
            "is_property_admin": user_has_role(
                global_user,
                "Property Administrator",
            ),
            "is_technician": user_has_role(global_user, "Technician"),
            "is_property_manager": is_property_manager,
            "active_admin_property": active_admin_property,
            "current_timezone": _current_timezone_name(),
            "active_main_theme": main_theme,
            "active_admin_theme": admin_theme,
        }

    app.jinja_env.filters["local_dt"] = local_dt


def seed_system_admin_role_for_email(email: str) -> None:
    """Ensure the given email has the System Administrator role if possible.

    This helper can be called after creating a User to grant them global
    administrative privileges without duplicating role-seeding logic in
    multiple places.
    """

    email_norm = str(email or "").strip().lower()
    if not email_norm:
        return

    engine = get_user_engine()
    if engine is None:
        return

    with Session(engine) as db:
        user = db.scalar(
            select(User).where(func.lower(User.email) == email_norm)
        )
        if user is None:
            return

        role = db.scalar(
            select(Role).where(Role.name == "System Administrator")
        )
        if role is None:
            role = Role(
                name="System Administrator",
                scope="global",
                description=(
                    "Full administrative access to the platform"
                ),
            )
            db.add(role)
            db.flush()

        existing = (
            db.query(
                UserRole,
            )
            .filter(
                UserRole.user_id == user.id,
                UserRole.role_id == role.id,
            )
            .first()
        )
        if existing is None:
            db.add(
                UserRole(
                    user_id=user.id,
                    role_id=role.id,
                    property_id=None,
                )
            )

        # Also ensure a Technician role exists so it can be assigned later via
        # UI.
        tech_role = db.scalar(
            select(Role).where(Role.name == "Technician")
        )
        if tech_role is None:
            tech_role = Role(
                name="Technician",
                scope="global",
                description=(
                    "Technical role with access to camera configuration and "
                    "diagnostics subject to administrator locks"
                ),
            )
            db.add(tech_role)

        prop_admin_role = db.scalar(
            select(Role).where(Role.name == "Property Administrator")
        )
        if prop_admin_role is None:
            prop_admin_role = Role(
                name="Property Administrator",
                scope="global",
                description=(
                    "Administrative role for managing assigned properties"
                ),
            )
            db.add(prop_admin_role)

        db.commit()
