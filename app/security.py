from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Dict, Iterable, Optional, Set, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import (
    abort,
    current_app,
    g,
    jsonify,
    redirect,
    request,
    session,
    url_for,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import get_property_engine, get_user_engine
from .logging_utils import evaluate_ip_access_policies
from .models import (
    Permission,
    Property,
    PropertyUser,
    Role,
    RolePermission,
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


def login_property_user(
    user: PropertyUser, property_uid: Optional[str] = None
) -> None:
    session.clear()
    session[_SESSION_PROPERTY_USER_ID_KEY] = int(user.id)
    if property_uid:
        session[_SESSION_PROPERTY_UID_KEY] = str(property_uid or "").strip()


def get_admin_active_property() -> Optional[Property]:
    prop = getattr(g, "admin_active_property", None)
    if prop is not None:
        return prop

    user = get_current_user()
    if user is None:
        g.admin_active_property = None
        return None

    if not (
        user_has_permission(user, "Cust.Properties.*")
        or user_has_permission(user, "Cust.*")
        or user_has_permission(user, "Platform.*")
        or user_has_permission(user, "*")
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


def _permission_candidates(permission_name: str) -> Set[str]:
    raw = str(permission_name or "").strip()
    if not raw:
        return set()

    parts = [p for p in raw.split(".") if p]
    if not parts:
        return set()

    candidates: Set[str] = set()
    candidates.add(".".join(parts))
    if len(parts) == 1:
        candidates.add(parts[0] + ".*")
        candidates.add("*")
        return candidates

    for i in range(len(parts) - 1, 0, -1):
        candidates.add(".".join(parts[:i]) + ".*")
    candidates.add("*")
    return candidates


def _load_user_permissions(
    user: User, property_id: Optional[int]
) -> Tuple[Set[str], Set[str]]:
    allow: Set[str] = set()
    deny: Set[str] = set()

    engine = get_user_engine()
    if engine is None:
        return allow, deny

    with Session(engine) as db:
        q = (
            db.query(Permission.name, RolePermission.effect)
            .join(
                RolePermission,
                RolePermission.permission_id == Permission.id,
            )
            .join(Role, Role.id == RolePermission.role_id)
            .join(UserRole, UserRole.role_id == Role.id)
            .filter(UserRole.user_id == int(user.id))
        )
        if property_id is None:
            q = q.filter(UserRole.property_id.is_(None))
        else:
            q = q.filter(
                (UserRole.property_id.is_(None))
                | (UserRole.property_id == int(property_id))
            )
        rows = q.all()

    for name, effect in rows:
        perm_name = str(name or "").strip()
        eff = str(effect or "").strip().lower()
        if not perm_name:
            continue
        if eff == "deny":
            deny.add(perm_name)
        else:
            allow.add(perm_name)
    return allow, deny


def user_has_permission(
    user: Optional[User],
    permission_name: str,
    property_id: Optional[int] = None,
) -> bool:
    if user is None:
        return False

    cache: Dict[Optional[int], Tuple[Set[str], Set[str]]] = getattr(
        g,
        "current_user_permission_cache",
        None,
    )
    if cache is None:
        cache = {}
        g.current_user_permission_cache = cache

    entry = cache.get(property_id)
    if entry is None:
        entry = _load_user_permissions(user, property_id)
        cache[property_id] = entry
    allow, deny = entry

    candidates = _permission_candidates(permission_name)
    if not candidates:
        return False
    if deny & candidates:
        return False
    return bool(allow & candidates)


def require_permissions(permissions: Iterable[str]) -> Callable:
    perm_set = {
        str(p or "").strip()
        for p in permissions
        if str(p or "").strip()
    }

    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if user is None:
                next_url = request.path or url_for("main.index")
                return redirect(url_for("main.login", next=next_url))
            if not perm_set:
                abort(403)
            for perm in perm_set:
                if user_has_permission(user, perm):
                    return view(*args, **kwargs)
            abort(403)

        return wrapper

    return decorator


def apply_sql_seed_file(engine, file_path: str) -> None:
    path = str(file_path or "").strip()
    if not path:
        return
    if not os.path.isfile(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception:  # noqa: BLE001
        return

    cleaned_lines: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("--"):
            continue
        cleaned_lines.append(line)

    sql_text = "\n".join(cleaned_lines)
    statements = [s.strip() for s in sql_text.split(";") if s.strip()]

    try:
        from sqlalchemy import text  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return

    try:
        with engine.begin() as conn:
            for stmt in statements:
                cleaned = (stmt or "").strip()
                if not cleaned:
                    continue
                try:
                    conn.execute(text(cleaned))
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        return


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

    def _rbac_is_exempt_path(path: str) -> bool:
        p = str(path or "")
        if not p:
            return True
        if p.startswith("/static/"):
            return True
        if p.startswith("/theme-css/"):
            return True
        if p.startswith("/install"):
            locked = str(current_app.config.get("INSTALL_LOCKED", "")).lower()
            if locked != "true":
                return True
        if p.startswith("/api/auth"):
            return True
        if p.startswith("/api/status"):
            return True
        if p.startswith("/api/diagnostics"):
            return True
        if p.startswith("/health"):
            return True
        if p.startswith("/property-login"):
            return True
        if p.startswith("/property-logout"):
            return True
        if p.startswith("/login"):
            return True
        if p.startswith("/logout"):
            return True
        return False

    def _rbac_require(
        any_of: Iterable[str] | None = None,
        all_of: Iterable[str] | None = None,
    ) -> tuple[Set[str], Set[str]]:
        return set(any_of or []), set(all_of or [])

    def _rbac_permissions_for_request() -> tuple[Set[str], Set[str]] | None:
        path = str(getattr(request, "path", "") or "")
        endpoint = str(getattr(request, "endpoint", "") or "")
        blueprint = str(getattr(request, "blueprint", "") or "")

        if not endpoint or _rbac_is_exempt_path(path):
            return None

        # Main system UI
        if blueprint == "main":
            if path == "/":
                return _rbac_require(any_of=["Nav.Overview.View"])
            if path.startswith("/cameras/"):
                return _rbac_require(any_of=["Nav.Feeds.Cameras.View"])
            if path.startswith("/streams/status"):
                return _rbac_require(any_of=["Nav.Overview.View"])
            if path.startswith("/recordings"):
                if path.endswith("/download"):
                    return _rbac_require(
                        any_of=[
                            "Video.Export.Download",
                            "Video.Export.*",
                            "Video.*",
                        ],
                        all_of=["Nav.Recording.Recordings.View"],
                    )
                return _rbac_require(any_of=["Nav.Recording.Recordings.View"])
            if path.startswith("/recording-settings"):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=[
                            "Nav.Recording.Schedule.View",
                            "Recording.Schedule.Manage",
                        ]
                    )
                return _rbac_require(any_of=["Nav.Recording.Schedule.View"])
            if path.startswith("/audit"):
                return _rbac_require(any_of=["Nav.Audit.AuditLog.View"])
            if path.startswith("/profile"):
                return None
            if (
                path.startswith("/faces-demo")
                or path.startswith("/auth-demo")
            ):
                return _rbac_require(any_of=["Video.Live.View", "Video.*"])
            if path.startswith("/api/face/"):
                return _rbac_require(
                    any_of=["Video.Live.TakeSnapshot", "Video.*"]
                )
            if path.startswith("/api/user/"):
                return None
            if path.startswith("/api/status"):
                return None

        # Admin area
        if blueprint == "admin":
            if path in ("/admin", "/admin/"):
                return _rbac_require(any_of=["Nav.Overview.View"])
            if path.startswith("/admin/users"):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=["Nav.IAM.Users.View", "Users.Manage"]
                    )
                return _rbac_require(any_of=["Nav.IAM.Users.View"])
            if path.startswith("/admin/properties"):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=[
                            "Nav.Cust.Properties.View",
                            "Properties.Manage",
                        ]
                    )
                return _rbac_require(any_of=["Nav.Cust.Properties.View"])
            if path.startswith("/admin/access-control"):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=[
                            "Nav.NetSec.BlockAllow.View",
                            "NetSec.BlockAllow.Manage",
                        ]
                    )
                return _rbac_require(any_of=["Nav.NetSec.BlockAllow.View"])
            if path.startswith("/admin/blocklist"):
                if path.startswith("/admin/blocklist-distribution"):
                    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                        return _rbac_require(
                            all_of=[
                                "Nav.NetSec.BlocklistDistribution.View",
                                "NetSec.BlocklistDistribution.Manage",
                            ]
                        )
                    return _rbac_require(
                        any_of=["Nav.NetSec.BlocklistDistribution.View"]
                    )
                if path.startswith("/admin/blocklist-integration"):
                    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                        return _rbac_require(
                            all_of=[
                                "Nav.NetSec.BlocklistIntegration.View",
                                "NetSec.BlocklistIntegration.Manage",
                            ]
                        )
                    return _rbac_require(
                        any_of=["Nav.NetSec.BlocklistIntegration.View"]
                    )
                if path.startswith("/admin/blocklist-audit"):
                    return _rbac_require(
                        any_of=["Nav.Audit.BlocklistAudit.View"]
                    )
                return _rbac_require(any_of=["Nav.NetSec.BlockAllow.View"])
            if path.startswith("/admin/services"):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=["Nav.Services.View", "Services.Manage"]
                    )
                return _rbac_require(any_of=["Nav.Services.View"])
            if path.startswith("/admin/themes"):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=["Nav.Themes.View", "Themes.Manage"]
                    )
                return _rbac_require(any_of=["Nav.Themes.View"])
            if path.startswith("/admin/git-pull"):
                return _rbac_require(
                    all_of=["Nav.Services.View", "Services.Manage"]
                )
            if path.startswith("/admin/storage"):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=[
                            "Nav.Storage.Providers.View",
                            "Storage.Providers.Manage",
                        ]
                    )
                return _rbac_require(any_of=["Nav.Storage.Providers.View"])
            if path.startswith("/admin/audit"):
                return _rbac_require(any_of=["Nav.Audit.AuditLog.View"])
            if path.startswith("/admin/login-failures"):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=[
                            "Nav.Audit.LoginFailures.View",
                            "Audit.LoginFailures.Decrypt",
                        ]
                    )
                return _rbac_require(any_of=["Nav.Audit.LoginFailures.View"])
            return _rbac_require(any_of=["Nav.Overview.View"])

        # Camera admin area
        if blueprint == "camera_admin":
            if path.startswith("/admin/cameras/devices") or path.startswith(
                "/admin/cameras/scan"
            ):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=[
                            "Nav.Feeds.Cameras.View",
                            "Feeds.Cameras.Manage",
                        ]
                    )
                return _rbac_require(any_of=["Nav.Feeds.Cameras.View"])
            if path.startswith("/admin/cameras/rtmp"):
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return _rbac_require(
                        all_of=[
                            "Nav.Feeds.RtmpOutputs.View",
                            "Feeds.RtmpOutputs.Manage",
                        ]
                    )
                return _rbac_require(any_of=["Nav.Feeds.RtmpOutputs.View"])
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                return _rbac_require(
                    all_of=[
                        "Nav.Feeds.CameraUrlTemplates.View",
                        "Feeds.CameraUrlTemplates.Manage",
                    ]
                )
            return _rbac_require(any_of=["Nav.Feeds.CameraUrlTemplates.View"])

        # Property manager portal
        if blueprint == "pm":
            return _rbac_require(any_of=["Nav.Cust.Properties.View"])

        if blueprint == "installer":
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                return _rbac_require(
                    all_of=[
                        "Nav.Installer.Databases.View",
                        "Installer.Databases.Manage",
                    ]
                )
            return _rbac_require(any_of=["Nav.Installer.Databases.View"])

        return _rbac_require(any_of=["*"])

    @app.before_request
    def _enforce_enterprise_rbac():
        if request.method == "OPTIONS":
            return None

        path = str(getattr(request, "path", "") or "")
        if _rbac_is_exempt_path(path):
            return None

        # Property-user sessions are not governed by main-system staff RBAC.
        prop_user = get_current_property_user()
        if prop_user is not None and get_current_user() is None:
            return None

        user = get_current_user()
        if user is None:
            endpoint = str(getattr(request, "endpoint", "") or "")
            if not endpoint:
                return None

            accept_json = (
                request.accept_mimetypes["application/json"]
                >= request.accept_mimetypes["text/html"]
            )
            if path.startswith("/api/") or accept_json:
                return jsonify({"error": "authentication required"}), 401

            next_url = path or url_for("main.index")
            if not str(next_url).startswith("/"):
                next_url = url_for("main.index")
            return redirect(url_for("main.login", next=next_url))

        reqd = _rbac_permissions_for_request()
        if not reqd:
            return None

        any_of, all_of = reqd

        # System Administrator has full access.
        if user_has_permission(user, "*"):
            return None

        for perm in all_of:
            if not user_has_permission(user, perm):
                abort(403)

        if not any_of:
            return None

        for perm in any_of:
            if user_has_permission(user, perm):
                return None

        abort(403)

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

        def has_permission(permission_name: str) -> bool:
            return user_has_permission(global_user, permission_name)

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
            "has_permission": has_permission,
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
