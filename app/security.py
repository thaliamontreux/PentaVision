from __future__ import annotations

from functools import wraps
from typing import Callable, Iterable, Optional, Set

from flask import abort, g, redirect, request, session, url_for
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_user_engine
from .models import Property, Role, User, UserProperty, UserRole


_SESSION_USER_ID_KEY = "user_id"
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
                    # Detach the instance from the session so later attribute access
                    # (e.g. in templates) does not try to refresh against a closed
                    # session, which would raise DetachedInstanceError.
                    db.expunge(user_obj)

    g.current_user = user_obj
    return user_obj


def login_user(user: User) -> None:
    # Clear any existing session state to reduce fixation risk.
    session.clear()
    session[_SESSION_USER_ID_KEY] = int(user.id)


def logout_user() -> None:
    session.pop(_SESSION_USER_ID_KEY, None)
    if hasattr(g, "current_user"):
        g.current_user = None


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

    For now, System Administrators always have access. Other users must have at
    least one UserProperty link for the property. Future implementations can
    refine this using residency status, zones, and role overrides.
    """

    if user is None:
        return False
    if user_has_role(user, "System Administrator"):
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
        if user is None:
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
    @app.before_request
    def _load_current_user() -> None:  # pragma: no cover - request wiring
        get_current_user()

    @app.context_processor
    def _inject_user() -> dict:  # pragma: no cover - template wiring
        return {
            "current_user": get_current_user(),
            "global_csrf_token": ensure_global_csrf_token(),
        }


def seed_system_admin_role_for_email(email: str) -> None:
    """Ensure the given email has the System Administrator role if possible.

    This helper can be called after creating a User to grant them global
    administrative privileges without duplicating role-seeding logic in
    multiple places.
    """

    engine = get_user_engine()
    if engine is None:
        return

    with Session(engine) as db:
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            return

        role = db.scalar(select(Role).where(Role.name == "System Administrator"))
        if role is None:
            role = Role(
                name="System Administrator",
                scope="global",
                description="Full administrative access to the platform",
            )
            db.add(role)
            db.flush()

        existing = (
            db.query(UserRole)
            .filter(UserRole.user_id == user.id, UserRole.role_id == role.id)
            .first()
        )
        if existing is None:
            db.add(UserRole(user_id=user.id, role_id=role.id, property_id=None))

        # Also ensure a Technician role exists so it can be assigned later via UI.
        tech_role = db.scalar(select(Role).where(Role.name == "Technician"))
        if tech_role is None:
            tech_role = Role(
                name="Technician",
                scope="global",
                description=(
                    "Technical role with access to camera configuration and diagnostics "
                    "subject to administrator locks"
                ),
            )
            db.add(tech_role)

        db.commit()
