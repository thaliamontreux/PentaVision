from __future__ import annotations

from datetime import datetime, timezone
import re

from argon2 import PasswordHasher
from flask import Blueprint, abort, redirect, render_template, request, url_for
from sqlalchemy.orm import Session

from .db import get_property_engine, get_user_engine
from .logging_utils import log_event
from .models import Property, PropertyUser, UserProperty
from .security import (
    get_current_user,
    user_has_role,
    validate_global_csrf_token,
)


bp = Blueprint("pm", __name__, url_prefix="/pm")
_ph = PasswordHasher()


def _require_global_user():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))
    return None


def _user_can_manage_property(user, property_id: int) -> bool:
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
                UserProperty.user_id == int(user.id),
                UserProperty.property_id == int(property_id),
            )
            .first()
        )
        return exists is not None


@bp.before_request
def _pm_require_login():
    return _require_global_user()


@bp.get("/")
def index():
    user = get_current_user()
    engine = get_user_engine()
    props: list[Property] = []

    if engine is not None:
        with Session(engine) as db:
            try:
                Property.__table__.create(bind=engine, checkfirst=True)
                UserProperty.__table__.create(bind=engine, checkfirst=True)
            except Exception:  # noqa: BLE001
                pass

            if user_has_role(user, "System Administrator"):
                props = db.query(Property).order_by(Property.name).all()
            else:
                prop_ids = [
                    int(pid)
                    for (pid,) in db.query(UserProperty.property_id)
                    .filter(UserProperty.user_id == int(user.id))
                    .all()
                ]
                if prop_ids:
                    props = (
                        db.query(Property)
                        .filter(Property.id.in_(prop_ids))
                        .order_by(Property.name)
                        .all()
                    )

    return render_template("pm/index.html", properties=props)


@bp.get("/properties/<int:property_id>/users")
def property_users(property_id: int):
    user = get_current_user()
    if not _user_can_manage_property(user, property_id):
        abort(403)

    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        if prop is None or not getattr(prop, "uid", None):
            abort(404)
        prop_uid = str(prop.uid)
        db.expunge(prop)

    tenant_engine = get_property_engine(prop_uid)
    if tenant_engine is None:
        abort(500)

    with Session(tenant_engine) as db:
        PropertyUser.__table__.create(
            bind=tenant_engine,
            checkfirst=True,
        )

        rows = (
            db.query(PropertyUser)
            .filter(PropertyUser.property_id == int(property_id))
            .order_by(PropertyUser.username)
            .all()
        )

    return render_template(
        "pm/property_users.html",
        prop=prop,
        rows=rows,
    )


@bp.post("/properties/<int:property_id>/users/create")
def property_users_create(property_id: int):
    user = get_current_user()
    if not _user_can_manage_property(user, property_id):
        abort(403)

    if not validate_global_csrf_token(request.form.get("csrf_token")):
        abort(400)

    username = str(request.form.get("username") or "").strip().lower()
    full_name = str(request.form.get("full_name") or "").strip() or None
    password = str(request.form.get("password") or "")
    pin = str(request.form.get("pin") or "").strip()

    if not username:
        return redirect(url_for("pm.property_users", property_id=property_id))
    if not password:
        return redirect(url_for("pm.property_users", property_id=property_id))

    if pin and re.fullmatch(r"\d{8}", pin) is None:
        return redirect(url_for("pm.property_users", property_id=property_id))

    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        if prop is None or not getattr(prop, "uid", None):
            abort(404)
        prop_uid = str(prop.uid)

    tenant_engine = get_property_engine(prop_uid)
    if tenant_engine is None:
        abort(500)

    now_dt = datetime.now(timezone.utc)

    with Session(tenant_engine) as db:
        PropertyUser.__table__.create(bind=tenant_engine, checkfirst=True)

        existing = (
            db.query(PropertyUser)
            .filter(
                PropertyUser.property_id == int(property_id),
                PropertyUser.username == username,
            )
            .first()
        )
        if existing is not None:
            return redirect(
                url_for(
                    "pm.property_users",
                    property_id=property_id,
                )
            )

        row = PropertyUser(
            property_id=int(property_id),
            username=username,
            password_hash=_ph.hash(password),
            pin_hash=_ph.hash(pin) if pin else None,
            full_name=full_name,
            is_active=1,
            failed_pin_attempts=0,
            pin_locked_until=None,
            last_login_at=None,
            last_pin_use_at=None,
            created_at=now_dt,
        )
        db.add(row)
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_USER_CREATE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, username={username}",
    )
    return redirect(url_for("pm.property_users", property_id=property_id))


@bp.post("/properties/<int:property_id>/users/<int:property_user_id>/toggle")
def property_users_toggle(property_id: int, property_user_id: int):
    user = get_current_user()
    if not _user_can_manage_property(user, property_id):
        abort(403)

    if not validate_global_csrf_token(request.form.get("csrf_token")):
        abort(400)

    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        if prop is None or not getattr(prop, "uid", None):
            abort(404)
        prop_uid = str(prop.uid)

    tenant_engine = get_property_engine(prop_uid)
    if tenant_engine is None:
        abort(500)

    with Session(tenant_engine) as db:
        PropertyUser.__table__.create(
            bind=tenant_engine,
            checkfirst=True,
        )
        row = db.get(PropertyUser, property_user_id)
        if row is None or int(getattr(row, "property_id", 0) or 0) != int(
            property_id
        ):
            abort(404)
        row.is_active = 0 if int(getattr(row, "is_active", 1) or 1) else 1
        db.add(row)
        db.commit()

        new_state = int(getattr(row, "is_active", 0) or 0)

    actor = get_current_user()
    log_event(
        "PROPERTY_USER_TOGGLE",
        user_id=actor.id if actor else None,
        details=(
            f"property_id={property_id}, property_user_id={property_user_id}, "
            f"is_active={new_state}"
        ),
    )
    return redirect(url_for("pm.property_users", property_id=property_id))
