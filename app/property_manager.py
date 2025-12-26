from __future__ import annotations

from datetime import datetime, timezone
import re
import uuid

from argon2 import PasswordHasher
from flask import Blueprint, abort, redirect, render_template, request, url_for
from sqlalchemy.orm import Session

from .db import get_property_engine, get_user_engine
from .logging_utils import log_event
from .models import Property, PropertyUser, PropertyUserProfile, UserProperty
from .security import (
    get_admin_active_property,
    get_current_user,
    set_admin_property_uid_for_session,
    clear_admin_property_uid_for_session,
    user_has_role,
    validate_global_csrf_token,
)


bp = Blueprint("pm", __name__, url_prefix="/pm")
_ph = PasswordHasher()


def _get_property_and_tenant_engine(property_id: int):
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
    return prop, tenant_engine


def _require_global_user():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))
    return None


def _user_can_manage_property(user, property_id: int) -> bool:
    if user is None:
        return False
    if (
        user_has_role(user, "System Administrator")
        or user_has_role(user, "Property Administrator")
    ):
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


def _admin_context_property_id() -> int | None:
    prop = get_admin_active_property()
    if prop is None:
        return None
    try:
        return int(getattr(prop, "id", None) or 0) or None
    except (TypeError, ValueError):
        return None


@bp.post("/properties/<int:property_id>/enter")
def pm_property_enter(property_id: int):
    user = get_current_user()
    if not (
        user_has_role(user, "System Administrator")
        or user_has_role(user, "Property Administrator")
    ):
        abort(403)
    if not validate_global_csrf_token(request.form.get("csrf_token")):
        abort(400)

    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        prop = db.get(Property, int(property_id))
        if prop is None or not getattr(prop, "uid", None):
            abort(404)
        prop_uid = str(prop.uid)

    set_admin_property_uid_for_session(prop_uid)

    actor = get_current_user()
    log_event(
        "ADMIN_PROPERTY_CONTEXT_ENTER",
        user_id=actor.id if actor else None,
        details=(
            f"source=pm, property_id={property_id}, property_uid={prop_uid}"
        ),
    )
    return redirect(url_for("pm.index"))


@bp.post("/properties/context/clear")
def pm_property_context_clear():
    user = get_current_user()
    if not (
        user_has_role(user, "System Administrator")
        or user_has_role(user, "Property Administrator")
    ):
        abort(403)
    if not validate_global_csrf_token(request.form.get("csrf_token")):
        abort(400)

    clear_admin_property_uid_for_session()

    actor = get_current_user()
    log_event(
        "ADMIN_PROPERTY_CONTEXT_EXIT",
        user_id=actor.id if actor else None,
        details="source=pm",
    )
    return redirect(url_for("pm.index"))


@bp.before_request
def _pm_require_login():
    return _require_global_user()


@bp.get("/")
def index():
    user = get_current_user()
    engine = get_user_engine()
    props: list[Property] = []

    ctx_id = _admin_context_property_id()

    if engine is not None:
        with Session(engine) as db:
            try:
                Property.__table__.create(bind=engine, checkfirst=True)
                UserProperty.__table__.create(bind=engine, checkfirst=True)
            except Exception:  # noqa: BLE001
                pass

            if (
                user_has_role(user, "System Administrator")
                or user_has_role(user, "Property Administrator")
            ):
                if ctx_id:
                    props = (
                        db.query(Property)
                        .filter(Property.id == int(ctx_id))
                        .order_by(Property.name)
                        .all()
                    )
                else:
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
    ctx_id = _admin_context_property_id()
    if (
        ctx_id
        and (
            user_has_role(user, "System Administrator")
            or user_has_role(user, "Property Administrator")
        )
        and int(property_id) != int(ctx_id)
    ):
        return redirect(url_for("pm.property_users", property_id=int(ctx_id)))
    if not _user_can_manage_property(user, property_id):
        abort(403)

    prop, tenant_engine = _get_property_and_tenant_engine(property_id)

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
    ctx_id = _admin_context_property_id()
    if (
        ctx_id
        and (
            user_has_role(user, "System Administrator")
            or user_has_role(user, "Property Administrator")
        )
        and int(property_id) != int(ctx_id)
    ):
        return redirect(url_for("pm.property_users", property_id=int(ctx_id)))
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

    _prop, tenant_engine = _get_property_and_tenant_engine(property_id)
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
            return redirect(url_for("pm.property_users", property_id=property_id))

        row = PropertyUser(
            property_id=int(property_id),
            uid=uuid.uuid4().hex,
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

        created_uid = getattr(row, "uid", None)

    actor = get_current_user()
    log_event(
        "PROPERTY_USER_CREATE",
        user_id=actor.id if actor else None,
        details=(
            f"property_id={property_id}, username={username}, "
            f"property_user_uid={created_uid}"
        ),
    )
    return redirect(url_for("pm.property_users", property_id=property_id))


@bp.route("/properties/<int:property_id>/users/<string:property_user_uid>", methods=["GET", "POST"])
def property_user_detail(property_id: int, property_user_uid: str):
    user = get_current_user()
    ctx_id = _admin_context_property_id()
    if (
        ctx_id
        and (
            user_has_role(user, "System Administrator")
            or user_has_role(user, "Property Administrator")
        )
        and int(property_id) != int(ctx_id)
    ):
        return redirect(
            url_for(
                "pm.property_user_detail",
                property_id=int(ctx_id),
                property_user_uid=property_user_uid,
            )
        )
    if not _user_can_manage_property(user, property_id):
        abort(403)

    prop, tenant_engine = _get_property_and_tenant_engine(property_id)

    errors: list[str] = []
    saved = False
    uid_norm = (property_user_uid or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", uid_norm) is None:
        abort(404)

    now_dt = datetime.now(timezone.utc)

    with Session(tenant_engine) as db:
        PropertyUser.__table__.create(bind=tenant_engine, checkfirst=True)
        PropertyUserProfile.__table__.create(bind=tenant_engine, checkfirst=True)

        user_row = (
            db.query(PropertyUser)
            .filter(
                PropertyUser.property_id == int(property_id),
                PropertyUser.uid == uid_norm,
            )
            .first()
        )
        if user_row is None:
            abort(404)

        profile_row = (
            db.query(PropertyUserProfile)
            .filter(PropertyUserProfile.property_user_id == int(user_row.id))
            .first()
        )
        if profile_row is None:
            profile_row = PropertyUserProfile(property_user_id=int(user_row.id))
            db.add(profile_row)
            db.commit()

        if request.method == "POST":
            if not validate_global_csrf_token(request.form.get("csrf_token")):
                errors.append("Invalid or missing CSRF token.")

            profile_only = (request.form.get("profile_only") or "") == "1"
            if profile_only:
                profile_row.email = (request.form.get("email") or "").strip() or None
                profile_row.primary_phone = (
                    request.form.get("primary_phone") or ""
                ).strip() or None
                profile_row.secondary_phone = (
                    request.form.get("secondary_phone") or ""
                ).strip() or None

                profile_row.unit_number = (
                    request.form.get("unit_number") or ""
                ).strip() or None
                profile_row.address_line1 = (
                    request.form.get("address_line1") or ""
                ).strip() or None
                profile_row.address_line2 = (
                    request.form.get("address_line2") or ""
                ).strip() or None
                profile_row.city = (request.form.get("city") or "").strip() or None
                profile_row.state = (request.form.get("state") or "").strip() or None
                profile_row.postal_code = (
                    request.form.get("postal_code") or ""
                ).strip() or None
                profile_row.country = (
                    request.form.get("country") or ""
                ).strip() or None
                profile_row.residency_status = (
                    request.form.get("residency_status") or ""
                ).strip() or None
                profile_row.emergency_contact_name = (
                    request.form.get("emergency_contact_name") or ""
                ).strip() or None
                profile_row.emergency_contact_phone = (
                    request.form.get("emergency_contact_phone") or ""
                ).strip() or None
                profile_row.emergency_contact_relation = (
                    request.form.get("emergency_contact_relation") or ""
                ).strip() or None
                profile_row.notes = (request.form.get("notes") or "").strip() or None
                profile_row.updated_at = now_dt
            else:
                username = (request.form.get("username") or "").strip().lower()
                full_name = (request.form.get("full_name") or "").strip() or None
                password = request.form.get("password") or ""
                pin = (request.form.get("pin") or "").strip()

                if not username:
                    errors.append("Username is required.")

                if pin and re.fullmatch(r"\d{8}", pin) is None:
                    errors.append("PIN must be exactly 8 digits.")

                if not errors:
                    existing = (
                        db.query(PropertyUser)
                        .filter(
                            PropertyUser.property_id == int(property_id),
                            PropertyUser.username == username,
                            PropertyUser.id != int(user_row.id),
                        )
                        .first()
                    )
                    if existing is not None:
                        errors.append("Username is already in use.")

                if not errors:
                    user_row.username = username
                    user_row.full_name = full_name
                    user_row.is_active = 1 if request.form.get("is_active") == "1" else 0
                    if password:
                        user_row.password_hash = _ph.hash(password)
                    if pin:
                        user_row.pin_hash = _ph.hash(pin)

            if not errors:
                db.add(user_row)
                db.add(profile_row)
                db.commit()
                saved = True

                actor = get_current_user()
                log_event(
                    "PROPERTY_USER_UPDATE",
                    user_id=actor.id if actor else None,
                    details=(
                        f"property_id={property_id}, property_user_uid={uid_norm}, "
                        f"profile_only={1 if profile_only else 0}"
                    ),
                )

        form = {
            "username": getattr(user_row, "username", "") or "",
            "full_name": getattr(user_row, "full_name", "") or "",
            "is_active": bool(getattr(user_row, "is_active", 0)),
        }
        profile = {
            "email": getattr(profile_row, "email", "") or "",
            "primary_phone": getattr(profile_row, "primary_phone", "") or "",
            "secondary_phone": getattr(profile_row, "secondary_phone", "") or "",
            "unit_number": getattr(profile_row, "unit_number", "") or "",
            "address_line1": getattr(profile_row, "address_line1", "") or "",
            "address_line2": getattr(profile_row, "address_line2", "") or "",
            "city": getattr(profile_row, "city", "") or "",
            "state": getattr(profile_row, "state", "") or "",
            "postal_code": getattr(profile_row, "postal_code", "") or "",
            "country": getattr(profile_row, "country", "") or "",
            "residency_status": getattr(profile_row, "residency_status", "") or "",
            "emergency_contact_name": getattr(profile_row, "emergency_contact_name", "") or "",
            "emergency_contact_phone": getattr(profile_row, "emergency_contact_phone", "") or "",
            "emergency_contact_relation": getattr(profile_row, "emergency_contact_relation", "") or "",
            "notes": getattr(profile_row, "notes", "") or "",
        }

        db.expunge(user_row)

    return render_template(
        "pm/property_user_detail.html",
        prop=prop,
        user_row=user_row,
        form=form,
        profile=profile,
        errors=errors,
        saved=saved,
    )


@bp.post("/properties/<int:property_id>/users/<string:property_user_uid>/toggle")
def property_users_toggle_uid(property_id: int, property_user_uid: str):
    user = get_current_user()
    ctx_id = _admin_context_property_id()
    if (
        ctx_id
        and (
            user_has_role(user, "System Administrator")
            or user_has_role(user, "Property Administrator")
        )
        and int(property_id) != int(ctx_id)
    ):
        return redirect(url_for("pm.property_users", property_id=int(ctx_id)))
    if not _user_can_manage_property(user, property_id):
        abort(403)

    if not validate_global_csrf_token(request.form.get("csrf_token")):
        abort(400)

    _prop, tenant_engine = _get_property_and_tenant_engine(property_id)
    uid_norm = (property_user_uid or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", uid_norm) is None:
        abort(404)

    with Session(tenant_engine) as db:
        PropertyUser.__table__.create(bind=tenant_engine, checkfirst=True)
        row = (
            db.query(PropertyUser)
            .filter(
                PropertyUser.property_id == int(property_id),
                PropertyUser.uid == uid_norm,
            )
            .first()
        )
        if row is None:
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
            f"property_id={property_id}, property_user_uid={uid_norm}, "
            f"is_active={new_state}"
        ),
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
