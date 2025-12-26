from __future__ import annotations

from datetime import datetime, timezone
import re
import uuid

from argon2 import PasswordHasher
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from sqlalchemy.orm import Session
from werkzeug.exceptions import HTTPException

from .db import diagnose_property_engine, get_property_engine, get_user_engine
from .logging_utils import log_event
from .models import (
    Property,
    PropertyUser,
    PropertyUserProfile,
    UserProperty,
    create_property_schema,
)
from .security import (
    get_admin_active_property,
    get_current_user,
    set_admin_property_uid_for_session,
    clear_admin_property_uid_for_session,
    user_has_permission,
    user_has_role,
    validate_global_csrf_token,
)


bp = Blueprint("pm", __name__, url_prefix="/pm")
_ph = PasswordHasher()


def _flash_tenant_error(property_uid: str, fallback: str) -> None:
    msg = ""
    try:
        msg = diagnose_property_engine(property_uid)
    except Exception:  # noqa: BLE001
        msg = ""
    msg = (msg or "").strip() or str(fallback or "").strip()
    if not msg:
        msg = "Tenant database is unavailable."
    flash(msg, "error")


def _get_property_and_tenant_engine(property_id: int):
    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        if prop is None:
            abort(404)
        prop_uid = str(getattr(prop, "uid", None) or "").strip()
        if not prop_uid:
            prop_uid = uuid.uuid4().hex
            prop.uid = prop_uid
            db.add(prop)
            db.commit()
        db.expunge(prop)

    tenant_engine = get_property_engine(prop_uid)
    if tenant_engine is None:
        abort(503)
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
        user_has_permission(user, "Cust.Properties.*")
        or user_has_permission(user, "Cust.*")
        or user_has_permission(user, "Platform.*")
        or user_has_permission(user, "*")
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
    if user is None:
        abort(403)
    if not validate_global_csrf_token(request.form.get("csrf_token")):
        abort(400)

    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        prop = db.get(Property, int(property_id))
        if prop is None:
            abort(404)
        prop_uid = str(getattr(prop, "uid", None) or "").strip()
        if not prop_uid:
            prop_uid = uuid.uuid4().hex
            prop.uid = prop_uid
            db.add(prop)
            db.commit()

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


@bp.post("/properties/<int:property_id>/provision")
def pm_property_provision(property_id: int):
    user = get_current_user()
    if user is None:
        abort(403)
    if not validate_global_csrf_token(request.form.get("csrf_token")):
        abort(400)

    engine = get_user_engine()
    if engine is None:
        abort(500)

    prop_uid = ""
    try:
        with Session(engine) as db:
            prop = db.get(Property, int(property_id))
            if prop is None:
                abort(404)
            prop_uid = str(getattr(prop, "uid", "") or "").strip()
            if not prop_uid:
                prop_uid = uuid.uuid4().hex
                prop.uid = prop_uid
                db.add(prop)
                db.commit()

        tenant_engine = get_property_engine(prop_uid)
        if tenant_engine is None:
            raise RuntimeError(diagnose_property_engine(prop_uid))

        create_property_schema(tenant_engine)

        with tenant_engine.connect() as conn:
            conn.execute("SELECT 1")

        flash("Provisioned tenant database and verified schema.", "success")
        actor = get_current_user()
        log_event(
            "ADMIN_PROPERTY_TENANT_PROVISION",
            user_id=actor.id if actor else None,
            details=f"property_id={property_id}, property_uid={prop_uid}, source=pm",
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _flash_tenant_error(prop_uid, exc)

    return redirect(url_for("pm.index"))


@bp.post("/properties/context/clear")
def pm_property_context_clear():
    user = get_current_user()
    if user is None:
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

            can_list_all = False
            if user is not None:
                can_list_all = bool(
                    user_has_permission(user, "Cust.Properties.List")
                    or user_has_permission(user, "Cust.Properties.*")
                    or user_has_permission(user, "Cust.*")
                    or user_has_permission(user, "Platform.*")
                    or user_has_permission(user, "*")
                )

            if can_list_all:
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
    if ctx_id and int(property_id) != int(ctx_id):
        return redirect(url_for("pm.property_users", property_id=int(ctx_id)))
    if not _user_can_manage_property(user, property_id):
        abort(403)

    errors: list[str] = []
    try:
        prop, tenant_engine = _get_property_and_tenant_engine(property_id)
        prop_uid = str(getattr(prop, "uid", "") or "").strip()
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
    except Exception as exc:  # noqa: BLE001
        # Tenant DB might be missing/unreachable/disk-full; show page without crashing.
        prop_uid = ""
        try:
            prop_uid = str(getattr(locals().get("prop", None), "uid", "") or "").strip()
        except Exception:  # noqa: BLE001
            prop_uid = ""
        try:
            errors.append(diagnose_property_engine(prop_uid))
        except Exception:  # noqa: BLE001
            msg = str(exc)
            if "No space left on device" in msg or "Errcode: 28" in msg:
                errors.append(
                    "Tenant DB error: disk is full on the database server. Free space and reload."
                )
            else:
                errors.append(
                    "Tenant database is unavailable or not yet provisioned. Check DB config and disk space, then reload."
                )

        engine = get_user_engine()
        prop = None
        if engine is not None:
            with Session(engine) as db:
                prop = db.get(Property, int(property_id))
                if prop is not None:
                    db.expunge(prop)
        if prop is None:
            abort(404)
        rows = []

    return render_template(
        "pm/property_users.html",
        prop=prop,
        rows=rows,
        errors=errors,
    )


@bp.post("/properties/<int:property_id>/users/create")
def property_users_create(property_id: int):
    user = get_current_user()
    ctx_id = _admin_context_property_id()
    if ctx_id and int(property_id) != int(ctx_id):
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

    created_uid = None
    now_dt = datetime.now(timezone.utc)
    prop_uid = ""
    try:
        prop, tenant_engine = _get_property_and_tenant_engine(property_id)
        prop_uid = str(getattr(prop, "uid", "") or "").strip()
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
    except Exception as exc:  # noqa: BLE001
        _flash_tenant_error(prop_uid, exc)
        return redirect(url_for("pm.property_users", property_id=property_id))

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


@bp.post("/properties/<int:property_id>/users/migrate-legacy")
def property_users_migrate_legacy(property_id: int):
    user = get_current_user()
    if not _user_can_manage_property(user, property_id):
        abort(403)

    if not validate_global_csrf_token(request.form.get("csrf_token")):
        abort(400)

    prop_uid = ""
    try:
        prop, tenant_engine = _get_property_and_tenant_engine(property_id)
        prop_uid = str(getattr(prop, "uid", "") or "").strip()
    except Exception as exc:  # noqa: BLE001
        _flash_tenant_error(prop_uid, exc)
        return redirect(url_for("pm.property_users", property_id=property_id))

    user_engine = get_user_engine()
    if user_engine is None:
        abort(500)

    legacy_rows: list[dict] = []
    try:
        with Session(user_engine) as db:
            # Legacy deployments stored property users in the global user DB.
            PropertyUser.__table__.create(bind=user_engine, checkfirst=True)

            rows = (
                db.query(PropertyUser)
                .filter(PropertyUser.property_id == int(property_id))
                .order_by(PropertyUser.id)
                .all()
            )
            if not rows:
                flash("No legacy property users found to migrate.", "notice")
                return redirect(url_for("pm.property_users", property_id=property_id))

            changed = False
            for r in rows:
                uid_val = str(getattr(r, "uid", "") or "").strip().lower()
                if re.fullmatch(r"[a-f0-9]{32}", uid_val) is None:
                    uid_val = uuid.uuid4().hex
                    r.uid = uid_val
                    db.add(r)
                    changed = True
                legacy_rows.append(
                    {
                        "uid": uid_val,
                        "username": getattr(r, "username", None),
                        "password_hash": getattr(r, "password_hash", None),
                        "pin_hash": getattr(r, "pin_hash", None),
                        "full_name": getattr(r, "full_name", None),
                        "is_active": int(getattr(r, "is_active", 0) or 0),
                        "failed_pin_attempts": int(
                            getattr(r, "failed_pin_attempts", 0) or 0
                        ),
                        "pin_locked_until": getattr(r, "pin_locked_until", None),
                        "last_login_at": getattr(r, "last_login_at", None),
                        "last_pin_use_at": getattr(r, "last_pin_use_at", None),
                        "created_at": getattr(r, "created_at", None),
                    }
                )
            if changed:
                db.commit()
    except Exception as exc:  # noqa: BLE001
        flash(f"Legacy migration read failed: {exc}", "error")
        return redirect(url_for("pm.property_users", property_id=property_id))

    migrated = 0
    skipped = 0
    try:
        # Ensure schema exists/updated before inserting.
        create_property_schema(tenant_engine)

        with Session(tenant_engine) as db:
            PropertyUser.__table__.create(bind=tenant_engine, checkfirst=True)

            for row in legacy_rows:
                uid_val = str(row.get("uid") or "").strip().lower()
                if not uid_val:
                    continue
                existing = (
                    db.query(PropertyUser.id)
                    .filter(
                        PropertyUser.property_id == int(property_id),
                        PropertyUser.uid == uid_val,
                    )
                    .first()
                )
                if existing is not None:
                    skipped += 1
                    continue

                new_row = PropertyUser(
                    property_id=int(property_id),
                    uid=uid_val,
                    username=row.get("username"),
                    password_hash=row.get("password_hash"),
                    pin_hash=row.get("pin_hash"),
                    full_name=row.get("full_name"),
                    is_active=1 if int(row.get("is_active") or 0) else 0,
                    failed_pin_attempts=int(row.get("failed_pin_attempts") or 0),
                    pin_locked_until=row.get("pin_locked_until"),
                    last_login_at=row.get("last_login_at"),
                    last_pin_use_at=row.get("last_pin_use_at"),
                    created_at=row.get("created_at"),
                )
                db.add(new_row)
                migrated += 1

            db.commit()

        flash(
            f"Migrated {migrated} legacy users into tenant DB (skipped {skipped}).",
            "success",
        )
        actor = get_current_user()
        log_event(
            "PROPERTY_USER_MIGRATE_LEGACY",
            user_id=actor.id if actor else None,
            details=(
                f"property_id={property_id}, migrated={migrated}, skipped={skipped}"
            ),
        )
    except Exception as exc:  # noqa: BLE001
        _flash_tenant_error(prop_uid, exc)

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

    try:
        prop, tenant_engine = _get_property_and_tenant_engine(property_id)
    except Exception as exc:  # noqa: BLE001
        _flash_tenant_error("", exc)
        return redirect(url_for("pm.property_users", property_id=property_id))

    errors: list[str] = []
    saved = False
    uid_norm = (property_user_uid or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", uid_norm) is None:
        abort(404)

    now_dt = datetime.now(timezone.utc)

    try:
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
    except Exception as exc:  # noqa: BLE001
        _flash_tenant_error(str(getattr(prop, "uid", "") or "").strip(), exc)
        return redirect(url_for("pm.property_users", property_id=property_id))

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

    uid_norm = (property_user_uid or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", uid_norm) is None:
        abort(404)

    prop_uid = ""
    new_state = None
    try:
        prop, tenant_engine = _get_property_and_tenant_engine(property_id)
        prop_uid = str(getattr(prop, "uid", "") or "").strip()
        with Session(tenant_engine) as db:
            PropertyUser.__table__.create(bind=tenant_engine, checkfirst=True)
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

            user_row.is_active = 0 if int(getattr(user_row, "is_active", 0) or 0) else 1
            db.add(user_row)
            db.commit()
            new_state = int(getattr(user_row, "is_active", 0) or 0)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _flash_tenant_error(prop_uid, exc)
        return redirect(url_for("pm.property_users", property_id=property_id))

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

    prop_uid = ""
    new_state = None
    try:
        prop, tenant_engine = _get_property_and_tenant_engine(property_id)
        prop_uid = str(getattr(prop, "uid", "") or "").strip()
        with Session(tenant_engine) as db:
            PropertyUser.__table__.create(
                bind=tenant_engine,
                checkfirst=True,
            )
            row = db.get(PropertyUser, property_user_id)
            if row is None or int(getattr(row, "property_id", 0) or 0) != int(property_id):
                abort(404)
            row.is_active = 0 if int(getattr(row, "is_active", 1) or 1) else 1
            db.add(row)
            db.commit()

            new_state = int(getattr(row, "is_active", 0) or 0)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _flash_tenant_error(prop_uid, exc)
        return redirect(url_for("pm.property_users", property_id=property_id))

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
