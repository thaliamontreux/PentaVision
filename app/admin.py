from __future__ import annotations

from typing import Dict, List, Set

from flask import (
    Blueprint,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_user_engine
from .logging_utils import log_event
from .models import Property, Role, User, UserProperty, UserRole
from .security import get_current_user, user_has_role


bp = Blueprint("admin", __name__, url_prefix="/admin")


def _ensure_csrf_token() -> str:
    token = session.get("admin_csrf")
    if not token:
        import secrets

        token = secrets.token_urlsafe(32)
        session["admin_csrf"] = token
    return token


def _validate_csrf_token(token: str | None) -> bool:
    if not token:
        return False
    return token == session.get("admin_csrf")


@bp.before_request
def _require_system_admin():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))
    if not user_has_role(user, "System Administrator"):
        abort(403)


@bp.get("/users")
def users_list():
    engine = get_user_engine()
    errors: List[str] = []
    users: List[User] = []
    user_roles: Dict[int, Set[str]] = {}

    if engine is None:
        errors.append("User database is not configured.")
    else:
        with Session(engine) as db:
            users = db.query(User).order_by(User.email).all()
            role_rows = db.query(Role).order_by(Role.name).all()
            user_role_rows = db.query(UserRole, Role).join(Role, Role.id == UserRole.role_id).all()

        for ur, role in user_role_rows:
            roles_for_user = user_roles.setdefault(ur.user_id, set())
            roles_for_user.add(role.name)

    csrf_token = _ensure_csrf_token()
    # For now we focus on two key roles; additional roles can be managed later.
    managed_roles = ["System Administrator", "Technician"]

    return render_template(
        "admin/users.html",
        users=users,
        user_roles=user_roles,
        managed_roles=managed_roles,
        errors=errors,
        csrf_token=csrf_token,
    )


@bp.post("/users/<int:user_id>/roles")
def update_user_roles(user_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)

    role_name = (request.form.get("role") or "").strip()
    action = (request.form.get("action") or "").strip()
    if not role_name or action not in {"add", "remove"}:
        abort(400)

    engine = get_user_engine()
    if engine is None:
        abort(500)
    changed = False
    target_user_id = None
    target_role_name = None

    with Session(engine) as db:
        user = db.get(User, user_id)
        if user is None:
            abort(404)

        role = db.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            abort(404)

        # Load all current admin role bindings to enforce safety when demoting.
        if role_name == "System Administrator" and action == "remove":
            current_admin_ids = [
                ur.user_id
                for ur, r in db.query(UserRole, Role)
                .join(Role, Role.id == UserRole.role_id)
                .filter(Role.name == "System Administrator")
                .all()
            ]
            # If this is the only admin, do not allow demotion to avoid lockout.
            if len(current_admin_ids) <= 1 and user.id in current_admin_ids:
                # Silently ignore and return to list; a future UI could show a warning.
                return redirect(url_for("admin.users_list"))

        target_user_id = user.id
        target_role_name = role.name

        if action == "add":
            existing = (
                db.query(UserRole)
                .filter(
                    UserRole.user_id == user.id,
                    UserRole.role_id == role.id,
                    UserRole.property_id.is_(None),
                )
                .first()
            )
            if existing is None:
                db.add(UserRole(user_id=user.id, role_id=role.id, property_id=None))
                changed = True
        elif action == "remove":
            deleted = db.query(UserRole).filter(
                UserRole.user_id == user.id,
                UserRole.role_id == role.id,
                UserRole.property_id.is_(None),
            ).delete(synchronize_session=False)
            if deleted:
                changed = True

        db.commit()

    if changed:
        actor = get_current_user()
        event_type = "ROLE_ASSIGN" if action == "add" else "ROLE_REVOKE"
        log_event(
            event_type,
            user_id=actor.id if actor else None,
            details=f"target_user_id={target_user_id}, role={target_role_name}",
        )

    return redirect(url_for("admin.users_list"))


@bp.get("/properties")
def properties_list():
    engine = get_user_engine()
    errors: List[str] = []
    properties: List[Property] = []

    if engine is None:
        errors.append("User database is not configured.")
    else:
        with Session(engine) as db:
            properties = db.query(Property).order_by(Property.name).all()

    csrf_token = _ensure_csrf_token()
    return render_template(
        "admin/properties.html",
        properties=properties,
        errors=errors,
        csrf_token=csrf_token,
    )


@bp.route("/properties/new", methods=["GET", "POST"])
def property_create():
    engine = get_user_engine()
    errors: List[str] = []
    form = {
        "name": "",
        "address_line1": "",
        "address_line2": "",
        "city": "",
        "state": "",
        "postal_code": "",
        "country": "",
        "timezone": "",
    }
    csrf_token = _ensure_csrf_token()

    if engine is None:
        errors.append("User database is not configured.")
        return render_template(
            "admin/properties_edit.html",
            form=form,
            errors=errors,
            csrf_token=csrf_token,
            is_edit=False,
            users=[],
            user_links={},
            property_id=None,
        )

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")

        form["name"] = (request.form.get("name") or "").strip()
        form["address_line1"] = (request.form.get("address_line1") or "").strip()
        form["address_line2"] = (request.form.get("address_line2") or "").strip()
        form["city"] = (request.form.get("city") or "").strip()
        form["state"] = (request.form.get("state") or "").strip()
        form["postal_code"] = (request.form.get("postal_code") or "").strip()
        form["country"] = (request.form.get("country") or "").strip()
        form["timezone"] = (request.form.get("timezone") or "").strip()

        if not form["name"]:
            errors.append("Name is required.")

        if not errors:
            with Session(engine) as db:
                prop = Property(
                    name=form["name"],
                    address_line1=form["address_line1"] or None,
                    address_line2=form["address_line2"] or None,
                    city=form["city"] or None,
                    state=form["state"] or None,
                    postal_code=form["postal_code"] or None,
                    country=form["country"] or None,
                    timezone=form["timezone"] or None,
                )
                db.add(prop)
                db.commit()
            actor = get_current_user()
            log_event(
                "PROPERTY_CREATE",
                user_id=actor.id if actor else None,
                details=f"property_id={prop.id}, name={prop.name}",
            )
            return redirect(url_for("admin.properties_list"))

    return render_template(
        "admin/properties_edit.html",
        form=form,
        errors=errors,
        csrf_token=csrf_token,
        is_edit=False,
        users=[],
        user_links={},
        property_id=None,
    )


@bp.route("/properties/<int:property_id>/edit", methods=["GET", "POST"])
def property_edit(property_id: int):
    engine = get_user_engine()
    errors: List[str] = []
    csrf_token = _ensure_csrf_token()

    if engine is None:
        errors.append("User database is not configured.")
        return render_template(
            "admin/properties_edit.html",
            form=None,
            errors=errors,
            csrf_token=csrf_token,
            is_edit=True,
            users=[],
            user_links={},
            property_id=property_id,
        )

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        if prop is None:
            errors.append("Property not found.")
            return render_template(
                "admin/properties_edit.html",
                form=None,
                errors=errors,
                csrf_token=csrf_token,
                is_edit=True,
                users=[],
                user_links={},
                property_id=property_id,
            )

        form = {
            "name": prop.name,
            "address_line1": prop.address_line1 or "",
            "address_line2": prop.address_line2 or "",
            "city": prop.city or "",
            "state": prop.state or "",
            "postal_code": prop.postal_code or "",
            "country": prop.country or "",
            "timezone": prop.timezone or "",
        }

        if request.method == "POST":
            if not _validate_csrf_token(request.form.get("csrf_token")):
                errors.append("Invalid or missing CSRF token.")

            form["name"] = (request.form.get("name") or "").strip()
            form["address_line1"] = (request.form.get("address_line1") or "").strip()
            form["address_line2"] = (request.form.get("address_line2") or "").strip()
            form["city"] = (request.form.get("city") or "").strip()
            form["state"] = (request.form.get("state") or "").strip()
            form["postal_code"] = (request.form.get("postal_code") or "").strip()
            form["country"] = (request.form.get("country") or "").strip()
            form["timezone"] = (request.form.get("timezone") or "").strip()

            if not form["name"]:
                errors.append("Name is required.")

            if not errors:
                prop.name = form["name"]
                prop.address_line1 = form["address_line1"] or None
                prop.address_line2 = form["address_line2"] or None
                prop.city = form["city"] or None
                prop.state = form["state"] or None
                prop.postal_code = form["postal_code"] or None
                prop.country = form["country"] or None
                prop.timezone = form["timezone"] or None
                db.add(prop)
                db.commit()
                actor = get_current_user()
                log_event(
                    "PROPERTY_UPDATE",
                    user_id=actor.id if actor else None,
                    details=f"property_id={prop.id}, name={prop.name}",
                )
                return redirect(url_for("admin.properties_list"))

        users = db.query(User).order_by(User.email).all()
        links = (
            db.query(UserProperty)
            .filter(UserProperty.property_id == property_id)
            .all()
        )
        user_links: Dict[int, UserProperty] = {link.user_id: link for link in links}

    return render_template(
        "admin/properties_edit.html",
        form=form,
        errors=errors,
        csrf_token=csrf_token,
        is_edit=True,
        users=users,
        user_links=user_links,
        property_id=property_id,
    )


@bp.post("/properties/<int:property_id>/delete")
def property_delete(property_id: int):
    engine = get_user_engine()
    if engine is None:
        return redirect(url_for("admin.properties_list"))

    if not _validate_csrf_token(request.form.get("csrf_token")):
        return redirect(url_for("admin.properties_list"))

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        if prop is not None:
            # For now, deleting a property also deletes any UserProperty links.
            db.query(UserProperty).filter(
                UserProperty.property_id == property_id
            ).delete(synchronize_session=False)
            name = prop.name
            db.delete(prop)
            db.commit()
            actor = get_current_user()
            log_event(
                "PROPERTY_DELETE",
                user_id=actor.id if actor else None,
                details=f"property_id={property_id}, name={name}",
            )

    return redirect(url_for("admin.properties_list"))


@bp.post("/properties/<int:property_id>/users/<int:user_id>")
def property_update_user(property_id: int, user_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)

    engine = get_user_engine()
    if engine is None:
        abort(500)

    action = (request.form.get("action") or "").strip()
    if action not in {"save", "remove"}:
        abort(400)

    with Session(engine) as db:
        user = db.get(User, user_id)
        prop = db.get(Property, property_id)
        if user is None or prop is None:
            abort(404)

        if action == "remove":
            db.query(UserProperty).filter(
                UserProperty.user_id == user_id,
                UserProperty.property_id == property_id,
            ).delete(synchronize_session=False)
            db.commit()
            actor = get_current_user()
            log_event(
                "PROPERTY_USER_UNLINK",
                user_id=actor.id if actor else None,
                details=f"property_id={property_id}, target_user_id={user_id}",
            )
            return redirect(url_for("admin.property_edit", property_id=property_id))

        residency_status = (request.form.get("residency_status") or "").strip()
        camera_scope = (request.form.get("camera_scope") or "").strip()
        access_windows = (request.form.get("access_windows") or "").strip()
        authorized_zones = (request.form.get("authorized_zones") or "").strip()
        role_overrides = (request.form.get("role_overrides") or "").strip()

        link = (
            db.query(UserProperty)
            .filter(
                UserProperty.user_id == user_id,
                UserProperty.property_id == property_id,
            )
            .first()
        )
        if link is None:
            link = UserProperty(user_id=user_id, property_id=property_id)
            db.add(link)

        link.residency_status = residency_status or None
        link.camera_scope = camera_scope or None
        link.access_windows = access_windows or None
        link.authorized_zones = authorized_zones or None
        link.role_overrides = role_overrides or None

        db.add(link)
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_USER_UPDATE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, target_user_id={user_id}",
    )

    return redirect(url_for("admin.property_edit", property_id=property_id))
