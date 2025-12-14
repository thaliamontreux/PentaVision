from __future__ import annotations

from typing import Dict, List, Sequence, Set

from argon2 import PasswordHasher
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
from .models import (
    CountryAccessPolicy,
    IpAllowlist,
    IpBlocklist,
    Property,
    Role,
    User,
    UserProperty,
    UserRole,
)
from .security import get_current_user, user_has_role


bp = Blueprint("admin", __name__, url_prefix="/admin")
_ph = PasswordHasher()


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


@bp.get("/")
def index():
    return render_template("admin/index.html")


@bp.get("/recordings")
def recordings_alias():
    """Admin-scoped alias for the main recordings view."""
    return redirect(url_for("main.recordings"))


@bp.get("/storage")
def storage_alias():
    """Admin-scoped alias for the main storage settings view.

    This keeps the underlying implementation in the main blueprint but provides
    a stable /admin URL for navigation and future refactors.
    """
    return redirect(url_for("main.storage_settings"))


@bp.get("/recording-settings")
def recording_settings_alias():
    """Admin-scoped alias for the main recording settings view."""
    return redirect(url_for("main.recording_settings"))


@bp.get("/audit")
def audit_alias():
    """Admin-scoped alias for the main audit log view."""
    return redirect(url_for("main.audit_events"))


@bp.route("/access-control", methods=["GET", "POST"])
def access_control():
    engine = get_user_engine()
    errors: List[str] = []
    messages: List[str] = []
    ip_allow: List[IpAllowlist] = []
    ip_block: List[IpBlocklist] = []
    policy = None
    csrf_token = _ensure_csrf_token()

    if engine is None:
        errors.append("User database is not configured.")
    else:
        with Session(engine) as db:
            IpAllowlist.__table__.create(bind=engine, checkfirst=True)
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            CountryAccessPolicy.__table__.create(bind=engine, checkfirst=True)

            if request.method == "POST":
                if not _validate_csrf_token(request.form.get("csrf_token")):
                    errors.append("Invalid or missing CSRF token.")
                else:
                    action = (request.form.get("action") or "").strip()
                    if action == "add_allow":
                        cidr = (request.form.get("cidr") or "").strip()
                        description = (request.form.get("description") or "").strip()
                        if cidr:
                            existing = (
                                db.query(IpAllowlist)
                                .filter(IpAllowlist.cidr == cidr)
                                .first()
                            )
                            if existing is None:
                                entry = IpAllowlist(
                                    cidr=cidr,
                                    description=description or None,
                                )
                                db.add(entry)
                                db.commit()
                                actor = get_current_user()
                                log_event(
                                    "ADMIN_IP_ALLOWLIST_ADD",
                                    user_id=actor.id if actor else None,
                                    details=f"cidr={cidr}",
                                )
                                messages.append("IP exemption added.")
                    elif action == "delete_allow":
                        entry_id = request.form.get("id")
                        try:
                            entry_id_int = int(entry_id or "")
                        except ValueError:
                            entry_id_int = None
                        if entry_id_int is not None:
                            db.query(IpAllowlist).filter(
                                IpAllowlist.id == entry_id_int
                            ).delete(synchronize_session=False)
                            db.commit()
                            actor = get_current_user()
                            log_event(
                                "ADMIN_IP_ALLOWLIST_DELETE",
                                user_id=actor.id if actor else None,
                                details=f"id={entry_id_int}",
                            )
                            messages.append("IP exemption removed.")
                    elif action == "add_block":
                        cidr = (request.form.get("cidr") or "").strip()
                        description = (request.form.get("description") or "").strip()
                        if cidr:
                            existing = (
                                db.query(IpBlocklist)
                                .filter(IpBlocklist.cidr == cidr)
                                .first()
                            )
                            if existing is None:
                                entry = IpBlocklist(
                                    cidr=cidr,
                                    description=description or None,
                                )
                                db.add(entry)
                                db.commit()
                                actor = get_current_user()
                                log_event(
                                    "ADMIN_IP_BLOCKLIST_ADD",
                                    user_id=actor.id if actor else None,
                                    details=f"cidr={cidr}",
                                )
                                messages.append("IP/network block added.")
                    elif action == "delete_block":
                        entry_id = request.form.get("id")
                        try:
                            entry_id_int = int(entry_id or "")
                        except ValueError:
                            entry_id_int = None
                        if entry_id_int is not None:
                            db.query(IpBlocklist).filter(
                                IpBlocklist.id == entry_id_int
                            ).delete(synchronize_session=False)
                            db.commit()
                            actor = get_current_user()
                            log_event(
                                "ADMIN_IP_BLOCKLIST_DELETE",
                                user_id=actor.id if actor else None,
                                details=f"id={entry_id_int}",
                            )
                            messages.append("IP/network block removed.")
                    elif action == "update_country":
                        mode = (request.form.get("mode") or "").strip()
                        allowed_codes = request.form.getlist("allowed_countries")
                        blocked_codes = request.form.getlist("blocked_countries")
                        allowed_str = ",".join(
                            sorted(
                                {
                                    c.strip().upper()
                                    for c in allowed_codes
                                    if c.strip()
                                }
                            )
                        )
                        blocked_str = ",".join(
                            sorted(
                                {
                                    c.strip().upper()
                                    for c in blocked_codes
                                    if c.strip()
                                }
                            )
                        )
                        policy = (
                            db.query(CountryAccessPolicy)
                            .order_by(CountryAccessPolicy.id.asc())
                            .first()
                        )
                        if policy is None:
                            policy = CountryAccessPolicy()
                            db.add(policy)
                        policy.mode = mode or None
                        policy.allowed_countries = allowed_str or None
                        policy.blocked_countries = blocked_str or None
                        db.add(policy)
                        db.commit()
                        actor = get_current_user()
                        log_event(
                            "ADMIN_COUNTRY_POLICY_UPDATE",
                            user_id=actor.id if actor else None,
                            details=f"mode={mode}",
                        )
                        messages.append("Country access policy updated.")

            ip_allow = db.query(IpAllowlist).order_by(IpAllowlist.cidr.asc()).all()
            ip_block = db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all()
            if policy is None:
                policy = (
                    db.query(CountryAccessPolicy)
                    .order_by(CountryAccessPolicy.id.asc())
                    .first()
                )

    return render_template(
        "admin/access_control.html",
        errors=errors,
        messages=messages,
        csrf_token=csrf_token,
        ip_allow=ip_allow,
        ip_block=ip_block,
        policy=policy,
        country_choices=COUNTRY_CHOICES,
    )


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
                db.add(
                    UserRole(
                        user_id=user.id,
                        role_id=role.id,
                        property_id=None,
                    )
                )
                changed = True
        else:
            deleted = (
                db.query(UserRole)
                .filter(
                    UserRole.user_id == user.id,
                    UserRole.role_id == role.id,
                    UserRole.property_id.is_(None),
                )
                .delete(synchronize_session=False)
            )
            if deleted:
                changed = True

        if changed:
            db.commit()
            actor = get_current_user()
            log_event(
                "ADMIN_USER_ROLE_UPDATE",
                user_id=actor.id if actor else None,
                details=f"target_user_id={target_user_id}, role={target_role_name}, action={action}",
            )

    return redirect(url_for("admin.users_list"))


PRONOUN_OPTIONS: Sequence[str] = (
    "",
    "she/her",
    "he/him",
    "they/them",
    "she/they",
    "he/they",
    "ze/zir",
    "ze/hir",
    "xe/xem",
)


TIMEZONE_OPTIONS: Sequence[str] = (
    "Africa/Cairo",
    "Africa/Johannesburg",
    "Africa/Lagos",
    "Africa/Nairobi",
    "America/Anchorage",
    "America/Argentina/Buenos_Aires",
    "America/Bogota",
    "America/Chicago",
    "America/Denver",
    "America/Halifax",
    "America/Los_Angeles",
    "America/Mexico_City",
    "America/New_York",
    "America/Phoenix",
    "America/Santiago",
    "America/Sao_Paulo",
    "America/Toronto",
    "America/Vancouver",
    "America/Winnipeg",
    "Asia/Almaty",
    "Asia/Amman",
    "Asia/Bangkok",
    "Asia/Beirut",
    "Asia/Calcutta",
    "Asia/Colombo",
    "Asia/Dubai",
    "Asia/Ho_Chi_Minh",
    "Asia/Hong_Kong",
    "Asia/Jakarta",
    "Asia/Jerusalem",
    "Asia/Karachi",
    "Asia/Kathmandu",
    "Asia/Kolkata",
    "Asia/Kuala_Lumpur",
    "Asia/Manila",
    "Asia/Riyadh",
    "Asia/Seoul",
    "Asia/Shanghai",
    "Asia/Singapore",
    "Asia/Taipei",
    "Asia/Tbilisi",
    "Asia/Tehran",
    "Asia/Tokyo",
    "Australia/Adelaide",
    "Australia/Brisbane",
    "Australia/Melbourne",
    "Australia/Perth",
    "Australia/Sydney",
    "Europe/Amsterdam",
    "Europe/Athens",
    "Europe/Berlin",
    "Europe/Brussels",
    "Europe/Bucharest",
    "Europe/Budapest",
    "Europe/Copenhagen",
    "Europe/Dublin",
    "Europe/Helsinki",
    "Europe/Istanbul",
    "Europe/Kiev",
    "Europe/Lisbon",
    "Europe/London",
    "Europe/Madrid",
    "Europe/Moscow",
    "Europe/Oslo",
    "Europe/Paris",
    "Europe/Prague",
    "Europe/Rome",
    "Europe/Stockholm",
    "Europe/Vienna",
    "Europe/Warsaw",
    "Pacific/Auckland",
    "Pacific/Fiji",
    "Pacific/Honolulu",
)


COUNTRY_CHOICES: Sequence[tuple[str, str]] = (
    ("US", "United States"),
    ("CA", "Canada"),
    ("MX", "Mexico"),
    ("BR", "Brazil"),
    ("AR", "Argentina"),
    ("GB", "United Kingdom"),
    ("IE", "Ireland"),
    ("FR", "France"),
    ("DE", "Germany"),
    ("ES", "Spain"),
    ("PT", "Portugal"),
    ("IT", "Italy"),
    ("NL", "Netherlands"),
    ("BE", "Belgium"),
    ("CH", "Switzerland"),
    ("AT", "Austria"),
    ("SE", "Sweden"),
    ("NO", "Norway"),
    ("DK", "Denmark"),
    ("FI", "Finland"),
    ("PL", "Poland"),
    ("CZ", "Czechia"),
    ("SK", "Slovakia"),
    ("HU", "Hungary"),
    ("RO", "Romania"),
    ("BG", "Bulgaria"),
    ("GR", "Greece"),
    ("TR", "Turkey"),
    ("RU", "Russia"),
    ("UA", "Ukraine"),
    ("CN", "China"),
    ("JP", "Japan"),
    ("KR", "South Korea"),
    ("TW", "Taiwan"),
    ("HK", "Hong Kong"),
    ("SG", "Singapore"),
    ("IN", "India"),
    ("PK", "Pakistan"),
    ("BD", "Bangladesh"),
    ("VN", "Vietnam"),
    ("TH", "Thailand"),
    ("PH", "Philippines"),
    ("ID", "Indonesia"),
    ("MY", "Malaysia"),
    ("AU", "Australia"),
    ("NZ", "New Zealand"),
    ("ZA", "South Africa"),
    ("NG", "Nigeria"),
    ("KE", "Kenya"),
    ("EG", "Egypt"),
)


@bp.route("/users/new", methods=["GET", "POST"])
def user_create():
    engine = get_user_engine()
    errors: List[str] = []
    form = {
        "email": "",
        "full_name": "",
        "preferred_name": "",
        "pronouns": "",
        "timezone": "America/Chicago",
    }
    selected_property_ids: List[int] = []
    csrf_token = _ensure_csrf_token()

    if engine is None:
        errors.append("User database is not configured.")
        return render_template(
            "admin/user_edit.html",
            form=form,
            errors=errors,
            csrf_token=csrf_token,
            is_edit=False,
            user_id=None,
            pronoun_options=PRONOUN_OPTIONS,
            timezone_options=TIMEZONE_OPTIONS,
            properties=[],
            selected_property_ids=selected_property_ids,
        )

    properties: List[Property] = []
    with Session(engine) as db:
        properties = db.query(Property).order_by(Property.name).all()

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")

        form["email"] = (request.form.get("email") or "").strip().lower()
        form["full_name"] = (request.form.get("full_name") or "").strip()
        form["preferred_name"] = (request.form.get("preferred_name") or "").strip()
        form["pronouns"] = (request.form.get("pronouns") or "").strip()
        form["timezone"] = (request.form.get("timezone") or "").strip()
        if not form["timezone"]:
            form["timezone"] = "America/Chicago"
        selected_property_ids = []
        for raw_id in request.form.getlist("property_ids"):
            try:
                selected_property_ids.append(int(raw_id))
            except ValueError:
                continue
        password = request.form.get("password") or ""
        password_confirm = request.form.get("password_confirm") or ""
        make_viewer = request.form.get("make_viewer") == "1"
        make_admin = request.form.get("make_admin") == "1"
        make_tech = request.form.get("make_tech") == "1"

        if not form["email"]:
            errors.append("Email is required.")
        if not password:
            errors.append("Password is required.")
        if password != password_confirm:
            errors.append("Passwords do not match.")

        created_user_id = None
        created_user_email = None

        if not errors:
            with Session(engine) as db:
                existing = (
                    db.query(User)
                    .filter(User.email == form["email"])
                    .first()
                )
                if existing is not None:
                    errors.append("A user with that email already exists.")
                else:
                    password_hash = _ph.hash(password)
                    user = User(
                        email=form["email"],
                        password_hash=password_hash,
                        full_name=form["full_name"] or None,
                        preferred_name=form["preferred_name"] or None,
                        pronouns=form["pronouns"] or None,
                        timezone=form["timezone"] or None,
                    )
                    db.add(user)
                    db.flush()

                    # Capture primitive identifiers for logging after the
                    # session is closed to avoid DetachedInstanceError on
                    # expired attributes.
                    created_user_id = int(user.id)
                    created_user_email = user.email

                    if make_viewer or make_admin or make_tech:
                        roles_to_apply: List[str] = []
                        if make_viewer:
                            roles_to_apply.append("Viewer")
                        if make_admin:
                            roles_to_apply.append("System Administrator")
                        if make_tech:
                            roles_to_apply.append("Technician")
                        for name in roles_to_apply:
                            role = db.scalar(select(Role).where(Role.name == name))
                            if role is None:
                                role = Role(
                                    name=name,
                                    scope="global",
                                    description=None,
                                )
                                db.add(role)
                                db.flush()
                            existing_link = (
                                db.query(UserRole)
                                .filter(
                                    UserRole.user_id == user.id,
                                    UserRole.role_id == role.id,
                                    UserRole.property_id.is_(None),
                                )
                                .first()
                            )
                            if existing_link is None:
                                db.add(
                                    UserRole(
                                        user_id=user.id,
                                        role_id=role.id,
                                        property_id=None,
                                    )
                                )

                    # Link the new user to any selected properties/households.
                    for prop_id in selected_property_ids:
                        existing_link = (
                            db.query(UserProperty)
                            .filter(
                                UserProperty.user_id == user.id,
                                UserProperty.property_id == prop_id,
                            )
                            .first()
                        )
                        if existing_link is None:
                            db.add(
                                UserProperty(
                                    user_id=user.id,
                                    property_id=prop_id,
                                )
                            )

                    db.commit()

            if created_user_id is not None and created_user_email is not None:
                actor = get_current_user()
                log_event(
                    "ADMIN_USER_CREATE",
                    user_id=actor.id if actor else None,
                    details=(
                        f"target_user_id={created_user_id}, "
                        f"email={created_user_email}"
                    ),
                )
            return redirect(url_for("admin.users_list"))

    return render_template(
        "admin/user_edit.html",
        form=form,
        errors=errors,
        csrf_token=csrf_token,
        is_edit=False,
        user_id=None,
        pronoun_options=PRONOUN_OPTIONS,
        timezone_options=TIMEZONE_OPTIONS,
        properties=properties,
        selected_property_ids=selected_property_ids,
    )


@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
def user_edit(user_id: int):
    engine = get_user_engine()
    errors: List[str] = []
    csrf_token = _ensure_csrf_token()

    if engine is None:
        errors.append("User database is not configured.")
        return render_template(
            "admin/user_edit.html",
            form=None,
            errors=errors,
            csrf_token=csrf_token,
            is_edit=True,
            user_id=user_id,
        )

    with Session(engine) as db:
        user = db.get(User, user_id)
        if user is None:
            errors.append("User not found.")
            return render_template(
                "admin/user_edit.html",
                form=None,
                errors=errors,
                csrf_token=csrf_token,
                is_edit=True,
                user_id=user_id,
            )

        form = {
            "email": user.email,
            "full_name": user.full_name or "",
            "preferred_name": user.preferred_name or "",
            "pronouns": user.pronouns or "",
            "timezone": user.timezone or "America/Chicago",
            "account_status": user.account_status or "",
        }

        if request.method == "POST":
            if not _validate_csrf_token(request.form.get("csrf_token")):
                errors.append("Invalid or missing CSRF token.")

            form["full_name"] = (request.form.get("full_name") or "").strip()
            form["preferred_name"] = (
                request.form.get("preferred_name") or ""
            ).strip()
            form["pronouns"] = (request.form.get("pronouns") or "").strip()
            form["timezone"] = (request.form.get("timezone") or "").strip()
            form["account_status"] = (
                request.form.get("account_status") or ""
            ).strip()

            if not errors:
                user.full_name = form["full_name"] or None
                user.preferred_name = form["preferred_name"] or None
                user.pronouns = form["pronouns"] or None
                user.timezone = form["timezone"] or None
                user.account_status = form["account_status"] or None
                db.add(user)
                db.commit()
                actor = get_current_user()
                log_event(
                    "ADMIN_USER_UPDATE",
                    user_id=actor.id if actor else None,
                    details=f"target_user_id={user.id}",
                )
                return redirect(url_for("admin.users_list"))

    return render_template(
        "admin/user_edit.html",
        form=form,
        errors=errors,
        csrf_token=csrf_token,
        is_edit=True,
        user_id=user_id,
        pronoun_options=PRONOUN_OPTIONS,
        timezone_options=TIMEZONE_OPTIONS,
    )


@bp.route("/users/<int:user_id>/password", methods=["GET", "POST"])
def user_password(user_id: int):
    engine = get_user_engine()
    errors: List[str] = []
    csrf_token = _ensure_csrf_token()

    if engine is None:
        errors.append("User database is not configured.")
        return render_template(
            "admin/user_password.html",
            errors=errors,
            csrf_token=csrf_token,
            user_id=user_id,
            email="",
        )

    with Session(engine) as db:
        user = db.get(User, user_id)
        if user is None:
            errors.append("User not found.")
            return render_template(
                "admin/user_password.html",
                errors=errors,
                csrf_token=csrf_token,
                user_id=user_id,
                email="",
            )

        email = user.email

        if request.method == "POST":
            if not _validate_csrf_token(request.form.get("csrf_token")):
                errors.append("Invalid or missing CSRF token.")

            password = request.form.get("password") or ""
            password_confirm = request.form.get("password_confirm") or ""
            if not password:
                errors.append("Password is required.")
            if password != password_confirm:
                errors.append("Passwords do not match.")

            if not errors:
                user.password_hash = _ph.hash(password)
                user.failed_logins = 0
                user.locked_until = None
                db.add(user)
                db.commit()
                actor = get_current_user()
                log_event(
                    "ADMIN_USER_PASSWORD_RESET",
                    user_id=actor.id if actor else None,
                    details=f"target_user_id={user.id}",
                )
                return redirect(url_for("admin.users_list"))

    return render_template(
        "admin/user_password.html",
        errors=errors,
        csrf_token=csrf_token,
        user_id=user_id,
        email=email,
    )


@bp.post("/users/<int:user_id>/delete")
def user_delete(user_id: int):
    engine = get_user_engine()
    if engine is None:
        return redirect(url_for("admin.users_list"))

    if not _validate_csrf_token(request.form.get("csrf_token")):
        return redirect(url_for("admin.users_list"))

    with Session(engine) as db:
        user = db.get(User, user_id)
        if user is None:
            return redirect(url_for("admin.users_list"))

        admin_role = db.scalar(select(Role).where(Role.name == "System Administrator"))
        if admin_role is not None:
            admin_ids = [
                ur.user_id
                for ur, r in db.query(UserRole, Role)
                .join(Role, Role.id == UserRole.role_id)
                .filter(Role.name == "System Administrator")
                .all()
            ]
            if len(admin_ids) <= 1 and user.id in admin_ids:
                return redirect(url_for("admin.users_list"))

        email = user.email
        db.query(UserRole).filter(UserRole.user_id == user.id).delete(
            synchronize_session=False
        )
        db.delete(user)
        db.commit()

        actor = get_current_user()
        log_event(
            "ADMIN_USER_DELETE",
            user_id=actor.id if actor else None,
            details=f"target_user_id={user_id}, email={email}",
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
            created_property_id = None
            created_property_name = None
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
                db.flush()
                created_property_id = prop.id
                created_property_name = prop.name
                db.commit()
            actor = get_current_user()
            log_event(
                "PROPERTY_CREATE",
                user_id=actor.id if actor else None,
                details=f"property_id={created_property_id}, name={created_property_name}",
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
