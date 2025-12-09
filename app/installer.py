import csv
import os
from pathlib import Path
from typing import Dict, List

from argon2 import PasswordHasher
from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from sqlalchemy import select
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .config import load_config
from .db import get_face_engine, get_record_engine, get_user_engine
from .models import (
    CameraUrlPattern,
    User,
    create_audit_schema,
    create_face_schema,
    create_record_schema,
    create_user_schema,
)
from .security import seed_system_admin_role_for_email


bp = Blueprint("installer", __name__)

_PH = PasswordHasher()


def _is_locked() -> bool:
    value = str(current_app.config.get("INSTALL_LOCKED", "")).lower()
    return value == "true"


def _project_root() -> Path:
    # app.root_path points at the "app" package; its parent is the project root
    return Path(current_app.root_path).parent


def _env_path() -> Path:
    return _project_root() / ".env"


def _load_form_defaults() -> Dict[str, str]:
    cfg = load_config()

    form: Dict[str, str] = {
        # User DB defaults
        "user_db_backend": "mysql",
        "user_db_host": "127.0.0.1",
        "user_db_port": "3306",
        "user_db_username": "",
        "user_db_password": "",
        "user_db_name": "users",
        "user_db_url": cfg.get("USER_DB_URL", ""),
        # Face DB defaults
        "face_db_backend": "mysql",
        "face_db_host": "127.0.0.1",
        "face_db_port": "3306",
        "face_db_username": "",
        "face_db_password": "",
        "face_db_name": "faces",
        "face_db_url": cfg.get("FACE_DB_URL", ""),
        # Record DB defaults
        "record_db_backend": "mysql",
        "record_db_host": "127.0.0.1",
        "record_db_port": "3306",
        "record_db_username": "",
        "record_db_password": "",
        "record_db_name": "records",
        "record_db_url": cfg.get("RECORD_DB_URL", ""),
    }

    def _apply_from_url(prefix: str, url_key: str, default_db: str) -> None:
        url = cfg.get(url_key, "")
        if not url:
            form[f"{prefix}_db_name"] = default_db
            return

        form[f"{prefix}_db_url"] = url
        try:
            parsed = make_url(url)
        except Exception:  # noqa: BLE001
            # Fall back to advanced URL mode
            form[f"{prefix}_db_backend"] = "url"
            return

        drivername = parsed.drivername or ""
        if drivername.startswith("mysql"):
            form[f"{prefix}_db_backend"] = "mysql"
        else:
            form[f"{prefix}_db_backend"] = "url"

        if parsed.host:
            form[f"{prefix}_db_host"] = parsed.host
        if parsed.port:
            form[f"{prefix}_db_port"] = str(parsed.port)
        if parsed.username:
            form[f"{prefix}_db_username"] = parsed.username
        if parsed.password:
            form[f"{prefix}_db_password"] = parsed.password
        if parsed.database:
            form[f"{prefix}_db_name"] = parsed.database

    _apply_from_url("user", "USER_DB_URL", "users")
    _apply_from_url("face", "FACE_DB_URL", "faces")
    _apply_from_url("record", "RECORD_DB_URL", "records")

    return form


def _build_mysql_url(
    host: str,
    port: str,
    username: str,
    password: str,
    database: str,
) -> str:
    driver = "mysql+pymysql"
    auth = ""
    if username or password:
        auth = f"{username}:{password}@"
    port_part = f":{port}" if port else ""
    return f"{driver}://{auth}{host}{port_part}/{database}"


def _build_db_url_from_form(
    form: Dict[str, str], prefix: str, label: str, errors: List[str]
) -> str:
    backend = (form.get(f"{prefix}_db_backend") or "mysql").strip()

    if backend == "url":
        url = (form.get(f"{prefix}_db_url") or "").strip()
        if not url:
            errors.append(f"{label} DB URL is required when using Other/URL mode.")
        return url

    host = (form.get(f"{prefix}_db_host") or "").strip()
    port = (form.get(f"{prefix}_db_port") or "").strip()
    username = (form.get(f"{prefix}_db_username") or "").strip()
    password = (form.get(f"{prefix}_db_password") or "").strip()
    database = (form.get(f"{prefix}_db_name") or "").strip()

    if not host:
        errors.append(f"{label} DB host/IP is required.")
    if not database:
        errors.append(f"{label} DB name is required.")

    if errors:
        return ""

    # For now, the structured mode always uses MySQL/MariaDB via PyMySQL.
    return _build_mysql_url(host, port, username, password, database)


def _write_env(vars_to_write: Dict[str, str]) -> None:
    env_file = _env_path()
    lines: List[str] = []

    # Preserve existing keys that we are not overwriting
    if env_file.exists():
        existing = {}
        for line in env_file.read_text().splitlines():
            if not line or line.strip().startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            existing[key] = value
        for key, value in existing.items():
            if key not in vars_to_write:
                lines.append(f"{key}={value}")

    for key, value in vars_to_write.items():
        lines.append(f"{key}={value}")

    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _ensure_csrf_token() -> str:
    token = session.get("installer_csrf")
    if not token:
        import secrets

        token = secrets.token_urlsafe(32)
        session["installer_csrf"] = token
    return token


def _validate_csrf_token(token: str | None) -> bool:
    if not token:
        return False
    return token == session.get("installer_csrf")


def _get_install_access_code() -> str | None:
    value = str(current_app.config.get("INSTALL_ACCESS_CODE", "")).strip()
    return value or None


def _has_install_access() -> bool:
    code = _get_install_access_code()
    if not code:
        return True
    return bool(session.get("installer_access_granted"))


def _is_secure_install_request() -> bool:
    if current_app.debug:
        return True
    if request.is_secure:
        return True
    forwarded = request.headers.get("X-Forwarded-Proto", "").lower()
    if "https" in forwarded:
        return True
    return False


def _init_databases(errors: List[str]) -> None:
    for label, getter, creator in (
        ("User", get_user_engine, create_user_schema),
        ("Face", get_face_engine, create_face_schema),
        ("Record", get_record_engine, create_record_schema),
    ):
        engine = getter()
        if engine is None:
            errors.append(f"{label} database URL is not configured.")
            continue
        try:
            creator(engine)
            if label == "User":
                create_audit_schema(engine)
            if label == "Record":
                _import_camera_url_patterns(errors)
        except SQLAlchemyError as exc:  # noqa: TRY003
            errors.append(f"{label} database initialization failed: {exc}")


def _import_camera_url_patterns(errors: List[str]) -> None:
    """Import cameraurl.csv into the RecordDB if the table is empty.

    This runs during installer DB initialization and is safe to call multiple
    times; if rows already exist, the import is skipped.
    """

    engine = get_record_engine()
    if engine is None:
        return

    csv_path = _project_root() / "cameraurl.csv"
    if not csv_path.exists():
        return

    try:
        with Session(engine) as session_db:
            # Skip import if data already present
            existing = session_db.query(CameraUrlPattern).first()
            if existing is not None:
                return

            with csv_path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    manufacturer = (
                        row.get("manufacturer") or ""
                    ).strip()
                    rtsp_pattern = (
                        row.get("rtsp_url_pattern") or ""
                    ).strip()
                    if not manufacturer or not rtsp_pattern:
                        continue
                    # Infer protocol from the URL scheme; default to RTSP.
                    lower = rtsp_pattern.lower()
                    if "://" in lower:
                        proto = lower.split("://", 1)[0]
                    else:
                        proto = "rtsp"
                    protocol = {
                        "rtsp": "RTSP",
                        "rtmp": "RTMP",
                        "srt": "SRT",
                        "rist": "RIST",
                        "http": "HTTP",
                        "https": "HTTPS",
                    }.get(proto, "RTSP")

                    pattern = CameraUrlPattern(
                        manufacturer=manufacturer,
                        model_or_note=(
                            row.get("model_or_note") or ""
                        ).strip()
                        or None,
                        protocol=protocol,
                        rtsp_url_pattern=rtsp_pattern,
                        is_active=1,
                    )
                    session_db.add(pattern)
                session_db.commit()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Camera URL import failed: {exc}")


@bp.route("/", methods=["GET", "POST"])
def install():
    if _is_locked():
        return render_template("install/locked.html"), 403

    if not _is_secure_install_request():
        return render_template("install/https_required.html"), 400

    if not _has_install_access():
        return redirect(url_for("installer.access"))

    errors: List[str] = []
    form = _load_form_defaults()
    csrf_token = _ensure_csrf_token()

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")

        # Capture posted form fields so they can be redisplayed on error.
        for prefix in ("user", "face", "record"):
            form[f"{prefix}_db_backend"] = (
                request.form.get(f"{prefix}_db_backend") or "mysql"
            ).strip()
            form[f"{prefix}_db_host"] = (
                request.form.get(f"{prefix}_db_host") or ""
            ).strip()
            form[f"{prefix}_db_port"] = (
                request.form.get(f"{prefix}_db_port") or ""
            ).strip()
            form[f"{prefix}_db_username"] = (
                request.form.get(f"{prefix}_db_username") or ""
            ).strip()
            form[f"{prefix}_db_password"] = (
                request.form.get(f"{prefix}_db_password") or ""
            ).strip()
            form[f"{prefix}_db_name"] = (
                request.form.get(f"{prefix}_db_name") or ""
            ).strip()
            form[f"{prefix}_db_url"] = (
                request.form.get(f"{prefix}_db_url") or ""
            ).strip()

        # Build SQLAlchemy URLs from structured fields.
        user_db_url = _build_db_url_from_form(form, "user", "User", errors)
        face_db_url = _build_db_url_from_form(form, "face", "Face", errors)
        record_db_url = _build_db_url_from_form(form, "record", "Record", errors)

        form["user_db_url"] = user_db_url
        form["face_db_url"] = face_db_url
        form["record_db_url"] = record_db_url

        if not errors:
            secret = (
                os.getenv("APP_SECRET_KEY")
                or current_app.config.get("SECRET_KEY")
                or "change-me"
            )
            if not secret or secret == "change-me":
                # Lazy import to avoid unnecessary dependency if not used elsewhere
                import secrets

                secret = secrets.token_urlsafe(32)

            _write_env(
                {
                    "APP_SECRET_KEY": secret,
                    "USER_DB_URL": form["user_db_url"],
                    "FACE_DB_URL": form["face_db_url"],
                    "RECORD_DB_URL": form["record_db_url"],
                }
            )

            # Refresh process environment and Flask config for this run
            os.environ.update(
                {
                    "APP_SECRET_KEY": secret,
                    "USER_DB_URL": form["user_db_url"],
                    "FACE_DB_URL": form["face_db_url"],
                    "RECORD_DB_URL": form["record_db_url"],
                }
            )
            current_app.config.from_mapping(load_config())

            _init_databases(errors)

            if not errors:
                return render_template(
                    "install/step1.html",
                    form=form,
                    errors=errors,
                    saved=True,
                    csrf_token=csrf_token,
                    next_step_url="/install/admin",
                )

    return render_template(
        "install/step1.html",
        form=form,
        errors=errors,
        saved=False,
        csrf_token=csrf_token,
        next_step_url="/install/admin",
    )


@bp.route("/access", methods=["GET", "POST"])
def access():
    if _is_locked():
        return render_template("install/locked.html"), 403

    if not _is_secure_install_request():
        return render_template("install/https_required.html"), 400

    if _has_install_access():
        return redirect(url_for("installer.install"))

    errors: List[str] = []
    csrf_token = _ensure_csrf_token()
    access_code = _get_install_access_code()

    if access_code is None:
        session["installer_access_granted"] = True
        return redirect(url_for("installer.install"))

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")

        submitted = (request.form.get("access_code") or "").strip()
        if not submitted:
            errors.append("Access code is required.")
        elif not errors and submitted != access_code:
            errors.append("Access code is incorrect.")

        if not errors:
            session["installer_access_granted"] = True
            return redirect(url_for("installer.install"))

    return render_template(
        "install/access.html",
        errors=errors,
        csrf_token=csrf_token,
    )


@bp.route("/admin", methods=["GET", "POST"])
def admin_step():
    if _is_locked():
        return render_template("install/locked.html"), 403

    if not _is_secure_install_request():
        return render_template("install/https_required.html"), 400

    if not _has_install_access():
        return redirect(url_for("installer.access"))

    errors: List[str] = []
    form = {"email": "", "password": "", "password_confirm": ""}
    csrf_token = _ensure_csrf_token()

    engine = get_user_engine()
    if engine is None:
        errors.append("User database is not configured.")
        return render_template(
            "install/admin.html",
            form=form,
            errors=errors,
            saved=False,
            csrf_token=csrf_token,
        )

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")
        form["email"] = (request.form.get("email") or "").strip().lower()
        form["password"] = request.form.get("password") or ""
        form["password_confirm"] = request.form.get("password_confirm") or ""

        if not form["email"]:
            errors.append("Email is required.")
        if not form["password"]:
            errors.append("Password is required.")
        if form["password"] != form["password_confirm"]:
            errors.append("Passwords do not match.")

        if not errors:
            with Session(engine) as session_db:
                existing_admin = session_db.scalar(
                    select(User).where(User.email == form["email"])
                )
                if existing_admin is not None:
                    errors.append("An account with this email already exists.")
                else:
                    password_hash = _PH.hash(form["password"])
                    user = User(email=form["email"], password_hash=password_hash)
                    session_db.add(user)
                    session_db.commit()

                    # Ensure core RBAC roles exist and grant System Administrator
                    # to this initial admin account (and to Thalia if this email
                    # matches her address).
                    seed_system_admin_role_for_email(user.email)

                    _write_env({"INSTALL_LOCKED": "true"})
                    os.environ["INSTALL_LOCKED"] = "true"
                    current_app.config["INSTALL_LOCKED"] = "true"

                    return render_template(
                        "install/admin.html",
                        form=form,
                        errors=errors,
                        saved=True,
                        csrf_token=csrf_token,
                    )

    return render_template(
        "install/admin.html",
        form=form,
        errors=errors,
        saved=False,
        csrf_token=csrf_token,
    )
