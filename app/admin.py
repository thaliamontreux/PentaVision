from __future__ import annotations

import secrets
import subprocess
from datetime import datetime, timezone
import json
import os
import uuid
from urllib.request import urlopen

from typing import Dict, List, Sequence, Set

from argon2 import PasswordHasher
from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.routing import BuildError
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .db import get_user_engine
from .logging_utils import log_event, _client_ip
from .models import (
    BlocklistDistributionSettings,
    CountryAccessPolicy,
    IpAllowlist,
    IpBlocklist,
    Property,
    PropertyGroup,
    PropertyZone,
    Role,
    AuditEvent,
    User,
    UserPropertyAccessWindow,
    UserProperty,
    UserPropertyGroupScope,
    UserPropertyRoleOverride,
    UserPropertyZoneLink,
    PropertyScheduleTemplate,
    PropertyScheduleTemplateWindow,
    UserPropertyScheduleAssignment,
    PropertyGroupScheduleAssignment,
    UserRole,
)
from .security import get_current_user, user_has_role
from .storage_settings_page import storage_settings_page


def _pid_is_running(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        n = int(pid)
    except Exception:
        return False
    if n <= 0:
        return False
    try:
        # Signal 0 does not kill the process; it only checks for existence/permission.
        os.kill(n, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # If we can't signal it, but it exists, treat as running.
        return True
    except Exception:
        return False


bp = Blueprint("admin", __name__, url_prefix="/admin")
_ph = PasswordHasher()


def _git_pull_runs_dir() -> str:
    base = os.environ.get("PENTAVISION_RUN_LOG_DIR") or "/tmp/pentavision"
    out = os.path.join(str(base), "git_pull_runs")
    try:
        os.makedirs(out, exist_ok=True)
    except Exception:
        pass
    return out


def _git_pull_paths(run_id: str) -> tuple[str, str]:
    safe_id = str(run_id or "").strip()
    safe_id = safe_id.replace("/", "").replace("\\", "")
    base = _git_pull_runs_dir()
    meta_path = os.path.join(base, f"{safe_id}.json")
    log_path = os.path.join(base, f"{safe_id}.log")
    return meta_path, log_path


def _read_text_tail(path: str, *, offset: int, max_bytes: int = 64 * 1024) -> tuple[str, int]:
    try:
        size = os.path.getsize(path)
    except Exception:
        size = 0
    if size <= 0:
        return "", int(offset or 0)

    start = max(0, int(offset or 0))
    if start > size:
        start = size

    try:
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read(int(max_bytes))
    except Exception:
        return "", start

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    return text, start + len(data)


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
    csrf_token = _ensure_csrf_token()
    git_pull_start_url = ""
    try:
        git_pull_start_url = url_for("admin.git_pull_start")
    except BuildError:
        git_pull_start_url = ""
    return render_template(
        "admin/index.html",
        csrf_token=csrf_token,
        git_pull_start_url=git_pull_start_url,
    )


@bp.post("/git-pull/start")
def git_pull_start():
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)

    run_id = uuid.uuid4().hex
    meta_path, log_path = _git_pull_paths(run_id)

    app_root = os.path.abspath(os.path.join(current_app.root_path, os.pardir))
    script_path = os.path.join(app_root, "scripts", "git_pull.sh")

    try:
        with open(log_path, "wb") as logf:
            logf.write(
                (
                    f"== PentaVision git pull run {run_id} ==\n"
                    f"started_utc={datetime.now(timezone.utc).isoformat()}\n"
                    f"script={script_path}\n\n"
                ).encode("utf-8")
            )
            logf.flush()

            proc = subprocess.Popen(  # noqa: S603
                ["bash", script_path],
                cwd=app_root,
                stdout=logf,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"failed_to_start: {type(exc).__name__}"}), 500

    meta = {
        "run_id": run_id,
        "pid": int(proc.pid),
        "log_path": log_path,
        "started_utc": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f)
    except Exception:
        pass

    try:
        log_event(
            "ADMIN_GIT_PULL_START",
            user_id=getattr(get_current_user(), "id", None),
            details=f"run_id={run_id}, ip={_client_ip()}",
        )
    except Exception:
        pass

    return jsonify({"ok": True, "run_id": run_id, "view_url": url_for("admin.git_pull_view", run_id=run_id)})


@bp.get("/git-pull/view/<run_id>")
def git_pull_view(run_id: str):
    csrf_token = _ensure_csrf_token()
    safe_run_id = str(run_id or "").strip()
    return (
        "<!doctype html>"
        "<html lang=\"en\">"
        "<head>"
        "  <meta charset=\"utf-8\">"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "  <title>PentaVision · Git Pull Output</title>"
        "  <style>"
        "    body{margin:0;background:#050b14;color:#e5e7eb;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}"
        "    .top{position:sticky;top:0;padding:10px 12px;background:rgba(255,255,255,0.06);border-bottom:1px solid rgba(255,255,255,0.12);backdrop-filter:blur(12px);}"
        "    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace;}"
        "    .btn{display:inline-flex;align-items:center;gap:8px;padding:8px 10px;border-radius:10px;border:1px solid rgba(255,255,255,0.16);background:rgba(255,255,255,0.08);color:#e5e7eb;font-weight:800;cursor:pointer;}"
        "    .btn:hover{border-color:rgba(34,211,238,0.55);}"
        "    pre{margin:0;padding:12px;white-space:pre-wrap;word-break:break-word;}"
        "  </style>"
        "</head>"
        "<body>"
        f"<div class=\"top\"><strong>Git Pull</strong> <span class=\"mono\">{safe_run_id}</span> "
        "<button class=\"btn\" id=\"pvCopy\" type=\"button\">Copy</button>"
        "<span id=\"pvStatus\" style=\"margin-left:10px;opacity:.8\">starting...</span>"
        "</div>"
        f"<pre id=\"pvOut\" class=\"mono\" data-run=\"{safe_run_id}\" data-csrf=\"{csrf_token}\"></pre>"
        "<script>"
        "(function(){"
        "  const pre=document.getElementById('pvOut');"
        "  const statusEl=document.getElementById('pvStatus');"
        "  const runId=pre.getAttribute('data-run');"
        "  const csrf=pre.getAttribute('data-csrf');"
        "  let offset=0;"
        "  async function poll(){"
        "    try{"
        "      const url='/admin/git-pull/poll/'+encodeURIComponent(runId)+'?offset='+offset;"
        "      const r=await fetch(url,{cache:'no-store',headers:{'X-CSRF-Token':csrf}});"
        "      const data=await r.json();"
        "      if(data && data.append){pre.textContent+=data.append;offset=data.offset||offset;}"
        "      statusEl.textContent=(data && data.running)?'running...':'finished';"
        "      if(data && data.running){setTimeout(poll,1000);}"
        "    }catch(e){statusEl.textContent='error';setTimeout(poll,2000);}"
        "  }"
        "  document.getElementById('pvCopy').addEventListener('click', async function(){"
        "    try{await navigator.clipboard.writeText(pre.textContent||'');}catch(e){}"
        "  });"
        "  poll();"
        "})();"
        "</script>"
        "</body>"
        "</html>"
    )


@bp.get("/git-pull/poll/<run_id>")
def git_pull_poll(run_id: str):
    # Lightweight CSRF: require header token matching admin session.
    if not _validate_csrf_token(request.headers.get("X-CSRF-Token")):
        abort(400)

    meta_path, log_path = _git_pull_paths(run_id)
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception:
        meta = {"pid": None, "log_path": log_path}

    pid = meta.get("pid")
    running = _pid_is_running(pid)

    try:
        offset = int(request.args.get("offset") or 0)
    except Exception:
        offset = 0

    append, new_offset = _read_text_tail(str(meta.get("log_path") or log_path), offset=offset)
    return jsonify({"ok": True, "run_id": run_id, "running": bool(running), "append": append, "offset": int(new_offset)})


@bp.get("/recordings")
def recordings_alias():
    """Admin-scoped alias for the main recordings view."""
    return redirect(url_for("main.recordings"))


@bp.route("/storage", methods=["GET", "POST"])
def storage_settings():
    return storage_settings_page()


@bp.get("/recording-settings")
def recording_settings_alias():
    """Admin-scoped alias for the main recording settings view."""
    return redirect(url_for("main.recording_settings"))


@bp.get("/audit")
def audit_alias():
    """Admin-scoped alias for the main audit log view."""
    return redirect(url_for("main.audit_events"))


def _systemctl_available() -> bool:
    try:
        subprocess.run(
            ["systemctl", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        return True
    except Exception:  # noqa: BLE001
        return False


def _systemctl_status(service: str) -> tuple[str, str]:
    try:
        active = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        active = "unknown"

    try:
        enabled = subprocess.run(
            ["systemctl", "is-enabled", service],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        enabled = "unknown"

    return active or "unknown", enabled or "unknown"


def _systemctl_restart(service: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["systemctl", "restart", service],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        if proc.returncode == 0:
            return True, ""
        msg = (proc.stderr or proc.stdout or "restart failed").strip()
        return False, msg
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _fetch_blocklist_health() -> str:
    try:
        with urlopen("http://127.0.0.1:7080/healthz", timeout=3) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return (raw or "").strip() or "unknown"
    except Exception as exc:  # noqa: BLE001
        return f"not_ok: {type(exc).__name__}"


def _fetch_blocklist_count() -> int:
    try:
        with urlopen("http://127.0.0.1:7080/blocklist.csv", timeout=5) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        lines = [ln for ln in (raw or "").splitlines() if ln.strip()]
        if not lines:
            return 0
        # Header + rows
        return max(0, len(lines) - 1)
    except Exception:  # noqa: BLE001
        return 0


def _public_blocklist_base_url() -> str:
    # Prefer forwarded headers when running behind Apache/Nginx.
    host = (
        request.headers.get("X-Forwarded-Host")
        or request.headers.get("Host")
        or request.host
        or "127.0.0.1"
    )
    # If multiple hosts are present (comma-separated), use the first.
    host = host.split(",")[0].strip()
    host_no_port = host.split(":")[0].strip() or "127.0.0.1"

    scheme = (
        request.headers.get("X-Forwarded-Proto")
        or request.headers.get("X-Forwarded-Scheme")
        or request.scheme
        or "http"
    )
    scheme = scheme.split(",")[0].strip() or "http"
    return f"{scheme}://{host_no_port}:7080"


@bp.route("/blocklist-distribution", methods=["GET", "POST"])
def blocklist_distribution():
    engine = get_user_engine()
    errors: List[str] = []
    messages: List[str] = []
    csrf_token = _ensure_csrf_token()

    if engine is None:
        errors.append("User database is not configured.")
        settings = BlocklistDistributionSettings(
            enabled=1,
            consumer_allow_cidrs="",
            token_enabled=0,
            token="",
            ttl_seconds=5,
            rate_limit_per_min=60,
        )
    else:
        with Session(engine) as db:
            BlocklistDistributionSettings.__table__.create(bind=engine, checkfirst=True)
            settings = db.query(BlocklistDistributionSettings).order_by(BlocklistDistributionSettings.id.desc()).first()
            if settings is None:
                settings = BlocklistDistributionSettings(
                    enabled=1,
                    consumer_allow_cidrs="",
                    token_enabled=0,
                    token="",
                    ttl_seconds=5,
                    rate_limit_per_min=60,
                )
                db.add(settings)
                db.commit()

            # Ensure settings is safe to use outside this Session (templates).
            try:
                db.refresh(settings)
                db.expunge(settings)
            except Exception:  # noqa: BLE001
                pass

            if request.method == "POST":
                if not _validate_csrf_token(request.form.get("csrf_token")):
                    errors.append("Invalid or missing CSRF token.")
                else:
                    action = (request.form.get("action") or "").strip()
                    if action == "save":
                        enabled = 1 if request.form.get("enabled") else 0
                        token_enabled = 1 if request.form.get("token_enabled") else 0
                        consumer_allow_cidrs = (request.form.get("consumer_allow_cidrs") or "").strip()
                        token = (request.form.get("token") or "").strip()

                        try:
                            ttl_seconds = int((request.form.get("ttl_seconds") or "5").strip())
                        except ValueError:
                            ttl_seconds = 5
                        try:
                            rate_limit_per_min = int((request.form.get("rate_limit_per_min") or "60").strip())
                        except ValueError:
                            rate_limit_per_min = 60

                        settings.enabled = enabled
                        settings.consumer_allow_cidrs = consumer_allow_cidrs
                        settings.token_enabled = token_enabled
                        settings.token = token
                        settings.ttl_seconds = max(0, min(ttl_seconds, 60))
                        settings.rate_limit_per_min = max(1, min(rate_limit_per_min, 10000))
                        settings.updated_at = datetime.now(timezone.utc)
                        db.commit()

                        try:
                            db.refresh(settings)
                            db.expunge(settings)
                        except Exception:  # noqa: BLE001
                            pass

                        actor = get_current_user()
                        log_event(
                            "BLOCKLIST_DISTRIBUTION_SETTINGS_UPDATE",
                            user_id=actor.id if actor else None,
                            details=f"enabled={enabled}, token_enabled={token_enabled}",
                        )
                        messages.append("Blocklist Distribution settings saved.")
                    elif action == "rotate_token":
                        settings.token = secrets.token_urlsafe(32)
                        settings.token_enabled = 1
                        settings.updated_at = datetime.now(timezone.utc)
                        db.commit()

                        try:
                            db.refresh(settings)
                            db.expunge(settings)
                        except Exception:  # noqa: BLE001
                            pass
                        actor = get_current_user()
                        log_event(
                            "BLOCKLIST_DISTRIBUTION_TOKEN_ROTATE",
                            user_id=actor.id if actor else None,
                            details="token_rotated=1",
                        )
                        messages.append("Bearer token rotated.")
                    elif action == "restart_blocklist":
                        if not _systemctl_available():
                            errors.append("systemctl is not available on this host.")
                        else:
                            ok, msg = _systemctl_restart("pentavision-blocklist.service")
                            actor = get_current_user()
                            log_event(
                                "ADMIN_SERVICE_RESTART",
                                user_id=actor.id if actor else None,
                                details="service=pentavision-blocklist.service",
                            )
                            if ok:
                                messages.append("Blocklist service restart requested.")
                            else:
                                errors.append(f"Restart failed: {msg}")

            # If any action committed after the initial detach, make sure we
            # still have a detached instance for templates.
            try:
                if getattr(settings, "id", None) is not None:
                    db.refresh(settings)
                    db.expunge(settings)
            except Exception:  # noqa: BLE001
                pass

    base_url = _public_blocklist_base_url()
    root_url = f"{base_url}/"
    csv_url = f"{base_url}/blocklist.csv"
    health_url = f"{base_url}/healthz"
    health_text = _fetch_blocklist_health()
    published_count = _fetch_blocklist_count()

    return render_template(
        "admin/blocklist_distribution.html",
        errors=errors,
        messages=messages,
        csrf_token=csrf_token,
        settings=settings,
        root_url=root_url,
        csv_url=csv_url,
        health_url=health_url,
        health_text=health_text,
        published_count=published_count,
    )


@bp.route("/services", methods=["GET", "POST"])
def services():
    errors: List[str] = []
    messages: List[str] = []
    csrf_token = _ensure_csrf_token()

    allowed_services = [
        "pentavision-web.service",
        "pentavision-video.service",
        "pentavision-logserver.service",
        "pentavision-blocklist.service",
    ]

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")
        else:
            action = (request.form.get("action") or "").strip()
            target = (request.form.get("service") or "").strip()
            if action == "restart" and target in allowed_services:
                if not _systemctl_available():
                    errors.append("systemctl is not available on this host.")
                else:
                    ok, msg = _systemctl_restart(target)
                    actor = get_current_user()
                    log_event(
                        "ADMIN_SERVICE_RESTART",
                        user_id=actor.id if actor else None,
                        details=f"service={target}",
                    )
                    if ok:
                        messages.append(f"Restart requested: {target}")
                    else:
                        errors.append(f"Restart failed for {target}: {msg}")
            elif action:
                abort(400)

    services_rows = []
    for name in allowed_services:
        if _systemctl_available():
            active_state, enabled_state = _systemctl_status(name)
        else:
            active_state, enabled_state = "unknown", "unknown"
        services_rows.append(
            {
                "name": name,
                "active_state": active_state,
                "enabled_state": enabled_state,
            }
        )

    return render_template(
        "admin/services.html",
        errors=errors,
        messages=messages,
        csrf_token=csrf_token,
        services=services_rows,
    )


@bp.get("/blocklist-audit")
def blocklist_audit():
    engine = get_user_engine()
    errors: List[str] = []
    events: List[AuditEvent] = []

    q = (request.args.get("q") or "").strip()
    event_type = (request.args.get("event_type") or "").strip()
    ip = (request.args.get("ip") or "").strip()
    limit = 300

    if engine is None:
        errors.append("User database is not configured.")
    else:
        with Session(engine) as db:
            AuditEvent.__table__.create(bind=engine, checkfirst=True)
            qry = db.query(AuditEvent)

            # Focus on blocklist distribution + related control-plane events.
            type_prefixes = (
                "BLOCKLIST_",
                "BLOCKLIST_DISTRIBUTION_",
                "ADMIN_SERVICE_RESTART",
            )

            qry = qry.filter(
                or_(
                    *[
                        AuditEvent.event_type.like(f"{p}%")
                        for p in type_prefixes
                    ]
                )
            )

            if event_type:
                qry = qry.filter(AuditEvent.event_type == event_type)
            if ip:
                qry = qry.filter(AuditEvent.ip == ip)
            if q:
                like = f"%{q}%"
                qry = qry.filter(or_(AuditEvent.details.like(like), AuditEvent.ip.like(like)))

            events = qry.order_by(AuditEvent.when.desc()).limit(limit).all()

            event_types = (
                db.query(AuditEvent.event_type)
                .filter(
                    or_(
                        *[
                            AuditEvent.event_type.like(f"{p}%")
                            for p in type_prefixes
                        ]
                    )
                )
                .distinct()
                .order_by(AuditEvent.event_type)
                .all()
            )

    return render_template(
        "admin/blocklist_audit.html",
        errors=errors,
        events=events,
        q=q,
        event_type=event_type,
        ip=ip,
        limit=limit,
        event_types=[t[0] for t in (event_types or [])],
    )


@bp.get("/blocklist-integration")
def blocklist_integration():
    csv_url = f"{_public_blocklist_base_url()}/blocklist.csv"
    return render_template(
        "admin/blocklist_integration.html",
        csv_url=csv_url,
    )


@bp.route("/access-control", methods=["GET", "POST"])
def access_control():
    engine = get_user_engine()
    errors: List[str] = []
    messages: List[str] = []
    ip_allow: List[IpAllowlist] = []
    ip_block: List[IpBlocklist] = []
    policy = None
    csrf_token = _ensure_csrf_token()
    current_ip = _client_ip()
    current_ip_is_allowlisted = False

    if engine is None:
        errors.append("User database is not configured.")
    else:
        with Session(engine) as db:
            IpAllowlist.__table__.create(bind=engine, checkfirst=True)
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            CountryAccessPolicy.__table__.create(bind=engine, checkfirst=True)

            # On first use, preload common private LAN ranges into the
            # allowlist so that typical RFC1918 networks are exempted by
            # default. If any allowlist entries already exist, we assume an
            # administrator has configured the list and do not modify it.
            allow_count = db.query(IpAllowlist).count()
            if allow_count == 0:
                defaults = (
                    ("10.0.0.0/8", "Private LAN (RFC1918 10.0.0.0/8)"),
                    ("172.16.0.0/12", "Private LAN (RFC1918 172.16.0.0/12)"),
                    ("192.168.0.0/16", "Private LAN (RFC1918 192.168.0.0/16)"),
                )
                for cidr, description in defaults:
                    entry = IpAllowlist(cidr=cidr, description=description)
                    db.add(entry)
                db.commit()

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
                    elif action == "exempt_ip":
                        ip = (current_ip or "").strip()
                        if not ip:
                            messages.append("Could not determine client IP address.")
                        else:
                            existing = (
                                db.query(IpAllowlist)
                                .filter(IpAllowlist.cidr == ip)
                                .first()
                            )
                            if existing is None:
                                entry = IpAllowlist(
                                    cidr=ip,
                                    description="Exempted via access-control helper",
                                )
                                db.add(entry)
                                db.commit()
                                actor = get_current_user()
                                log_event(
                                    "ADMIN_IP_ALLOWLIST_EXEMPT_SELF",
                                    user_id=actor.id if actor else None,
                                    details=f"ip={ip}",
                                )
                                messages.append("Current IP has been exempted.")
                            else:
                                messages.append("Current IP is already exempted.")
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

            if current_ip:
                current_ip_is_allowlisted = any(
                    entry.cidr == current_ip for entry in ip_allow
                )

    return render_template(
        "admin/access_control.html",
        errors=errors,
        messages=messages,
        csrf_token=csrf_token,
        ip_allow=ip_allow,
        ip_block=ip_block,
        policy=policy,
        current_ip=current_ip,
        current_ip_is_allowlisted=current_ip_is_allowlisted,
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


@bp.get("/properties/<int:property_id>/workspace")
def property_workspace(property_id: int):
    engine = get_user_engine()
    errors: List[str] = []
    csrf_token = _ensure_csrf_token()
    tab = (request.args.get("tab") or "zones").strip().lower()
    if tab not in {"zones", "camera_scopes", "access_windows", "role_overrides"}:
        tab = "zones"

    if engine is None:
        errors.append("User database is not configured.")
        return render_template(
            "admin/property_workspace.html",
            errors=errors,
            csrf_token=csrf_token,
            property_id=property_id,
            prop=None,
            tab=tab,
            zones=[],
            groups=[],
            roles=[],
            users=[],
            zone_memberships={},
            access_windows_by_user={},
            group_scopes={},
            role_overrides={},
            templates=[],
            template_windows_by_template={},
            user_schedule_assignment={},
            group_schedule_assignment={},
            user_links={},
        )

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        if prop is None:
            errors.append("Property not found.")
            return render_template(
                "admin/property_workspace.html",
                errors=errors,
                csrf_token=csrf_token,
                property_id=property_id,
                prop=None,
                tab=tab,
                zones=[],
                groups=[],
                roles=[],
                users=[],
                zone_memberships={},
                access_windows_by_user={},
                group_scopes={},
                role_overrides={},
                templates=[],
                template_windows_by_template={},
                user_schedule_assignment={},
                group_schedule_assignment={},
                user_links={},
            )

        zones = (
            db.query(PropertyZone)
            .filter(PropertyZone.property_id == property_id)
            .order_by(PropertyZone.name)
            .all()
        )
        groups = (
            db.query(PropertyGroup)
            .filter(PropertyGroup.property_id == property_id)
            .order_by(PropertyGroup.name)
            .all()
        )
        roles = db.query(Role).order_by(Role.name).all()
        users = db.query(User).order_by(User.email).all()

        links = (
            db.query(UserProperty)
            .filter(UserProperty.property_id == property_id)
            .all()
        )
        user_links: Dict[int, UserProperty] = {link.user_id: link for link in links}

        zone_rows = (
            db.query(UserPropertyZoneLink.user_id, UserPropertyZoneLink.zone_id)
            .filter(UserPropertyZoneLink.property_id == property_id)
            .all()
        )
        zone_memberships: Dict[int, set[int]] = {}
        for user_id, zone_id in zone_rows:
            zone_memberships.setdefault(int(user_id), set()).add(int(zone_id))

        aw_rows = (
            db.query(UserPropertyAccessWindow)
            .filter(UserPropertyAccessWindow.property_id == property_id)
            .order_by(UserPropertyAccessWindow.user_id, UserPropertyAccessWindow.id)
            .all()
        )
        access_windows_by_user: Dict[int, List[UserPropertyAccessWindow]] = {}
        for w in aw_rows:
            access_windows_by_user.setdefault(int(w.user_id), []).append(w)

        scope_rows = (
            db.query(UserPropertyGroupScope.user_id, UserPropertyGroupScope.property_group_id)
            .filter(UserPropertyGroupScope.property_id == property_id)
            .all()
        )
        group_scopes: Dict[int, set[int]] = {}
        for uid, gid in scope_rows:
            group_scopes.setdefault(int(uid), set()).add(int(gid))

        override_rows = (
            db.query(UserPropertyRoleOverride.user_id, UserPropertyRoleOverride.role_id)
            .filter(UserPropertyRoleOverride.property_id == property_id)
            .all()
        )
        role_overrides: Dict[int, set[int]] = {}
        for uid, rid in override_rows:
            role_overrides.setdefault(int(uid), set()).add(int(rid))

        templates = (
            db.query(PropertyScheduleTemplate)
            .filter(PropertyScheduleTemplate.property_id == property_id)
            .order_by(PropertyScheduleTemplate.name)
            .all()
        )
        template_windows = (
            db.query(PropertyScheduleTemplateWindow)
            .filter(
                PropertyScheduleTemplateWindow.template_id.in_([t.id for t in templates])
                if templates
                else False
            )
            .order_by(PropertyScheduleTemplateWindow.template_id, PropertyScheduleTemplateWindow.id)
            .all()
        )
        template_windows_by_template: Dict[int, List[PropertyScheduleTemplateWindow]] = {}
        for w in template_windows:
            template_windows_by_template.setdefault(int(w.template_id), []).append(w)

        user_assignment_rows = (
            db.query(UserPropertyScheduleAssignment.user_id, UserPropertyScheduleAssignment.template_id)
            .filter(UserPropertyScheduleAssignment.property_id == property_id)
            .all()
        )
        user_schedule_assignment: Dict[int, int] = {int(uid): int(tid) for uid, tid in user_assignment_rows}

        group_assignment_rows = (
            db.query(PropertyGroupScheduleAssignment.property_group_id, PropertyGroupScheduleAssignment.template_id)
            .filter(PropertyGroupScheduleAssignment.property_id == property_id)
            .all()
        )
        group_schedule_assignment: Dict[int, int] = {int(gid): int(tid) for gid, tid in group_assignment_rows}

    return render_template(
        "admin/property_workspace.html",
        errors=errors,
        csrf_token=csrf_token,
        property_id=property_id,
        prop=prop,
        tab=tab,
        zones=zones,
        groups=groups,
        roles=roles,
        users=users,
        zone_memberships=zone_memberships,
        access_windows_by_user=access_windows_by_user,
        group_scopes=group_scopes,
        role_overrides=role_overrides,
        templates=templates,
        template_windows_by_template=template_windows_by_template,
        user_schedule_assignment=user_schedule_assignment,
        group_schedule_assignment=group_schedule_assignment,
        user_links=user_links,
    )


@bp.post("/properties/<int:property_id>/users/<int:user_id>/camera-scopes")
def property_user_camera_scopes_update(property_id: int, user_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    selected = request.form.getlist("group_ids")
    selected_ids: set[int] = set()
    for raw in selected:
        try:
            selected_ids.add(int(raw))
        except (TypeError, ValueError):
            continue

    with Session(engine) as db:
        user = db.get(User, user_id)
        prop = db.get(Property, property_id)
        if user is None or prop is None:
            abort(404)

        valid_group_ids = {
            int(gid)
            for (gid,) in db.query(PropertyGroup.id)
            .filter(PropertyGroup.property_id == property_id)
            .all()
        }
        selected_ids = {gid for gid in selected_ids if gid in valid_group_ids}

        db.query(UserPropertyGroupScope).filter(
            UserPropertyGroupScope.property_id == property_id,
            UserPropertyGroupScope.user_id == user_id,
        ).delete(synchronize_session=False)

        for gid in sorted(selected_ids):
            db.add(
                UserPropertyGroupScope(
                    property_id=property_id,
                    user_id=user_id,
                    property_group_id=gid,
                )
            )
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_USER_CAMERA_SCOPES_UPDATE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, target_user_id={user_id}, groups={sorted(selected_ids)}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="camera_scopes"))


@bp.post("/properties/<int:property_id>/users/<int:user_id>/role-overrides")
def property_user_role_overrides_update(property_id: int, user_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    selected = request.form.getlist("role_ids")
    selected_ids: set[int] = set()
    for raw in selected:
        try:
            selected_ids.add(int(raw))
        except (TypeError, ValueError):
            continue

    with Session(engine) as db:
        user = db.get(User, user_id)
        prop = db.get(Property, property_id)
        if user is None or prop is None:
            abort(404)

        valid_role_ids = {
            int(rid) for (rid,) in db.query(Role.id).all()
        }
        selected_ids = {rid for rid in selected_ids if rid in valid_role_ids}

        db.query(UserPropertyRoleOverride).filter(
            UserPropertyRoleOverride.property_id == property_id,
            UserPropertyRoleOverride.user_id == user_id,
        ).delete(synchronize_session=False)

        for rid in sorted(selected_ids):
            db.add(
                UserPropertyRoleOverride(
                    property_id=property_id,
                    user_id=user_id,
                    role_id=rid,
                )
            )
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_USER_ROLE_OVERRIDES_UPDATE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, target_user_id={user_id}, roles={sorted(selected_ids)}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="role_overrides"))


@bp.post("/properties/<int:property_id>/zones")
def property_zones_create(property_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    name = (request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip()
    if not name:
        return redirect(url_for("admin.property_workspace", property_id=property_id, tab="zones"))

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        if prop is None:
            abort(404)
        zone = PropertyZone(
            property_id=property_id,
            name=name,
            description=description or None,
        )
        db.add(zone)
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_ZONE_CREATE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, name={name}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="zones"))


@bp.post("/properties/<int:property_id>/zones/<int:zone_id>/delete")
def property_zones_delete(property_id: int, zone_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        zone = db.get(PropertyZone, zone_id)
        if zone is None or int(zone.property_id) != int(property_id):
            abort(404)
        db.query(UserPropertyZoneLink).filter(
            UserPropertyZoneLink.property_id == property_id,
            UserPropertyZoneLink.zone_id == zone_id,
        ).delete(synchronize_session=False)
        name = zone.name
        db.delete(zone)
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_ZONE_DELETE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, zone_id={zone_id}, name={name}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="zones"))


@bp.post("/properties/<int:property_id>/users/<int:user_id>/zones")
def property_user_zones_update(property_id: int, user_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    selected = request.form.getlist("zone_ids")
    selected_ids: set[int] = set()
    for raw in selected:
        try:
            selected_ids.add(int(raw))
        except (TypeError, ValueError):
            continue

    with Session(engine) as db:
        user = db.get(User, user_id)
        prop = db.get(Property, property_id)
        if user is None or prop is None:
            abort(404)
        valid_zone_ids = {
            int(zid)
            for (zid,) in db.query(PropertyZone.id)
            .filter(PropertyZone.property_id == property_id)
            .all()
        }
        selected_ids = {z for z in selected_ids if z in valid_zone_ids}

        db.query(UserPropertyZoneLink).filter(
            UserPropertyZoneLink.property_id == property_id,
            UserPropertyZoneLink.user_id == user_id,
        ).delete(synchronize_session=False)

        for zid in sorted(selected_ids):
            db.add(
                UserPropertyZoneLink(
                    property_id=property_id,
                    user_id=user_id,
                    zone_id=zid,
                )
            )
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_USER_ZONES_UPDATE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, target_user_id={user_id}, zones={sorted(selected_ids)}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="zones"))


@bp.post("/properties/<int:property_id>/users/<int:user_id>/access-windows")
def property_user_access_windows_create(property_id: int, user_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    day_values = request.form.getlist("days")
    if day_values:
        days_list: List[int] = []
        for raw in day_values:
            try:
                val = int(raw)
            except (TypeError, ValueError):
                continue
            if 0 <= val <= 6:
                days_list.append(val)
        days = ",".join(str(v) for v in sorted(set(days_list))) or "0,1,2,3,4,5,6"
    else:
        days = (request.form.get("days_of_week") or "0,1,2,3,4,5,6").strip()

    start_time = (request.form.get("start_time") or "00:00").strip()
    end_time = (request.form.get("end_time") or "23:59").strip()
    timezone_value = (request.form.get("timezone") or "").strip() or None
    is_enabled = 1 if (request.form.get("is_enabled") in {"1", "on", "true", "yes"}) else 0

    with Session(engine) as db:
        user = db.get(User, user_id)
        prop = db.get(Property, property_id)
        if user is None or prop is None:
            abort(404)
        db.add(
            UserPropertyAccessWindow(
                property_id=property_id,
                user_id=user_id,
                days_of_week=days or "0,1,2,3,4,5,6",
                start_time=start_time or "00:00",
                end_time=end_time or "23:59",
                timezone=timezone_value,
                is_enabled=is_enabled,
            )
        )
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_USER_ACCESS_WINDOW_CREATE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, target_user_id={user_id}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="access_windows"))


@bp.post("/properties/<int:property_id>/schedule-templates")
def property_schedule_template_create(property_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)
    name = (request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    if not name:
        return redirect(url_for("admin.property_workspace", property_id=property_id, tab="access_windows"))

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        if prop is None:
            abort(404)
        db.add(PropertyScheduleTemplate(property_id=property_id, name=name, description=description))
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_SCHEDULE_TEMPLATE_CREATE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, name={name}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="access_windows"))


@bp.post("/properties/<int:property_id>/schedule-templates/<int:template_id>/delete")
def property_schedule_template_delete(property_id: int, template_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        tmpl = db.get(PropertyScheduleTemplate, template_id)
        if tmpl is None or int(tmpl.property_id) != int(property_id):
            abort(404)
        db.query(PropertyScheduleTemplateWindow).filter(
            PropertyScheduleTemplateWindow.template_id == template_id
        ).delete(synchronize_session=False)
        db.query(UserPropertyScheduleAssignment).filter(
            UserPropertyScheduleAssignment.property_id == property_id,
            UserPropertyScheduleAssignment.template_id == template_id,
        ).delete(synchronize_session=False)
        db.query(PropertyGroupScheduleAssignment).filter(
            PropertyGroupScheduleAssignment.property_id == property_id,
            PropertyGroupScheduleAssignment.template_id == template_id,
        ).delete(synchronize_session=False)
        name = tmpl.name
        db.delete(tmpl)
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_SCHEDULE_TEMPLATE_DELETE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, template_id={template_id}, name={name}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="access_windows"))


@bp.post("/properties/<int:property_id>/schedule-templates/<int:template_id>/windows")
def property_schedule_template_window_create(property_id: int, template_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    day_values = request.form.getlist("days")
    days_list: List[int] = []
    for raw in day_values:
        try:
            val = int(raw)
        except (TypeError, ValueError):
            continue
        if 0 <= val <= 6:
            days_list.append(val)
    days = ",".join(str(v) for v in sorted(set(days_list))) or "0,1,2,3,4,5,6"
    start_time = (request.form.get("start_time") or "00:00").strip()
    end_time = (request.form.get("end_time") or "23:59").strip()
    timezone_value = (request.form.get("timezone") or "").strip() or None
    is_enabled = 1 if (request.form.get("is_enabled") in {"1", "on", "true", "yes"}) else 0

    with Session(engine) as db:
        tmpl = db.get(PropertyScheduleTemplate, template_id)
        if tmpl is None or int(tmpl.property_id) != int(property_id):
            abort(404)
        db.add(
            PropertyScheduleTemplateWindow(
                template_id=template_id,
                days_of_week=days,
                start_time=start_time or "00:00",
                end_time=end_time or "23:59",
                timezone=timezone_value,
                is_enabled=is_enabled,
            )
        )
        db.commit()

    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="access_windows"))


@bp.post(
    "/properties/<int:property_id>/schedule-templates/<int:template_id>/windows/<int:window_id>/delete"
)
def property_schedule_template_window_delete(
    property_id: int, template_id: int, window_id: int
):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        tmpl = db.get(PropertyScheduleTemplate, template_id)
        if tmpl is None or int(tmpl.property_id) != int(property_id):
            abort(404)
        w = db.get(PropertyScheduleTemplateWindow, window_id)
        if w is None or int(w.template_id) != int(template_id):
            abort(404)
        db.delete(w)
        db.commit()

    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="access_windows"))


@bp.post("/properties/<int:property_id>/apply-schedule/user/<int:user_id>")
def property_apply_schedule_to_user(property_id: int, user_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    try:
        template_id = int(request.form.get("template_id") or 0)
    except (TypeError, ValueError):
        template_id = 0
    mode = (request.form.get("mode") or "replace").strip().lower()
    if mode not in {"replace", "append"}:
        mode = "replace"

    with Session(engine) as db:
        user = db.get(User, user_id)
        prop = db.get(Property, property_id)
        tmpl = db.get(PropertyScheduleTemplate, template_id) if template_id else None
        if user is None or prop is None or tmpl is None or int(tmpl.property_id) != int(property_id):
            abort(404)

        windows = (
            db.query(PropertyScheduleTemplateWindow)
            .filter(PropertyScheduleTemplateWindow.template_id == template_id)
            .order_by(PropertyScheduleTemplateWindow.id)
            .all()
        )

        if mode == "replace":
            db.query(UserPropertyAccessWindow).filter(
                UserPropertyAccessWindow.property_id == property_id,
                UserPropertyAccessWindow.user_id == user_id,
            ).delete(synchronize_session=False)

        for w in windows:
            db.add(
                UserPropertyAccessWindow(
                    property_id=property_id,
                    user_id=user_id,
                    days_of_week=w.days_of_week,
                    start_time=w.start_time,
                    end_time=w.end_time,
                    timezone=w.timezone,
                    is_enabled=w.is_enabled,
                )
            )

        db.query(UserPropertyScheduleAssignment).filter(
            UserPropertyScheduleAssignment.property_id == property_id,
            UserPropertyScheduleAssignment.user_id == user_id,
        ).delete(synchronize_session=False)
        db.add(
            UserPropertyScheduleAssignment(
                property_id=property_id,
                user_id=user_id,
                template_id=template_id,
            )
        )
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_APPLY_SCHEDULE_TO_USER",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, target_user_id={user_id}, template_id={template_id}, mode={mode}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="access_windows"))


@bp.post("/properties/<int:property_id>/apply-schedule/group/<int:group_id>")
def property_apply_schedule_to_group(property_id: int, group_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    try:
        template_id = int(request.form.get("template_id") or 0)
    except (TypeError, ValueError):
        template_id = 0
    mode = (request.form.get("mode") or "replace").strip().lower()
    if mode not in {"replace", "append"}:
        mode = "replace"

    with Session(engine) as db:
        prop = db.get(Property, property_id)
        grp = db.get(PropertyGroup, group_id)
        tmpl = db.get(PropertyScheduleTemplate, template_id) if template_id else None
        if (
            prop is None
            or grp is None
            or int(grp.property_id) != int(property_id)
            or tmpl is None
            or int(tmpl.property_id) != int(property_id)
        ):
            abort(404)

        windows = (
            db.query(PropertyScheduleTemplateWindow)
            .filter(PropertyScheduleTemplateWindow.template_id == template_id)
            .order_by(PropertyScheduleTemplateWindow.id)
            .all()
        )

        # Group schedules apply to the set of global Users whose structured camera
        # scope includes this PropertyGroup.
        user_ids = [
            int(uid)
            for (uid,) in db.query(UserPropertyGroupScope.user_id)
            .filter(
                UserPropertyGroupScope.property_id == property_id,
                UserPropertyGroupScope.property_group_id == group_id,
            )
            .all()
        ]

        if mode == "replace":
            db.query(UserPropertyAccessWindow).filter(
                UserPropertyAccessWindow.property_id == property_id,
                UserPropertyAccessWindow.user_id.in_(user_ids) if user_ids else False,
            ).delete(synchronize_session=False)

        for uid in user_ids:
            for w in windows:
                db.add(
                    UserPropertyAccessWindow(
                        property_id=property_id,
                        user_id=uid,
                        days_of_week=w.days_of_week,
                        start_time=w.start_time,
                        end_time=w.end_time,
                        timezone=w.timezone,
                        is_enabled=w.is_enabled,
                    )
                )

        db.query(PropertyGroupScheduleAssignment).filter(
            PropertyGroupScheduleAssignment.property_id == property_id,
            PropertyGroupScheduleAssignment.property_group_id == group_id,
        ).delete(synchronize_session=False)
        db.add(
            PropertyGroupScheduleAssignment(
                property_id=property_id,
                property_group_id=group_id,
                template_id=template_id,
            )
        )
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_APPLY_SCHEDULE_TO_GROUP",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, group_id={group_id}, template_id={template_id}, mode={mode}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="access_windows"))


@bp.post(
    "/properties/<int:property_id>/users/<int:user_id>/access-windows/<int:window_id>/delete"
)
def property_user_access_windows_delete(property_id: int, user_id: int, window_id: int):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    engine = get_user_engine()
    if engine is None:
        abort(500)

    with Session(engine) as db:
        w = db.get(UserPropertyAccessWindow, window_id)
        if (
            w is None
            or int(w.property_id) != int(property_id)
            or int(w.user_id) != int(user_id)
        ):
            abort(404)
        db.delete(w)
        db.commit()

    actor = get_current_user()
    log_event(
        "PROPERTY_USER_ACCESS_WINDOW_DELETE",
        user_id=actor.id if actor else None,
        details=f"property_id={property_id}, target_user_id={user_id}, window_id={window_id}",
    )
    return redirect(url_for("admin.property_workspace", property_id=property_id, tab="access_windows"))


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
