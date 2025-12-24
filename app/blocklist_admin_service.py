from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
import ipaddress
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, Response, abort, request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import load_config
from .db import get_user_engine
from .models import AuditEvent, CountryAccessPolicy, IpAllowlist, IpBlocklist, Role, User, UserRole


_ph = PasswordHasher()


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if ip:
            return ip
    return request.remote_addr or ""


def _unauthorized(realm: str) -> Response:
    resp = Response("unauthorized\n", status=401, mimetype="text/plain; charset=utf-8")
    resp.headers["WWW-Authenticate"] = f'Basic realm="{realm}", charset="UTF-8"'
    return resp


def _is_admin_user(db: Session, user: User) -> bool:
    role = db.scalar(select(Role).where(Role.name == "System Administrator"))
    if role is None:
        return False
    row = db.scalar(
        select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
    )
    return row is not None


def _require_admin_basic_auth(realm: str) -> Optional[Response]:
    auth = request.authorization
    if auth is None or not auth.username or not auth.password:
        return _unauthorized(realm)

    engine = get_user_engine()
    if engine is None:
        return Response("not_ok: no_user_db\n", status=503, mimetype="text/plain; charset=utf-8")

    with Session(engine) as db:
        user = db.scalar(select(User).where(User.email == auth.username))
        if user is None:
            return _unauthorized(realm)

        try:
            _ph.verify(user.password_hash, auth.password)
        except VerifyMismatchError:
            return _unauthorized(realm)
        except Exception:
            return Response("not_ok\n", status=503, mimetype="text/plain; charset=utf-8")

        if not _is_admin_user(db, user):
            return Response("forbidden\n", status=403, mimetype="text/plain; charset=utf-8")

    return None


def _normalize_cidr(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        raise ValueError("missing")
    if "/" in value:
        net = ipaddress.ip_network(value, strict=False)
        return str(net)
    addr = ipaddress.ip_address(value)
    if addr.version == 6:
        return f"{addr}/128"
    return f"{addr}/32"


def _parse_until(details: str) -> Optional[datetime]:
    text = str(details or "")
    for part in text.split():
        if part.startswith("until="):
            val = part.split("=", 1)[1].strip()
            try:
                return datetime.fromisoformat(val)
            except Exception:
                return None
    return None


def _offense_from_counts(rule: str, count: int) -> str:
    r = (rule or "").strip().lower()
    try:
        n = int(count)
    except Exception:
        n = 0

    if r == "login":
        if n >= 12:
            return "Permanently Blocked"
        if n >= 9:
            return "3rd offense"
        if n >= 6:
            return "2nd offense"
        if n >= 3:
            return "1st offense"
        return ""
    if r == "bad_url":
        if n >= 10:
            return "Permanently Blocked"
        if n >= 5:
            return "1st offense"
        return ""
    return ""


def _rule_label(rule: str) -> str:
    r = (rule or "").strip().lower()
    if r == "login":
        return "login"
    if r == "bad_url":
        return "bad url"
    if r == "network_escalation":
        return "network escalation"
    if r == "manual":
        return "manual"
    return r or "unknown"


def _blocked_reason_from_desc(desc: str) -> tuple[str, str, str]:
    d = str(desc or "").strip().lower()
    if "auth_failures" in d:
        return "login", "Permanently Blocked", "login"
    if "bad_urls" in d:
        return "bad_url", "Permanently Blocked", "bad url"
    if "escalate_network" in d:
        return "network_escalation", "Permanently Blocked", "network escalation"
    if d:
        return "manual", "Permanently Blocked", "manual"
    return "manual", "Permanently Blocked", "manual"


def create_blocklist_admin_service() -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(load_config())
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    def _render_page(
        allow_rows: list[IpAllowlist],
        blocked_rows: list[dict],
        policy: Optional[CountryAccessPolicy],
        error: str = "",
        message: str = "",
    ) -> str:
        mode = (policy.mode if policy and policy.mode else "disabled") if policy else "disabled"
        allowed = (policy.allowed_countries if policy and policy.allowed_countries else "") if policy else ""
        blocked = (policy.blocked_countries if policy and policy.blocked_countries else "") if policy else ""

        def _chips(raw: str) -> str:
            parts = [c.strip().upper() for c in (raw or "").split(",") if c.strip()]
            if not parts:
                return "<span class=\"muted\">(none)</span>"
            return " ".join([f"<span class=\"chip\">{c}</span>" for c in parts])

        now = datetime.now(timezone.utc).isoformat()
        current_ip = _client_ip() or "Unknown"

        def _row_html(table: str, entry_id: int, cidr: str, desc: Optional[str]) -> str:
            safe_desc = (desc or "").replace("<", "&lt;").replace(">", "&gt;")
            safe_cidr = (cidr or "").replace("<", "&lt;").replace(">", "&gt;")
            return (
                "<tr>"
                f"<td class=\"mono\">{safe_cidr}</td>"
                f"<td>{safe_desc or '&nbsp;'}</td>"
                "<td style=\"width:1%;white-space:nowrap;\">"
                f"<form method=\"post\" action=\"/remove/{table}/{entry_id}\" onsubmit=\"return confirm('Remove this entry?');\">"
                "<button class=\"btn danger\" type=\"submit\">Remove</button>"
                "</form>"
                "</td>"
                "</tr>"
            )

        allow_body = "".join(
            [_row_html("allow", int(r.id), str(r.cidr), r.description) for r in allow_rows]
        )
        def _blocked_row_html(row: dict) -> str:
            cidr = str(row.get("cidr") or "")
            desc = str(row.get("description") or "")
            status = str(row.get("status") or "")
            rule = str(row.get("rule") or "")
            until = row.get("until")
            until_text = ""
            if isinstance(until, datetime):
                until_text = until.astimezone(timezone.utc).isoformat()
            elif until is None:
                until_text = "permanent"
            else:
                until_text = str(until)

            safe_cidr = cidr.replace("<", "&lt;").replace(">", "&gt;")
            safe_desc = desc.replace("<", "&lt;").replace(">", "&gt;")
            safe_status = status.replace("<", "&lt;").replace(">", "&gt;")
            safe_rule = rule.replace("<", "&lt;").replace(">", "&gt;")
            safe_until = until_text.replace("<", "&lt;").replace(">", "&gt;")

            action_html = ""
            if row.get("kind") == "block" and row.get("id") is not None:
                entry_id = int(row.get("id"))
                action_html = (
                    f"<form method=\"post\" action=\"/remove/block/{entry_id}\" onsubmit=\"return confirm('Remove this entry?');\">"
                    "<button class=\"btn danger\" type=\"submit\">Remove</button>"
                    "</form>"
                )
            elif row.get("kind") == "suspend" and row.get("ip"):
                ip = str(row.get("ip"))
                safe_ip = ip.replace("<", "&lt;").replace(">", "&gt;")
                action_html = (
                    "<form method=\"post\" action=\"/remove/suspend\" onsubmit=\"return confirm('Clear temporary suspension for this IP?');\">"
                    f"<input type=\"hidden\" name=\"ip\" value=\"{safe_ip}\" />"
                    "<button class=\"btn danger\" type=\"submit\">Clear</button>"
                    "</form>"
                )

            return (
                "<tr>"
                f"<td class=\"mono\">{safe_cidr}</td>"
                f"<td class=\"mono\">{safe_until}</td>"
                f"<td>{safe_status or '&nbsp;'}</td>"
                f"<td>{safe_rule or '&nbsp;'}</td>"
                f"<td>{safe_desc or '&nbsp;'}</td>"
                f"<td style=\"width:1%;white-space:nowrap;\">{action_html}</td>"
                "</tr>"
            )

        block_body = "".join([_blocked_row_html(r) for r in (blocked_rows or [])])

        error_html = ""
        if error:
            safe = str(error).replace("<", "&lt;").replace(">", "&gt;")
            error_html = f"<div class=\"alert err\">{safe}</div>"
        msg_html = ""
        if message:
            safe = str(message).replace("<", "&lt;").replace(">", "&gt;")
            msg_html = f"<div class=\"alert ok\">{safe}</div>"

        return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>PentaVision Access Control</title>
  <style>
    :root {{
      --bg: #061821;
      --panel: rgba(255,255,255,0.06);
      --panel2: rgba(255,255,255,0.04);
      --text: #e5e7eb;
      --muted: rgba(229,231,235,0.72);
      --border: rgba(255,255,255,0.12);
      --accent: #60a5fa;
      --danger: #ef4444;
      --ok: #22c55e;
    }}
    body {{
      margin: 0;
      background:
        radial-gradient(1200px 600px at 15% 0%, rgba(34,211,238,0.18), transparent 60%),
        radial-gradient(900px 520px at 85% 10%, rgba(96,165,250,0.16), transparent 55%),
        var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 18px; }}
    .header {{ display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; flex-wrap: wrap; }}
    h1 {{ margin: 0; font-size: 1.4rem; letter-spacing: 0.2px; }}
    .sub {{ margin-top: 6px; color: var(--muted); font-size: 0.92rem; }}
    .panel {{ margin-top: 14px; background: linear-gradient(180deg, rgba(255,255,255,0.08), rgba(255,255,255,0.04)); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; }}
    .panel-top {{ display:flex; justify-content:space-between; align-items:center; padding: 12px 14px; background: rgba(255,255,255,0.04); border-bottom: 1px solid var(--border); gap: 10px; flex-wrap: wrap; }}
    .kpis {{ display: flex; gap: 14px; flex-wrap: wrap; color: var(--muted); font-size: 0.9rem; }}
    .kpis strong {{ color: var(--text); font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 0.92rem; }}
    th {{ text-align:left; color: rgba(229,231,235,0.85); font-weight: 700; background: rgba(255,255,255,0.03); }}
    tr:hover td {{ background: rgba(96,165,250,0.06); }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace; }}
    .btn {{ display:inline-flex; align-items:center; gap: 8px; padding: 8px 10px; border-radius: 10px; border: 1px solid var(--border); background: var(--panel); color: var(--text); text-decoration:none; font-weight: 700; cursor: pointer; }}
    .btn:hover {{ border-color: rgba(96,165,250,0.6); }}
    .btn.danger {{ border-color: rgba(239,68,68,0.55); background: rgba(239,68,68,0.12); }}
    .btn.danger:hover {{ border-color: rgba(239,68,68,0.9); }}
    .grid {{ display:grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 14px; }}
    @media (max-width: 980px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    .alert {{ margin-top: 10px; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border); background: rgba(255,255,255,0.05); }}
    .alert.err {{ border-color: rgba(239,68,68,0.55); background: rgba(239,68,68,0.12); }}
    .alert.ok {{ border-color: rgba(34,197,94,0.55); background: rgba(34,197,94,0.12); }}
    .muted {{ color: var(--muted); }}
    .chip {{ display:inline-flex; align-items:center; padding: 4px 8px; border-radius: 999px; border: 1px solid rgba(255,255,255,0.14); background: rgba(255,255,255,0.05); margin-right: 6px; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <div class=\"header\">
      <div>
        <h1>Access Control (8124)</h1>
        <div class=\"sub\">Current IP: <span class=\"mono\">{current_ip}</span> · Server time: <span class=\"mono\">{now}</span></div>
      </div>
    </div>

    {error_html}
    {msg_html}

    <div class=\"panel\">
      <div class=\"panel-top\">
        <div><strong>Country access policy</strong></div>
        <div class=\"kpis\">
          <div><strong>Mode</strong> <span class=\"mono\">{mode}</span></div>
        </div>
      </div>
      <div style=\"padding: 12px 14px;\">
        <div class=\"muted\" style=\"margin-bottom: 8px;\">Allowed countries:</div>
        <div>{_chips(allowed)}</div>
        <div class=\"muted\" style=\"margin: 12px 0 8px;\">Blocked countries:</div>
        <div>{_chips(blocked)}</div>
      </div>
    </div>

    <div class=\"grid\">
      <div class=\"panel\">
        <div class=\"panel-top\">
          <div><strong>IP allowlist (exemptions)</strong></div>
          <div class=\"kpis\"><div><strong>{len(allow_rows)}</strong> entries</div></div>
        </div>
        <div style=\"padding: 12px 14px; border-bottom: 1px solid rgba(255,255,255,0.08);\">
          <form method=\"post\" action=\"/add/allow\" style=\"display:flex; gap:10px; flex-wrap:wrap; align-items:center;\">
            <input name=\"cidr\" placeholder=\"IP or CIDR (e.g. 203.0.113.5 or 192.0.2.0/24)\" style=\"flex: 1 1 18rem; min-width: 220px; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border); background: rgba(255,255,255,0.06); color: var(--text);\" />
            <input name=\"description\" placeholder=\"Description (optional)\" style=\"flex: 1 1 14rem; min-width: 180px; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border); background: rgba(255,255,255,0.06); color: var(--text);\" />
            <button class=\"btn\" type=\"submit\">Add to allowlist</button>
          </form>
          <div class=\"muted\" style=\"margin-top: 8px; font-size: 0.9rem;\">Adding requires System Administrator credentials.</div>
        </div>
        <table>
          <thead><tr><th>CIDR / IP</th><th>Description</th><th></th></tr></thead>
          <tbody>{allow_body or '<tr><td colspan=3 class="muted">(none)</td></tr>'}</tbody>
        </table>
      </div>

      <div class=\"panel\">
        <div class=\"panel-top\">
          <div><strong>IP / network blocklist</strong></div>
          <div class=\"kpis\"><div><strong>{len(blocked_rows)}</strong> entries</div></div>
        </div>
        <table>
          <thead><tr><th>CIDR / IP</th><th>Blocked until (UTC)</th><th>Status</th><th>Rule</th><th>Notes</th><th></th></tr></thead>
          <tbody>{block_body or '<tr><td colspan=6 class="muted">(none)</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>"""

    @app.get("/healthz")
    def healthz() -> Response:
        engine = get_user_engine()
        if engine is None:
            return Response("not_ok: no_user_db\n", status=503, mimetype="text/plain; charset=utf-8")
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return Response("ok\n", mimetype="text/plain; charset=utf-8")
        except Exception as exc:  # noqa: BLE001
            return Response(
                f"not_ok: db_error: {type(exc).__name__}\n",
                status=503,
                mimetype="text/plain; charset=utf-8",
            )

    @app.get("/")
    def root() -> Response:
        engine = get_user_engine()
        if engine is None:
            html = _render_page([], [], None, error="User database is not configured.")
            return Response(html, status=503, mimetype="text/html; charset=utf-8")

        def _load_view_model(db: Session):
            now_local = datetime.now(timezone.utc)
            day_ago = now_local - timedelta(days=1)

            IpAllowlist.__table__.create(bind=engine, checkfirst=True)
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            CountryAccessPolicy.__table__.create(bind=engine, checkfirst=True)
            AuditEvent.__table__.create(bind=engine, checkfirst=True)

            allow_rows_local = db.query(IpAllowlist).order_by(IpAllowlist.cidr.asc()).all()
            block_rows_local = db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all()
            policy_local = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()

            allow_nets: list[ipaddress._BaseNetwork] = []
            for a in allow_rows_local:
                try:
                    allow_nets.append(ipaddress.ip_network(str(a.cidr), strict=False))
                except Exception:
                    continue

            def _ip_is_allowlisted_local(ip_str: str) -> bool:
                try:
                    addr = ipaddress.ip_address(str(ip_str))
                except Exception:
                    return False
                for net in allow_nets:
                    try:
                        if addr in net:
                            return True
                    except Exception:
                        continue
                return False

            suspend_rows = (
                db.query(AuditEvent)
                .filter(
                    AuditEvent.when >= day_ago,
                    AuditEvent.event_type.in_(["AUTH_IP_SUSPEND", "SECURITY_URL_SUSPEND"]),
                )
                .order_by(AuditEvent.when.desc())
                .all()
            )

            def _count_login_failures(ip: str) -> int:
                failure_events = [
                    "AUTH_LOGIN_FAILURE",
                    "AUTH_LOGIN_2FA_FAILURE",
                    "AUTH_TOTP_VERIFY_FAILURE",
                    "AUTH_WEBAUTHN_LOGIN_COMPLETE_FAILURE",
                ]
                return int(
                    (
                        db.query(AuditEvent.id)
                        .filter(
                            AuditEvent.when >= day_ago,
                            AuditEvent.ip == ip,
                            AuditEvent.event_type.in_(failure_events),
                        )
                        .count()
                    )
                    or 0
                )

            def _count_bad_urls(ip: str) -> int:
                return int(
                    (
                        db.query(AuditEvent.id)
                        .filter(
                            AuditEvent.when >= day_ago,
                            AuditEvent.ip == ip,
                            AuditEvent.event_type == "SECURITY_URL_404",
                        )
                        .count()
                    )
                    or 0
                )

            blocked_local: list[dict] = []

            for r in block_rows_local:
                cidr = str(r.cidr)
                _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                blocked_local.append(
                    {
                        "kind": "block",
                        "id": int(r.id),
                        "cidr": cidr,
                        "until": None,
                        "status": status,
                        "rule": rule_label,
                        "description": str(r.description or ""),
                    }
                )

            seen_ips: set[str] = set()
            for ev in suspend_rows:
                ip = str(ev.ip or "").strip()
                if not ip or ip in seen_ips:
                    continue
                if _ip_is_allowlisted_local(ip):
                    continue
                until = _parse_until(str(ev.details or ""))
                if until is None or now_local >= until:
                    continue
                seen_ips.add(ip)

                rule_key = "login" if str(ev.event_type) == "AUTH_IP_SUSPEND" else "bad_url"
                count = _count_login_failures(ip) if rule_key == "login" else _count_bad_urls(ip)
                offense = _offense_from_counts(rule_key, count)
                blocked_local.append(
                    {
                        "kind": "suspend",
                        "ip": ip,
                        "cidr": f"{ip}/32" if ":" not in ip else f"{ip}/128",
                        "until": until,
                        "status": offense or "Temporary Block",
                        "rule": _rule_label(rule_key),
                        "description": str(ev.details or ""),
                    }
                )

            def _sort_key(row: dict):
                cidr = str(row.get("cidr") or "")
                kind = str(row.get("kind") or "")
                until = row.get("until")
                until_ts = 0
                if isinstance(until, datetime):
                    try:
                        until_ts = int(until.timestamp())
                    except Exception:
                        until_ts = 0
                return (0 if kind == "suspend" else 1, -until_ts, cidr)

            blocked_local.sort(key=_sort_key)
            return allow_rows_local, blocked_local, policy_local

        with Session(engine) as db:
            allow_rows, blocked, policy = _load_view_model(db)

        html = _render_page(allow_rows, blocked, policy)
        return Response(html, mimetype="text/html; charset=utf-8")

    @app.post("/remove/allow/<int:entry_id>")
    def remove_allow(entry_id: int) -> Response:
        realm = f"PentaVision Admin Remove Allow {entry_id}"
        maybe = _require_admin_basic_auth(realm)
        if maybe is not None:
            return maybe

        engine = get_user_engine()
        if engine is None:
            abort(503)

        with Session(engine) as db:
            deleted = (
                db.query(IpAllowlist)
                .filter(IpAllowlist.id == entry_id)
                .delete(synchronize_session=False)
            )
            db.commit()

            allow_rows = db.query(IpAllowlist).order_by(IpAllowlist.cidr.asc()).all()
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            blocked = []
            for r in db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all():
                _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                blocked.append({"kind": "block", "id": int(r.id), "cidr": str(r.cidr), "until": None, "status": status, "rule": rule_label, "description": str(r.description or "")})

        msg = "Removed." if deleted else "Entry not found."
        html = _render_page(allow_rows, blocked, policy, message=msg)
        return Response(html, mimetype="text/html; charset=utf-8")

    @app.post("/add/allow")
    def add_allow() -> Response:
        realm = "PentaVision Admin Add Allow"
        maybe = _require_admin_basic_auth(realm)
        if maybe is not None:
            return maybe

        raw_cidr = (request.form.get("cidr") or "").strip()
        description = (request.form.get("description") or "").strip() or None

        engine = get_user_engine()
        if engine is None:
            abort(503)

        try:
            cidr = _normalize_cidr(raw_cidr)
        except Exception:
            with Session(engine) as db:
                allow_rows = db.query(IpAllowlist).order_by(IpAllowlist.cidr.asc()).all()
                policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
                blocked = []
                for r in db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all():
                    _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                    blocked.append({"kind": "block", "id": int(r.id), "cidr": str(r.cidr), "until": None, "status": status, "rule": rule_label, "description": str(r.description or "")})
            html = _render_page(allow_rows, blocked, policy, error="Invalid IP/CIDR")
            return Response(html, status=400, mimetype="text/html; charset=utf-8")

        with Session(engine) as db:
            IpAllowlist.__table__.create(bind=engine, checkfirst=True)
            exists = db.scalar(select(IpAllowlist).where(IpAllowlist.cidr == cidr))
            if exists is None:
                entry = IpAllowlist(cidr=cidr, description=description)
                db.add(entry)
                db.commit()

            allow_rows = db.query(IpAllowlist).order_by(IpAllowlist.cidr.asc()).all()
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            blocked = []
            for r in db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all():
                _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                blocked.append({"kind": "block", "id": int(r.id), "cidr": str(r.cidr), "until": None, "status": status, "rule": rule_label, "description": str(r.description or "")})

        msg = "Added." if exists is None else "Already present."
        html = _render_page(allow_rows, blocked, policy, message=msg)
        return Response(html, mimetype="text/html; charset=utf-8")

    @app.post("/remove/suspend")
    def remove_suspend() -> Response:
        ip = (request.form.get("ip") or "").strip()
        realm = f"PentaVision Admin Clear Suspend {ip}"
        maybe = _require_admin_basic_auth(realm)
        if maybe is not None:
            return maybe

        engine = get_user_engine()
        if engine is None:
            abort(503)

        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(days=1)

        with Session(engine) as db:
            IpAllowlist.__table__.create(bind=engine, checkfirst=True)
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            CountryAccessPolicy.__table__.create(bind=engine, checkfirst=True)
            AuditEvent.__table__.create(bind=engine, checkfirst=True)

            deleted = 0
            if ip:
                deleted = (
                    db.query(AuditEvent)
                    .filter(
                        AuditEvent.when >= day_ago,
                        AuditEvent.ip == ip,
                        AuditEvent.event_type.in_(["AUTH_IP_SUSPEND", "SECURITY_URL_SUSPEND"]),
                    )
                    .delete(synchronize_session=False)
                )
                db.commit()

            allow_rows = db.query(IpAllowlist).order_by(IpAllowlist.cidr.asc()).all()
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            blocked = []
            for r in db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all():
                _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                blocked.append(
                    {
                        "kind": "block",
                        "id": int(r.id),
                        "cidr": str(r.cidr),
                        "until": None,
                        "status": status,
                        "rule": rule_label,
                        "description": str(r.description or ""),
                    }
                )

        msg = "Cleared." if deleted else "No active suspension found."
        html = _render_page(allow_rows, blocked, policy, message=msg)
        return Response(html, mimetype="text/html; charset=utf-8")

    @app.post("/remove/block/<int:entry_id>")
    def remove_block(entry_id: int) -> Response:
        realm = f"PentaVision Admin Remove Block {entry_id}"
        maybe = _require_admin_basic_auth(realm)
        if maybe is not None:
            return maybe

        engine = get_user_engine()
        if engine is None:
            abort(503)

        with Session(engine) as db:
            deleted = (
                db.query(IpBlocklist)
                .filter(IpBlocklist.id == entry_id)
                .delete(synchronize_session=False)
            )
            db.commit()
            allow_rows = db.query(IpAllowlist).order_by(IpAllowlist.cidr.asc()).all()
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            blocked = []
            for r in db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all():
                _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                blocked.append({"kind": "block", "id": int(r.id), "cidr": str(r.cidr), "until": None, "status": status, "rule": rule_label, "description": str(r.description or "")})

        msg = "Removed." if deleted else "Entry not found."
        html = _render_page(allow_rows, blocked, policy, message=msg)
        return Response(html, mimetype="text/html; charset=utf-8")

    return app
