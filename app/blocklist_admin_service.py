from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, Response, abort, request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import load_config
from .db import get_user_engine
from .models import CountryAccessPolicy, IpAllowlist, IpBlocklist, Role, User, UserRole


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


def create_blocklist_admin_service() -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(load_config())
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    def _render_page(
        allow_rows: list[IpAllowlist],
        block_rows: list[IpBlocklist],
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
        block_body = "".join(
            [_row_html("block", int(r.id), str(r.cidr), r.description) for r in block_rows]
        )

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
        <table>
          <thead><tr><th>CIDR / IP</th><th>Description</th><th></th></tr></thead>
          <tbody>{allow_body or '<tr><td colspan=3 class="muted">(none)</td></tr>'}</tbody>
        </table>
      </div>

      <div class=\"panel\">
        <div class=\"panel-top\">
          <div><strong>IP / network blocklist</strong></div>
          <div class=\"kpis\"><div><strong>{len(block_rows)}</strong> entries</div></div>
        </div>
        <table>
          <thead><tr><th>CIDR / IP</th><th>Description</th><th></th></tr></thead>
          <tbody>{block_body or '<tr><td colspan=3 class="muted">(none)</td></tr>'}</tbody>
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

        with Session(engine) as db:
            IpAllowlist.__table__.create(bind=engine, checkfirst=True)
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            CountryAccessPolicy.__table__.create(bind=engine, checkfirst=True)
            allow_rows = db.query(IpAllowlist).order_by(IpAllowlist.cidr.asc()).all()
            block_rows = db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all()
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()

        html = _render_page(allow_rows, block_rows, policy)
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
            block_rows = db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all()
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()

        msg = "Removed." if deleted else "Entry not found."
        html = _render_page(allow_rows, block_rows, policy, message=msg)
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
            block_rows = db.query(IpBlocklist).order_by(IpBlocklist.cidr.asc()).all()
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()

        msg = "Removed." if deleted else "Entry not found."
        html = _render_page(allow_rows, block_rows, policy, message=msg)
        return Response(html, mimetype="text/html; charset=utf-8")

    return app
