from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
import glob
import ipaddress
import os
import re
import time
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, Response, abort, request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import load_config
from .db import get_user_engine
from .models import AuditEvent, CountryAccessPolicy, IpAllowlist, IpBlocklist, Role, User, UserRole

try:
    from .admin import COUNTRY_CHOICES
except Exception:  # noqa: BLE001
    COUNTRY_CHOICES = (  # type: ignore[assignment]
        ("US", "United States"),
        ("CA", "Canada"),
        ("MX", "Mexico"),
    )


_ph = PasswordHasher()


_apache_cache: dict[str, object] = {
    "ts": 0.0,
    "rows": [],
    "subnets": [],
    "err": "",
}


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


def _codes_from_raw(raw: str) -> list[str]:
    parts = [c.strip().upper() for c in str(raw or "").split(",") if c.strip()]
    out: list[str] = []
    seen: set[str] = set()
    for c in parts:
        if len(c) != 2:
            continue
        if c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


def _tail_lines(path: str, *, max_lines: int = 5000, max_bytes: int = 512 * 1024) -> list[str]:
    p = str(path or "").strip()
    if not p or not os.path.exists(p):
        return []
    try:
        with open(p, "rb") as f:
            try:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                start = max(0, size - int(max_bytes))
                f.seek(start)
                data = f.read()
            except Exception:
                f.seek(0)
                data = f.read()
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if len(lines) > int(max_lines):
            lines = lines[-int(max_lines):]
        return [str(ln) for ln in lines if ln is not None]
    except Exception:
        return []


def _apache_log_candidates() -> list[str]:
    cands: list[str] = []

    for p in (
        "/var/log/apache2/pentavision_access.log",
        "/var/log/apache2/pentavision_error.log",
    ):
        if os.path.exists(p):
            cands.append(p)
    for base in ("/etc/apache2", "/etc/apache", "/var/log/apache2", "/var/log/httpd"):
        for pat in ("*_access*", "*_error*", "access.log*", "error.log*"):
            try:
                cands.extend(glob.glob(os.path.join(base, pat)))
            except Exception:
                continue
    out: list[str] = []
    seen: set[str] = set()
    for p in cands:
        p = str(p or "").strip()
        if not p:
            continue
        if p in seen:
            continue
        seen.add(p)
        if os.path.isdir(p):
            continue
        out.append(p)
    return out


def _scan_apache_findings(*, cache_ttl_seconds: int = 10) -> tuple[list[dict], list[dict], str]:
    now = time.time()
    try:
        ts = float(_apache_cache.get("ts") or 0.0)
    except Exception:
        ts = 0.0
    if (now - ts) < float(cache_ttl_seconds or 10):
        return (
            list(_apache_cache.get("rows") or []),
            list(_apache_cache.get("subnets") or []),
            str(_apache_cache.get("err") or ""),
        )

    paths = _apache_log_candidates()

    access_re = re.compile(
        r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+\"(?P<m>\S+)\s+(?P<path>\S+)\s+\S+\"\s+(?P<status>\d{3})\s+",
        re.IGNORECASE,
    )
    error_client_re = re.compile(r"\bclient\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE)
    status_404 = 0

    def _parse_access_ts(raw: str) -> Optional[datetime]:
        s = str(raw or "").strip()
        if not s:
            return None
        try:
            # Example: 24/Dec/2025:07:00:29 -0600
            return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        except Exception:
            return None

    stats: dict[str, dict] = {}

    for p in paths:
        lines = _tail_lines(p, max_lines=5000, max_bytes=512 * 1024)
        if not lines:
            continue
        is_access = ("access" in os.path.basename(p).lower()) or (p.endswith("_access") or "_access" in p)
        for ln in lines:
            s = str(ln or "")
            if not s:
                continue

            ip = ""
            when = None
            path = ""
            status = ""

            if is_access:
                m = access_re.match(s)
                if not m:
                    continue
                ip = str(m.group("ip") or "").strip()
                when = _parse_access_ts(m.group("ts"))
                path = str(m.group("path") or "")
                status = str(m.group("status") or "")
            else:
                em = error_client_re.search(s)
                if not em:
                    continue
                ip = str(em.group("ip") or "").strip()
                path = s

            if not ip:
                continue

            row = stats.get(ip)
            if row is None:
                row = {
                    "ip": ip,
                    "count_404": 0,
                    "count_login": 0,
                    "count_total": 0,
                    "last_seen": None,
                    "examples": [],
                }
                stats[ip] = row

            is_404 = (status == "404") or (" 404 " in s)

            login_hit = False
            if is_access:
                pth = (path or "").lower()
                if any(k in pth for k in ("/login", "/auth", "/signin", "/webauthn", "/totp")):
                    if status in {"401", "403"}:
                        login_hit = True
            else:
                ls = s.lower()
                if any(k in ls for k in ("auth", "login", "invalid credentials", "authentication failure", "password")):
                    login_hit = True

            if is_404:
                row["count_404"] = int(row["count_404"] or 0) + 1
            if login_hit:
                row["count_login"] = int(row["count_login"] or 0) + 1
            row["count_total"] = int(row["count_total"] or 0) + 1

            if when is not None:
                try:
                    cur = row.get("last_seen")
                    if cur is None or (isinstance(cur, datetime) and when > cur):
                        row["last_seen"] = when
                except Exception:
                    pass

            ex = row.get("examples")
            if isinstance(ex, list) and len(ex) < 3:
                ex.append(s[:200])

    rows_out: list[dict] = []
    for ip, row in stats.items():
        try:
            if row.get("count_total"):
                rows_out.append(row)
        except Exception:
            continue

    def _row_sort_key(r: dict):
        return (
            -int(r.get("count_total") or 0),
            -int(r.get("count_404") or 0),
            -int(r.get("count_login") or 0),
            str(r.get("ip") or ""),
        )

    rows_out.sort(key=_row_sort_key)
    rows_out = rows_out[:200]

    subnet_counts: dict[str, dict] = {}
    for r in rows_out:
        ip = str(r.get("ip") or "").strip()
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            continue
        if addr.version != 4:
            continue
        try:
            net24 = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except Exception:
            continue
        sc = subnet_counts.get(net24)
        if sc is None:
            sc = {"cidr": net24, "hosts": set(), "count_total": 0, "count_404": 0, "count_login": 0}
            subnet_counts[net24] = sc
        sc["hosts"].add(ip)
        sc["count_total"] = int(sc.get("count_total") or 0) + int(r.get("count_total") or 0)
        sc["count_404"] = int(sc.get("count_404") or 0) + int(r.get("count_404") or 0)
        sc["count_login"] = int(sc.get("count_login") or 0) + int(r.get("count_login") or 0)

    subnets_out: list[dict] = []
    for cidr, sc in subnet_counts.items():
        hosts = sc.get("hosts")
        host_count = len(hosts) if isinstance(hosts, set) else 0
        if host_count >= 3:
            subnets_out.append(
                {
                    "cidr": cidr,
                    "host_count": host_count,
                    "count_total": int(sc.get("count_total") or 0),
                    "count_404": int(sc.get("count_404") or 0),
                    "count_login": int(sc.get("count_login") or 0),
                }
            )
    subnets_out.sort(key=lambda d: (-int(d.get("host_count") or 0), -int(d.get("count_total") or 0), str(d.get("cidr") or "")))
    subnets_out = subnets_out[:100]

    _apache_cache["ts"] = now
    _apache_cache["rows"] = rows_out
    _apache_cache["subnets"] = subnets_out
    _apache_cache["err"] = ""
    return rows_out, subnets_out, ""


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
        apache_rows: Optional[list[dict]] = None,
        apache_subnets: Optional[list[dict]] = None,
        apache_error: str = "",
    ) -> str:
        mode = (policy.mode if policy and policy.mode else "disabled") if policy else "disabled"
        allowed = (policy.allowed_countries if policy and policy.allowed_countries else "") if policy else ""
        blocked = (policy.blocked_countries if policy and policy.blocked_countries else "") if policy else ""
        allowed_set = set(_codes_from_raw(allowed))
        blocked_set = set(_codes_from_raw(blocked))

        apache_rows = list(apache_rows or [])
        apache_subnets = list(apache_subnets or [])

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
    .wrap {{ max-width: none; margin: 0; padding: 5px; }}
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
    .grid {{ display:grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; }}
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
        <div><strong>Apache findings</strong></div>
        <div class=\"kpis\">
          <div><strong>{len(apache_rows)}</strong> IPs</div>
          <div><strong>{len(apache_subnets)}</strong> /24 suggestions</div>
        </div>
      </div>
      <div style=\"padding: 12px 14px;\">
        <div class=\"muted\" style=\"font-size: 0.9rem;\">Scans recent lines from <span class=\"mono\">*_access*</span> and <span class=\"mono\">*_error*</span>. Use buttons to add permanent blocks to the database (admin credentials required per action).</div>
        {f'<div class="alert err" style="margin-top:10px;">{str(apache_error).replace("<","&lt;").replace(">","&gt;")}</div>' if apache_error else ''}
      </div>

      <div style=\"overflow:auto;\">
        <table>
          <thead>
            <tr>
              <th>IP</th>
              <th style=\"width:120px;\">404s</th>
              <th style=\"width:140px;\">Login fails</th>
              <th style=\"width:120px;\">Total</th>
              <th style=\"width:260px;\">Last seen (UTC)</th>
              <th style=\"width:1%;\"></th>
            </tr>
          </thead>
          <tbody>
            {(''.join([
              '<tr>'
              + f'<td class="mono">{str(r.get("ip") or "").replace("<","&lt;").replace(">","&gt;")}</td>'
              + f'<td>{int(r.get("count_404") or 0)}</td>'
              + f'<td>{int(r.get("count_login") or 0)}</td>'
              + f'<td><strong>{int(r.get("count_total") or 0)}</strong></td>'
              + f'<td class="mono">{(r.get("last_seen").astimezone(timezone.utc).isoformat() if isinstance(r.get("last_seen"), datetime) else "")}</td>'
              + '<td style="white-space:nowrap;">'
              + f'<form method="post" action="/add/block" style="display:inline-block; margin-right:8px;">'
              + f'<input type="hidden" name="cidr" value="{str(r.get("ip") or "").replace("\"","&quot;")}/32" />'
              + f'<input type="hidden" name="description" value="apache_findings" />'
              + '<button class="btn danger" type="submit">Block IP</button>'
              + '</form>'
              + '</td>'
              + '</tr>'
            ]) if apache_rows else '<tr><td colspan=6 class="muted">(no findings)</td></tr>')}
          </tbody>
        </table>
      </div>

      <div style=\"overflow:auto; border-top: 1px solid rgba(255,255,255,0.08);\">
        <table>
          <thead>
            <tr>
              <th>Suggested /24</th>
              <th style=\"width:140px;\">Hosts</th>
              <th style=\"width:120px;\">404s</th>
              <th style=\"width:140px;\">Login fails</th>
              <th style=\"width:120px;\">Total</th>
              <th style=\"width:1%;\"></th>
            </tr>
          </thead>
          <tbody>
            {(''.join([
              '<tr>'
              + f'<td class="mono">{str(s.get("cidr") or "").replace("<","&lt;").replace(">","&gt;")}</td>'
              + f'<td>{int(s.get("host_count") or 0)}</td>'
              + f'<td>{int(s.get("count_404") or 0)}</td>'
              + f'<td>{int(s.get("count_login") or 0)}</td>'
              + f'<td><strong>{int(s.get("count_total") or 0)}</strong></td>'
              + '<td style="white-space:nowrap;">'
              + f'<form method="post" action="/add/block" style="display:inline-block;">'
              + f'<input type="hidden" name="cidr" value="{str(s.get("cidr") or "").replace("\"","&quot;")}" />'
              + f'<input type="hidden" name="description" value="apache_findings_subnet" />'
              + '<button class="btn danger" type="submit">Block /24</button>'
              + '</form>'
              + '</td>'
              + '</tr>'
            ]) if apache_subnets else '<tr><td colspan=6 class="muted">(no /24 suggestions)</td></tr>')}
          </tbody>
        </table>
      </div>
    </div>

    <div class=\"panel\">
      <div class=\"panel-top\">
        <div><strong>Country access policy</strong></div>
        <div class=\"kpis\">
          <div><strong>Mode</strong> <span class=\"mono\">{mode}</span></div>
        </div>
      </div>
      <div style=\"padding: 12px 14px;\">
        <form method=\"post\" action=\"/country/update\" style=\"display:grid; grid-template-columns: minmax(220px, 0.8fr) minmax(0, 1fr) minmax(0, 1fr); gap: 10px; align-items: start;\">
          <div>
            <div class=\"muted\" style=\"margin-bottom: 6px;\">Policy mode</div>
            <select name=\"mode\" style=\"width: 100%; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border); background: rgba(255,255,255,0.06); color: var(--text);\">
              <option value=\"disabled\" {('selected' if mode == 'disabled' or not mode else '')}>Disabled</option>
              <option value=\"allow_list\" {('selected' if mode == 'allow_list' else '')}>Allow only listed countries</option>
              <option value=\"block_list\" {('selected' if mode == 'block_list' else '')}>Block listed countries</option>
              <option value=\"allow_all_except_blocked\" {('selected' if mode == 'allow_all_except_blocked' else '')}>Allow all except blocked</option>
            </select>
            <div class=\"muted\" style=\"margin-top: 8px; font-size: 0.9rem;\">This controls whether a country may connect/login. It does <strong>not</strong> exempt them from other rules.</div>
            <div style=\"margin-top: 10px;\">
              <button class=\"btn\" type=\"submit\">Save country policy</button>
            </div>
          </div>

          <div>
            <div class=\"muted\" style=\"margin-bottom: 6px;\">Allowed countries</div>
            <select name=\"allowed_countries\" multiple size=\"12\" style=\"width: 100%; min-height: 260px; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border); background: rgba(255,255,255,0.06); color: var(--text);\">
              {''.join([f'<option value="{code}" {("selected" if code in allowed_set else "")}>{code} - {name}</option>' for code, name in COUNTRY_CHOICES])}
            </select>
          </div>

          <div>
            <div class=\"muted\" style=\"margin-bottom: 6px;\">Blocked countries</div>
            <select name=\"blocked_countries\" multiple size=\"12\" style=\"width: 100%; min-height: 260px; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border); background: rgba(255,255,255,0.06); color: var(--text);\">
              {''.join([f'<option value="{code}" {("selected" if code in blocked_set else "")}>{code} - {name}</option>' for code, name in COUNTRY_CHOICES])}
            </select>
          </div>
        </form>
        <div class=\"muted\" style=\"margin-top: 8px; font-size: 0.9rem;\">Saving requires System Administrator credentials.</div>
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

            def _cidr_sort_key(cidr: str):
                try:
                    net = ipaddress.ip_network(str(cidr), strict=False)
                    return (int(net.version), int(net.network_address), int(net.prefixlen), str(cidr))
                except Exception:
                    return (99, 0, 0, str(cidr))

            IpAllowlist.__table__.create(bind=engine, checkfirst=True)
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            CountryAccessPolicy.__table__.create(bind=engine, checkfirst=True)
            AuditEvent.__table__.create(bind=engine, checkfirst=True)

            allow_rows_local = db.query(IpAllowlist).all()
            allow_rows_local.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))

            block_rows_local = db.query(IpBlocklist).all()
            block_rows_local.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
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
                return (0 if kind == "suspend" else 1, -until_ts, *_cidr_sort_key(cidr))

            blocked_local.sort(key=_sort_key)
            return allow_rows_local, blocked_local, policy_local

        with Session(engine) as db:
            allow_rows, blocked, policy = _load_view_model(db)

        apache_rows, apache_subnets, apache_err = _scan_apache_findings()

        html = _render_page(
            allow_rows,
            blocked,
            policy,
            apache_rows=apache_rows,
            apache_subnets=apache_subnets,
            apache_error=apache_err,
        )
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

        def _cidr_sort_key(cidr: str):
            try:
                net = ipaddress.ip_network(str(cidr), strict=False)
                return (int(net.version), int(net.network_address), int(net.prefixlen), str(cidr))
            except Exception:
                return (99, 0, 0, str(cidr))

        def _cidr_sort_key(cidr: str):
            try:
                net = ipaddress.ip_network(str(cidr), strict=False)
                return (int(net.version), int(net.network_address), int(net.prefixlen), str(cidr))
            except Exception:
                return (99, 0, 0, str(cidr))

        with Session(engine) as db:
            deleted = (
                db.query(IpAllowlist)
                .filter(IpAllowlist.id == entry_id)
                .delete(synchronize_session=False)
            )
            db.commit()

            allow_rows = db.query(IpAllowlist).all()
            allow_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            blocked = []
            block_rows = db.query(IpBlocklist).all()
            block_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            for r in block_rows:
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

        def _cidr_sort_key(cidr: str):
            try:
                net = ipaddress.ip_network(str(cidr), strict=False)
                return (int(net.version), int(net.network_address), int(net.prefixlen), str(cidr))
            except Exception:
                return (99, 0, 0, str(cidr))

        try:
            cidr = _normalize_cidr(raw_cidr)
        except Exception:
            with Session(engine) as db:
                allow_rows = db.query(IpAllowlist).all()
                allow_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
                policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
                blocked = []
                block_rows = db.query(IpBlocklist).all()
                block_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
                for r in block_rows:
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

            allow_rows = db.query(IpAllowlist).all()
            allow_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            blocked = []
            block_rows = db.query(IpBlocklist).all()
            block_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            for r in block_rows:
                _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                blocked.append({"kind": "block", "id": int(r.id), "cidr": str(r.cidr), "until": None, "status": status, "rule": rule_label, "description": str(r.description or "")})

        msg = "Added." if exists is None else "Already present."
        apache_rows, apache_subnets, apache_err = _scan_apache_findings()
        html = _render_page(
            allow_rows,
            blocked,
            policy,
            message=msg,
            apache_rows=apache_rows,
            apache_subnets=apache_subnets,
            apache_error=apache_err,
        )
        return Response(html, mimetype="text/html; charset=utf-8")

    @app.post("/add/block")
    def add_block() -> Response:
        cidr = (request.form.get("cidr") or "").strip()
        desc = (request.form.get("description") or "").strip()
        realm = f"PentaVision Admin Add Block {cidr}"
        maybe = _require_admin_basic_auth(realm)
        if maybe is not None:
            return maybe

        engine = get_user_engine()
        if engine is None:
            abort(503)

        def _cidr_sort_key(cidr: str):
            try:
                net = ipaddress.ip_network(str(cidr), strict=False)
                return (int(net.version), int(net.network_address), int(net.prefixlen), str(cidr))
            except Exception:
                return (99, 0, 0, str(cidr))

        try:
            cidr_norm = _normalize_cidr(cidr)
        except Exception:
            with Session(engine) as db:
                allow_rows = db.query(IpAllowlist).all()
                allow_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
                policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
                blocked = []
                block_rows = db.query(IpBlocklist).all()
                block_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
                for r in block_rows:
                    _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                    blocked.append({"kind": "block", "id": int(r.id), "cidr": str(r.cidr), "until": None, "status": status, "rule": rule_label, "description": str(r.description or "")})
            apache_rows, apache_subnets, apache_err = _scan_apache_findings()
            html = _render_page(
                allow_rows,
                blocked,
                policy,
                error="Invalid IP/CIDR",
                apache_rows=apache_rows,
                apache_subnets=apache_subnets,
                apache_error=apache_err,
            )
            return Response(html, status=400, mimetype="text/html; charset=utf-8")

        with Session(engine) as db:
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            exists = db.scalar(select(IpBlocklist).where(IpBlocklist.cidr == cidr_norm))
            if exists is None:
                entry = IpBlocklist(cidr=cidr_norm, description=(desc or "manual")[:256])
                db.add(entry)
                db.commit()

            allow_rows = db.query(IpAllowlist).all()
            allow_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            blocked = []
            block_rows = db.query(IpBlocklist).all()
            block_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            for r in block_rows:
                _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                blocked.append({"kind": "block", "id": int(r.id), "cidr": str(r.cidr), "until": None, "status": status, "rule": rule_label, "description": str(r.description or "")})

        msg = "Blocked." if exists is None else "Already blocked."
        apache_rows, apache_subnets, apache_err = _scan_apache_findings()
        html = _render_page(
            allow_rows,
            blocked,
            policy,
            message=msg,
            apache_rows=apache_rows,
            apache_subnets=apache_subnets,
            apache_error=apache_err,
        )
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

            allow_rows = db.query(IpAllowlist).all()
            allow_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            blocked = []
            block_rows = db.query(IpBlocklist).all()
            block_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            for r in block_rows:
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

            allow_rows = db.query(IpAllowlist).all()
            allow_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            blocked = []
            block_rows = db.query(IpBlocklist).all()
            block_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            for r in block_rows:
                _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                blocked.append({"kind": "block", "id": int(r.id), "cidr": str(r.cidr), "until": None, "status": status, "rule": rule_label, "description": str(r.description or "")})

        msg = "Removed." if deleted else "Entry not found."
        html = _render_page(allow_rows, blocked, policy, message=msg)
        return Response(html, mimetype="text/html; charset=utf-8")

    @app.post("/country/update")
    def update_country_policy() -> Response:
        realm = "PentaVision Admin Update Country Policy"
        maybe = _require_admin_basic_auth(realm)
        if maybe is not None:
            return maybe

        engine = get_user_engine()
        if engine is None:
            abort(503)

        mode = (request.form.get("mode") or "").strip()
        allowed_codes = request.form.getlist("allowed_countries")
        blocked_codes = request.form.getlist("blocked_countries")

        mode_norm = mode.strip().lower() or "disabled"
        valid_modes = {"disabled", "allow_list", "block_list", "allow_all_except_blocked"}
        if mode_norm not in valid_modes:
            mode_norm = "disabled"

        known = {str(code).upper() for code, _ in COUNTRY_CHOICES}
        allowed_norm = sorted({str(c).strip().upper() for c in allowed_codes if str(c).strip().upper() in known})
        blocked_norm = sorted({str(c).strip().upper() for c in blocked_codes if str(c).strip().upper() in known})

        allowed_str = ",".join(allowed_norm)
        blocked_str = ",".join(blocked_norm)

        with Session(engine, expire_on_commit=False) as db:
            CountryAccessPolicy.__table__.create(bind=engine, checkfirst=True)
            policy = db.query(CountryAccessPolicy).order_by(CountryAccessPolicy.id.asc()).first()
            if policy is None:
                policy = CountryAccessPolicy()
                db.add(policy)
            policy.mode = mode_norm
            policy.allowed_countries = allowed_str or None
            policy.blocked_countries = blocked_str or None
            db.add(policy)
            db.commit()

            try:
                db.refresh(policy)
                db.expunge(policy)
            except Exception:
                pass

            def _cidr_sort_key(cidr: str):
                try:
                    net = ipaddress.ip_network(str(cidr), strict=False)
                    return (int(net.version), int(net.network_address), int(net.prefixlen), str(cidr))
                except Exception:
                    return (99, 0, 0, str(cidr))

            allow_rows = db.query(IpAllowlist).all()
            allow_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))

            blocked_rows = []
            block_rows = db.query(IpBlocklist).all()
            block_rows.sort(key=lambda r: _cidr_sort_key(str(r.cidr)))
            for r in block_rows:
                _rule_key, status, rule_label = _blocked_reason_from_desc(str(r.description or ""))
                blocked_rows.append({"kind": "block", "id": int(r.id), "cidr": str(r.cidr), "until": None, "status": status, "rule": rule_label, "description": str(r.description or "")})

        msg = "Country access policy updated."
        html = _render_page(allow_rows, blocked_rows, policy, message=msg)
        return Response(html, mimetype="text/html; charset=utf-8")

    return app
