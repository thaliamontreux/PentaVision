from __future__ import annotations

import csv
import io
import ipaddress
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from flask import Flask, Response, abort, request
from sqlalchemy import text
from sqlalchemy.orm import Session

from .config import load_config
from .db import get_user_engine
from .logging_utils import log_event
from .models import BlocklistDistributionSettings, IpAllowlist, IpBlocklist


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if ip:
            return ip
    return request.remote_addr or ""


def _parse_allowlist_networks(rows: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for raw in rows:
        raw = str(raw or "").strip()
        if not raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
    return nets


def _builtin_never_block_networks() -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    # Never block LAN
    nets.append(ipaddress.ip_network("192.168.250.0/24"))

    # Never block this fixed IP range (expand to hosts to be exact)
    start = ipaddress.ip_address("96.45.17.168")
    end = ipaddress.ip_address("96.45.17.174")
    cur = start
    while cur <= end:
        nets.append(ipaddress.ip_network(f"{cur}/32"))
        cur = ipaddress.ip_address(int(cur) + 1)
    return nets


def _consumer_allow_networks() -> List[ipaddress._BaseNetwork]:
    raw = os.environ.get("PENTAVISION_BLOCKLIST_CONSUMER_ALLOW_CIDRS", "").strip()
    cidrs = [c.strip() for c in raw.split(",") if c.strip()]
    nets = _parse_allowlist_networks(cidrs)
    # Always allow loopback callers.
    nets.extend(_parse_allowlist_networks(["127.0.0.1/32", "::1/128"]))
    return nets


def _load_distribution_settings(engine) -> dict[str, object]:
    settings: dict[str, object] = {
        "enabled": True,
        "consumer_allow_cidrs": "",
        "token_enabled": False,
        "token": "",
        "ttl_seconds": None,
        "rate_limit_per_min": None,
    }

    try:
        BlocklistDistributionSettings.__table__.create(bind=engine, checkfirst=True)
        with Session(engine) as session:
            row = (
                session.query(BlocklistDistributionSettings)
                .order_by(BlocklistDistributionSettings.id.desc())
                .first()
            )
        if row is None:
            return settings

        settings["enabled"] = bool(row.enabled) if row.enabled is not None else True
        settings["consumer_allow_cidrs"] = str(row.consumer_allow_cidrs or "")
        settings["token_enabled"] = bool(row.token_enabled) if row.token_enabled is not None else False
        settings["token"] = str(row.token or "")
        settings["ttl_seconds"] = row.ttl_seconds
        settings["rate_limit_per_min"] = row.rate_limit_per_min
        return settings
    except Exception:  # noqa: BLE001
        return settings


def _client_allowed(ip: str, allow_nets: List[ipaddress._BaseNetwork]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in allow_nets:
        try:
            if addr in net:
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


class _RateLimiter:
    def __init__(self, per_minute: int) -> None:
        self.per_minute = max(1, int(per_minute or 60))
        self._buckets: Dict[str, List[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        window_start = now - 60.0
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = []
            self._buckets[key] = bucket
        # Drop old timestamps
        while bucket and bucket[0] < window_start:
            bucket.pop(0)
        if len(bucket) >= self.per_minute:
            return False
        bucket.append(now)
        return True


def _dt_iso(val: Any) -> str:
    if not val:
        return ""
    try:
        if isinstance(val, datetime):
            return val.astimezone(timezone.utc).isoformat()
    except Exception:  # noqa: BLE001
        pass
    return str(val)


def _determine_type(cidr: str) -> str:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return "host" if net.prefixlen == net.max_prefixlen else "subnet"
    except Exception:  # noqa: BLE001
        return "host"


def _exclude_by_allowlist(
    blocks: List[Tuple[str, Optional[datetime], Optional[str]]],
    allow_nets: List[ipaddress._BaseNetwork],
) -> List[Tuple[str, Optional[datetime], Optional[str]]]:
    out: List[Tuple[str, Optional[datetime], Optional[str]]] = []

    for cidr, created_at, desc in blocks:
        try:
            bnet = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue

        excluded = False
        for anet in allow_nets:
            try:
                # Allowlist supersedes: if any overlap, exclude the block.
                if bnet.overlaps(anet):
                    excluded = True
                    break
            except Exception:  # noqa: BLE001
                continue
        if not excluded:
            out.append((str(bnet), created_at, desc))

    return out


def _load_blocks_for_publication(engine) -> Tuple[List[Tuple[str, Optional[datetime], Optional[str]]], List[ipaddress._BaseNetwork]]:
    IpAllowlist.__table__.create(bind=engine, checkfirst=True)
    IpBlocklist.__table__.create(bind=engine, checkfirst=True)

    with Session(engine) as session:
        allow_rows = session.query(IpAllowlist.cidr).all()
        block_rows = session.query(IpBlocklist.cidr, IpBlocklist.created_at, IpBlocklist.description).all()

    dynamic_allow = [r[0] for r in allow_rows]
    allow_nets_effective = _parse_allowlist_networks(dynamic_allow)
    allow_nets_effective.extend(_builtin_never_block_networks())

    blocks_in: List[Tuple[str, Optional[datetime], Optional[str]]] = [
        (str(c), a, d) for (c, a, d) in block_rows
    ]
    blocks = _exclude_by_allowlist(blocks_in, allow_nets_effective)
    return blocks, allow_nets_effective


def create_blocklist_service() -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(load_config())
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    # Dynamic settings cache (UserDB-backed, with env fallback).
    _settings_cache: dict[str, object] = {}
    _settings_cache_at: float = 0.0

    def _effective_settings() -> dict[str, object]:
        nonlocal _settings_cache, _settings_cache_at
        now = time.time()
        if _settings_cache and (now - _settings_cache_at) < 5.0:
            return _settings_cache

        engine = get_user_engine()
        if engine is None:
            db_settings: dict[str, object] = {
                "enabled": True,
                "consumer_allow_cidrs": "",
                "token_enabled": False,
                "token": "",
                "ttl_seconds": None,
                "rate_limit_per_min": None,
            }
        else:
            db_settings = _load_distribution_settings(engine)

        # Env fallback defaults.
        env_allow = os.environ.get("PENTAVISION_BLOCKLIST_CONSUMER_ALLOW_CIDRS", "").strip()
        env_token = (os.environ.get("PENTAVISION_BLOCKLIST_TOKEN") or "").strip()
        ttl_raw = (os.environ.get("PENTAVISION_BLOCKLIST_TTL_SECONDS") or "5").strip()
        rate_raw = (os.environ.get("PENTAVISION_BLOCKLIST_RATE_LIMIT_PER_MIN") or "60").strip()

        try:
            env_ttl = max(0, min(int(ttl_raw), 60))
        except ValueError:
            env_ttl = 5
        try:
            env_rate = int(rate_raw)
        except ValueError:
            env_rate = 60

        ttl_seconds = db_settings.get("ttl_seconds")
        if ttl_seconds is None:
            ttl_seconds = env_ttl
        else:
            try:
                ttl_seconds = max(0, min(int(ttl_seconds), 60))
            except Exception:  # noqa: BLE001
                ttl_seconds = env_ttl

        rate_limit = db_settings.get("rate_limit_per_min")
        if rate_limit is None:
            rate_limit = env_rate
        else:
            try:
                rate_limit = int(rate_limit)
            except Exception:  # noqa: BLE001
                rate_limit = env_rate

        token_enabled = bool(db_settings.get("token_enabled"))
        token = str(db_settings.get("token") or "").strip() if token_enabled else ""
        if token_enabled and not token:
            token = env_token

        allow_raw = str(db_settings.get("consumer_allow_cidrs") or "").strip()
        if not allow_raw:
            allow_raw = env_allow

        merged = {
            "enabled": bool(db_settings.get("enabled", True)),
            "consumer_allow_cidrs": allow_raw,
            "token": token,
            "ttl_seconds": ttl_seconds,
            "rate_limit_per_min": max(1, int(rate_limit or 60)),
        }
        _settings_cache = merged
        _settings_cache_at = now
        return merged

    limiter = _RateLimiter(60)

    @app.before_request
    def _guard() -> None:
        settings = _effective_settings()
        if not bool(settings.get("enabled")):
            abort(503)

        ip = _client_ip()
        allow_raw = str(settings.get("consumer_allow_cidrs") or "").strip()
        allow_nets = _parse_allowlist_networks([c.strip() for c in allow_raw.split(",") if c.strip()])
        allow_nets.extend(_parse_allowlist_networks(["127.0.0.1/32", "::1/128"]))
        if allow_nets and not _client_allowed(ip, allow_nets):
            abort(403)

        token = str(settings.get("token") or "").strip()
        if token:
            auth = (request.headers.get("Authorization") or "").strip()
            if auth != f"Bearer {token}":
                abort(401)

        try:
            limiter.per_minute = max(1, int(settings.get("rate_limit_per_min") or 60))
        except Exception:  # noqa: BLE001
            limiter.per_minute = 60
        if not limiter.allow(ip or "?"):
            abort(429)

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
        health_text = "ok"
        health_ok = True
        blocks: List[Tuple[str, Optional[datetime], Optional[str]]] = []
        if engine is None:
            health_text = "not_ok: no_user_db"
            health_ok = False
        else:
            try:
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                blocks, _ = _load_blocks_for_publication(engine)
            except Exception as exc:  # noqa: BLE001
                health_text = f"not_ok: db_error: {type(exc).__name__}"
                health_ok = False

        def _sort_key(row: Tuple[str, Optional[datetime], Optional[str]]):
            cidr = row[0]
            t = _determine_type(cidr)
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                addr_int = int(net.network_address)
                plen = int(net.prefixlen)
            except Exception:  # noqa: BLE001
                addr_int = 0
                plen = 0
            return (0 if t == "host" else 1, addr_int, plen, cidr)

        blocks.sort(key=_sort_key)

        now = datetime.now(timezone.utc).isoformat()
        badge_bg = "#22c55e" if health_ok and health_text.strip().lower() == "ok" else "#ef4444"

        html = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>PentaVision Blocklist</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: rgba(255, 255, 255, 0.06);
      --panel2: rgba(255, 255, 255, 0.04);
      --text: #e5e7eb;
      --muted: rgba(229, 231, 235, 0.7);
      --border: rgba(255, 255, 255, 0.12);
      --accent: #60a5fa;
    }}
    body {{
      margin: 0;
      background: radial-gradient(1200px 600px at 20% 0%, rgba(96,165,250,0.18), transparent 60%), var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
    .header {{ display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; }}
    h1 {{ margin: 0; font-size: 1.6rem; letter-spacing: 0.2px; }}
    .sub {{ margin-top: 6px; color: var(--muted); font-size: 0.95rem; }}
    .actions {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
    .btn {{
      display: inline-flex; align-items: center; gap: 8px;
      padding: 10px 12px; border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--panel);
      color: var(--text);
      text-decoration: none;
      font-weight: 600;
    }}
    .btn:hover {{ border-color: rgba(96,165,250,0.6); }}
    .panel {{
      margin-top: 16px;
      background: linear-gradient(180deg, rgba(255,255,255,0.08), rgba(255,255,255,0.04));
      border: 1px solid var(--border);
      border-radius: 14px;
      overflow: hidden;
    }}
    .panel-top {{
      display: flex; justify-content: space-between; align-items: center;
      padding: 14px 16px;
      background: rgba(255,255,255,0.04);
      border-bottom: 1px solid var(--border);
    }}
    .kpis {{ display: flex; gap: 14px; flex-wrap: wrap; color: var(--muted); font-size: 0.92rem; }}
    .kpi strong {{ color: var(--text); font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 0.92rem; }}
    th {{ text-align: left; color: rgba(229,231,235,0.85); font-weight: 700; background: rgba(255,255,255,0.03); }}
    tr:hover td {{ background: rgba(96,165,250,0.06); }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace; }}
    .badge {{
      position: fixed;
      left: 16px;
      bottom: 64px;
      z-index: 9999;
      padding: 10px 12px;
      border-radius: 10px;
      background: {badge_bg};
      color: #000;
      border: 1px solid rgba(0,0,0,0.15);
      box-shadow: 0 10px 30px rgba(0,0,0,0.35);
      min-width: 220px;
    }}
    .badge .title {{ font-weight: 800; font-size: 0.9rem; }}
    .badge .msg {{ margin-top: 2px; font-size: 0.85rem; }}
    .empty {{ padding: 18px; color: var(--muted); }}
    .pv-status-bar {{
      position: fixed;
      left: 0;
      right: 0;
      bottom: 0;
      z-index: 9998;
      display: flex;
      gap: 0.75rem;
      align-items: center;
      padding: 0.55rem 0.9rem;
      box-shadow: 0 -10px 30px rgba(0,0,0,0.55);
      background: linear-gradient(90deg, rgba(15,23,42,0.98), rgba(2,6,23,0.96));
      color: #e5e7eb;
      font-weight: 700;
      font-size: 0.92rem;
      border-top: 1px solid rgba(56,189,248,0.22);
      backdrop-filter: blur(10px);
    }}
    .pv-status-sep {{ opacity: 0.55; }}
    .pv-status-label {{ white-space: nowrap; color: rgba(229,231,235,0.78); }}
    .pv-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }}
  </style>
</head>
<body>
  <div class=\"wrap\" style=\"padding-bottom: 80px;\">
    <div class=\"header\">
      <div>
        <h1>Blocklist Publication Service</h1>
        <div class=\"sub\">Generated at <span class=\"mono\">{now}</span>. This view matches published output after allowlist exclusions.</div>
      </div>
      <div class=\"actions\">
        <a class=\"btn\" href=\"/blocklist.csv\">Download CSV</a>
        <a class=\"btn\" href=\"/healthz\">Health</a>
      </div>
    </div>

    <div class=\"panel\">
      <div class=\"panel-top\">
        <div class=\"kpis\">
          <div class=\"kpi\"><strong>{len(blocks)}</strong> published blocks</div>
          <div class=\"kpi\">Source: <strong class=\"mono\">USER_DB_URL</strong></div>
        </div>
        <div class=\"kpis\">Tip: point pfSense alias URL to <strong class=\"mono\">/blocklist.csv</strong></div>
      </div>

      <div style=\"overflow:auto;\">
        <table>
          <thead>
            <tr>
              <th style=\"width:110px;\">Type</th>
              <th>IP / CIDR</th>
              <th style=\"width:240px;\">Detected</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
"""

        if not blocks:
            html += "<tr><td colspan=\"4\" class=\"empty\">No blocks currently published.</td></tr>"
        else:
            for cidr, created_at, desc in blocks:
                t = _determine_type(cidr)
                detected = _dt_iso(created_at)
                reason = (str(desc).strip() if desc else "BLOCKLIST")
                reason = reason.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html += (
                    "<tr>"
                    f"<td>{t}</td>"
                    f"<td class=\"mono\">{cidr}</td>"
                    f"<td class=\"mono\">{detected}</td>"
                    f"<td>{reason}</td>"
                    "</tr>"
                )

        html += f"""
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div id=\"healthBadge\" class=\"badge\">
    <div class=\"title\">System Health</div>
    <div id=\"healthMsg\" class=\"msg\">{health_text}</div>
  </div>

  <div id=\"pvStatusBar\" class=\"pv-status-bar\" role=\"status\" aria-live=\"polite\">
    <span id=\"pvStatusDatetime\" class=\"pv-mono\"></span>
    <span class=\"pv-status-sep\">|</span>
    <span class=\"pv-status-label\">System:</span>
    <span id=\"pvStatusSystem\" style=\"white-space: nowrap;\">{health_text}</span>
    <span class=\"pv-status-sep\">|</span>
    <span class=\"pv-status-label\">Last error:</span>
    <span id=\"pvStatusLastError\" style=\"font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;\"></span>
  </div>

  <script>
    (function () {
      const el = document.getElementById('pvStatusDatetime');
      if (!el) return;
      function pad(n) { return String(n).padStart(2, '0'); }
      function tick() {
        const d = new Date();
        const mm = pad(d.getMonth() + 1);
        const dd = pad(d.getDate());
        const yy = pad(d.getFullYear() % 100);
        const hh = pad(d.getHours());
        const mi = pad(d.getMinutes());
        el.textContent = mm + '/' + dd + '/' + yy + ' ' + hh + ':' + mi;
      }
      tick();
      window.setInterval(tick, 1000);
    })();

    (function () {
      const lastEl = document.getElementById('pvStatusLastError');
      if (!lastEl) return;
      function setLastError(message) {
        lastEl.textContent = String(message || '');
        try { window.sessionStorage.setItem('pvBlocklistLastError', String(message || '')); } catch (e) {}
      }
      try {
        const stored = window.sessionStorage.getItem('pvBlocklistLastError') || '';
        if (stored) lastEl.textContent = stored;
      } catch (e) {}
      window.pvSetBlocklistLastError = setLastError;
    })();

    async function pollHealth() {{
      try {{
        const r = await fetch('/healthz', {{ cache: 'no-store' }});
        const t = (await r.text()).trim();
        const ok = r.ok && t.toLowerCase() === 'ok';
        const badge = document.getElementById('healthBadge');
        const msg = document.getElementById('healthMsg');
        const sys = document.getElementById('pvStatusSystem');
        msg.textContent = t || (ok ? 'ok' : 'not_ok');
        if (sys) sys.textContent = msg.textContent;
        badge.style.background = ok ? '#22c55e' : '#ef4444';
        badge.style.color = '#000';
      }} catch (e) {{
        const badge = document.getElementById('healthBadge');
        const msg = document.getElementById('healthMsg');
        const sys = document.getElementById('pvStatusSystem');
        msg.textContent = 'not_ok: health_check_failed';
        if (sys) sys.textContent = msg.textContent;
        badge.style.background = '#ef4444';
        badge.style.color = '#000';
        try {
          if (window.pvSetBlocklistLastError) {
            window.pvSetBlocklistLastError('health: ' + (e && e.message ? e.message : String(e || 'failed')));
          }
        } catch (err) {}
      }}
    }}
    pollHealth();
    setInterval(pollHealth, 5000);
  </script>
</body>
</html>"""

        return Response(html, mimetype="text/html; charset=utf-8")

    @app.get("/blocklist.csv")
    def blocklist_csv() -> Response:
        engine = get_user_engine()
        if engine is None:
            abort(503)

        blocks, _ = _load_blocks_for_publication(engine)

        # Deterministic ordering: type then ip/cidr text
        def _sort_key(row: Tuple[str, Optional[datetime], Optional[str]]):
            cidr = row[0]
            t = _determine_type(cidr)
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                addr_int = int(net.network_address)
                plen = int(net.prefixlen)
            except Exception:  # noqa: BLE001
                addr_int = 0
                plen = 0
            return (0 if t == "host" else 1, addr_int, plen, cidr)

        blocks.sort(key=_sort_key)

        now = datetime.now(timezone.utc)
        source_system = os.environ.get("PENTAVISION_SOURCE_SYSTEM", "pentavision").strip() or "pentavision"

        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(
            [
                "type",
                "ip_or_cidr",
                "first_detected_timestamp",
                "last_detected_timestamp",
                "block_expiry_timestamp",
                "reason_code",
                "risk_score",
                "source_system",
                "asn",
                "attack_category",
                "enforcement_level",
            ]
        )

        for cidr, created_at, desc in blocks:
            detected = created_at
            # We only have one timestamp today; publish it as both first+last.
            first_ts = _dt_iso(detected)
            last_ts = _dt_iso(detected)
            expiry_ts = ""  # no expiry model yet

            reason_code = "BLOCKLIST"
            attack_category = ""
            risk_score = "50"
            enforcement_level = "persistent"
            asn = ""

            if desc:
                # Keep it strict and machine-friendly; no presentation formatting.
                d = str(desc).strip()
                if d:
                    reason_code = d[:64]

            writer.writerow(
                [
                    _determine_type(cidr),
                    cidr,
                    first_ts,
                    last_ts,
                    expiry_ts,
                    reason_code,
                    risk_score,
                    source_system,
                    asn,
                    attack_category,
                    enforcement_level,
                ]
            )

        csv_text = output.getvalue()

        try:
            ip = _client_ip()
            app.logger.info(
                "blocklist_csv_published ip=%s blocks=%s at=%s",
                ip,
                len(blocks),
                now.isoformat(),
            )
        except Exception:  # noqa: BLE001
            pass

        try:
            log_event(
                "BLOCKLIST_PUBLISHED",
                user_id=None,
                details=f"ip={_client_ip()}, blocks={len(blocks)}",
            )
        except Exception:  # noqa: BLE001
            pass

        settings = _effective_settings()
        ttl = int(settings.get("ttl_seconds") or 5)
        generated_at = datetime.now(timezone.utc).isoformat()

        resp = Response(csv_text, mimetype="text/csv; charset=utf-8")
        resp.headers["Cache-Control"] = f"no-store, no-cache, max-age={ttl}, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["X-Blocklist-Generated-At"] = generated_at
        return resp

    return app
