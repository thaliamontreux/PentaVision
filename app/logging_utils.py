from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
import os

from flask import Request, has_request_context, request, current_app
from sqlalchemy import func
from sqlalchemy.orm import Session

from .db import get_user_engine
from .models import AuditEvent, CountryAccessPolicy, IpAllowlist, IpBlocklist


_geoip_reader = None
_geoip_init_attempted = False


_PV_LOG_ROOT = Path("/dev/shm/pentavision/logs")
_PV_LOG_MAX_BYTES = 30 * 1024 * 1024
_pv_log_lock = threading.Lock()
_pv_log_file_locks: dict[str, threading.Lock] = {}


def _pv_log_path(category: str) -> Path:
    cat = (category or "").strip().lower() or "system"
    return _PV_LOG_ROOT / cat / "logfile"


def _pv_log_lock_for(category: str) -> threading.Lock:
    cat = (category or "").strip().lower() or "system"
    with _pv_log_lock:
        lock = _pv_log_file_locks.get(cat)
        if lock is None:
            lock = threading.Lock()
            _pv_log_file_locks[cat] = lock
        return lock


def _pv_log_suffix_today() -> str:
    # MM-DD-YYYY
    now = datetime.now(timezone.utc)
    return now.strftime("%m-%d-%Y")


def _pv_rotate_existing(path: Path) -> None:
    if not path.exists():
        return
    suffix = _pv_log_suffix_today()
    base = path.with_name(f"{path.name}.{suffix}")
    target = base
    try:
        size = path.stat().st_size
    except Exception:  # noqa: BLE001
        size = 0

    if size >= _PV_LOG_MAX_BYTES:
        # Always add an index when >30MB.
        for i in range(1, 1001):
            cand = path.with_name(f"{path.name}.{suffix}.{i}")
            if not cand.exists():
                target = cand
                break
    else:
        if target.exists():
            for i in range(1, 1001):
                cand = path.with_name(f"{path.name}.{suffix}.{i}")
                if not cand.exists():
                    target = cand
                    break

    try:
        path.rename(target)
    except Exception:  # noqa: BLE001
        return


def pv_rotate_logs_on_startup() -> None:
    """Rotate all category logfiles on log server startup.

    Implements: upon restarting pentavision log server it is to move any log file
    to logfile.MM-DD-YYYY (or .(1-1000)).
    """

    for cat in ("system", "modules", "rtsp", "rtmp", "security"):
        path = _pv_log_path(cat)
        lock = _pv_log_lock_for(cat)
        with lock:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
            except Exception:  # noqa: BLE001
                continue
            _pv_rotate_existing(path)


def pv_log(
    category: str,
    level: str,
    message: str,
    *,
    component: str = "",
    **fields,
) -> None:
    """Write a JSONL log line to /dev/shm/pentavision/logs/<category>/logfile.

    This is best-effort and must never raise.
    """

    cat = (category or "").strip().lower() or "system"
    lvl = (level or "").strip().lower() or "info"
    msg = str(message or "")

    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": lvl,
        "category": cat,
        "component": str(component or "") or None,
        "message": msg,
        "fields": fields or None,
    }
    line = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8", errors="replace"
    )

    path = _pv_log_path(cat)
    lock = _pv_log_lock_for(cat)
    with lock:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:  # noqa: BLE001
            return

        try:
            # Runtime size-based rollover.
            if path.exists() and path.stat().st_size >= _PV_LOG_MAX_BYTES:
                _pv_rotate_existing(path)
        except Exception:  # noqa: BLE001
            pass

        try:
            with open(path, "ab") as f:
                f.write(line)
        except Exception:  # noqa: BLE001
            return


def pv_log_exception(
    category: str,
    message: str,
    *,
    component: str = "",
    exc: Optional[BaseException] = None,
    **fields,
) -> None:
    text = ""
    try:
        if exc is not None:
            text = f"{type(exc).__name__}: {str(exc)[:500]}"
    except Exception:  # noqa: BLE001
        text = ""
    pv_log(
        category,
        "error",
        message,
        component=component,
        exception=text,
        **fields,
    )


def _client_ip() -> Optional[str]:
    if not has_request_context():
        return None
    req: Request = request
    # Simple best-effort: honor common proxy header if present, else remote_addr.
    forwarded = req.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the list
        return forwarded.split(",")[0].strip()
    return req.remote_addr


def log_event(event_type: str, user_id: Optional[int] = None, details: str = "") -> None:
    """Persist a security/audit event to the user database.

    This is best-effort: if the DB is not configured or an error occurs, the
    function will return silently so it never breaks the main request flow.
    """

    engine = get_user_engine()
    if engine is None:
        return

    ip = _client_ip()

    try:
        with Session(engine) as session:
            event = AuditEvent(user_id=user_id, event_type=event_type, ip=ip, details=details)
            session.add(event)
            session.commit()
    except Exception:  # noqa: BLE001
        # Do not raise from logging path.
        return


def log_event_for_ip(
    event_type: str,
    ip: str,
    *,
    user_id: Optional[int] = None,
    details: str = "",
) -> None:
    engine = get_user_engine()
    if engine is None:
        return
    ip_val = str(ip or "").strip()
    if not ip_val:
        return
    try:
        with Session(engine) as session:
            event = AuditEvent(
                user_id=user_id,
                event_type=str(event_type),
                ip=ip_val,
                details=str(details or ""),
            )
            session.add(event)
            session.commit()
    except Exception:  # noqa: BLE001
        return


def _env_consumer_allow_networks() -> list:
    # Backwards/forwards compatible: support both env var spellings.
    raw = os.environ.get("PENTAVISION_BLOCKLIST_CONSUMER_ALLOW_CIDRS", "").strip()
    if not raw:
        raw = os.environ.get("PENTAVISION_BLOCKLIST_CONSUMER_ALLOW_CIDR", "").strip()
    if not raw:
        raw = os.environ.get("PENTAVISION_BLOCKLIST_ALLOW_CIDRS", "").strip()
    parts = [c.strip() for c in raw.split(",") if c.strip()]
    nets = []
    for c in parts + ["127.0.0.1/32", "::1/128"]:
        try:
            nets.append(ip_network(c, strict=False))
        except ValueError:
            continue
    return nets


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_until(details: str) -> Optional[datetime]:
    # details format: "until=<iso> ..."
    text = str(details or "")
    for part in text.split():
        if part.startswith("until="):
            val = part.split("=", 1)[1].strip()
            try:
                return datetime.fromisoformat(val)
            except Exception:  # noqa: BLE001
                return None
    return None


def _ip_in_blocklist(ip: str) -> bool:
    engine = get_user_engine()
    if engine is None:
        return False

    ip_str = str(ip or "").strip()
    if not ip_str:
        return False

    try:
        addr = ip_address(ip_str)
    except ValueError:
        return False

    builtin_cidrs = ("192.168.250.0/24",)
    for cidr in builtin_cidrs:
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr in net:
            return True

    # Environment-based consumer allowlist (never block)
    for net in _env_consumer_allow_networks():
        try:
            if addr in net:
                return True
        except Exception:
            continue

    try:
        with Session(engine) as session:
            IpAllowlist.__table__.create(bind=engine, checkfirst=True)
            entries = session.query(IpAllowlist.cidr).all()
        for (cidr,) in entries:
            try:
                net = ip_network(str(cidr), strict=False)
            except ValueError:
                continue
            if addr in net:
                return True
    except Exception:  # noqa: BLE001
        return False

    return False
    try:
        addr = ip_address(str(ip))
    except ValueError:
        return False
    try:
        with Session(engine) as session:
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            rows = session.query(IpBlocklist.cidr).all()
        for (cidr,) in rows:
            try:
                net = ip_network(str(cidr), strict=False)
            except ValueError:
                continue
            try:
                if addr in net:
                    return True
            except Exception:
                continue
    except Exception:  # noqa: BLE001
        return False
    return False


def _set_ip_suspend(event_type: str, ip: str, until: datetime, details: str = "") -> None:
    engine = get_user_engine()
    if engine is None:
        return
    try:
        with Session(engine) as session:
            AuditEvent.__table__.create(bind=engine, checkfirst=True)
            session.add(
                AuditEvent(
                    user_id=None,
                    event_type=str(event_type),
                    ip=str(ip),
                    details=(f"until={until.isoformat()} " + str(details or "")).strip(),
                )
            )
            session.commit()
    except Exception:  # noqa: BLE001
        return


def _ip_is_allowlisted(ip: str) -> bool:
    """Return True if the given IP string is present in the allowlist.

    The allowlist stores CIDR entries (e.g. 192.0.2.0/24 or 203.0.113.5), and
    we treat single-host entries as /32 (or /128 for IPv6). Any DB or parsing
    errors are treated as not allowlisted to avoid silently disabling
    protections.
    """

    engine = get_user_engine()
    if engine is None:
        return False


def _add_blocklist_cidr(cidr: str, reason: str = "") -> None:
    engine = get_user_engine()
    if engine is None:
        return
    try:
        with Session(engine) as session:
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            exists = session.query(IpBlocklist.id).filter(IpBlocklist.cidr == cidr).first()
            if exists is None:
                entry = IpBlocklist(cidr=cidr, description=reason or None)
                session.add(entry)
                session.commit()
                log_event("SECURITY_IP_AUTO_BLOCK", details=f"cidr={cidr} reason={reason}")
                pv_log(
                    "security",
                    "warn",
                    "security_ip_auto_block",
                    component="logging_utils",
                    cidr=str(cidr),
                    reason=str(reason or ""),
                )
    except Exception:
        return


def _cidr24_for_ipv4(ip_str: str) -> Optional[str]:
    try:
        ip_obj = ip_address(ip_str)
    except ValueError:
        return None
    if isinstance(ip_obj, IPv4Address):
        parts = ip_str.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return None


def _escalate_network_if_needed(ip_str: str) -> None:
    # If 3 or more hosts in the same /24 are already blocked, block the whole /24.
    cidr24 = _cidr24_for_ipv4(ip_str)
    if not cidr24:
        return
    engine = get_user_engine()
    if engine is None:
        return
    try:
        with Session(engine) as session:
            rows = session.query(IpBlocklist.cidr).all()
            count_hosts = 0
            for (c,) in rows:
                try:
                    net = ip_network(c, strict=False)
                except ValueError:
                    continue
                try:
                    if net.prefixlen == 32 and str(net.supernet(new_prefix=24)) == cidr24:
                        count_hosts += 1
                except Exception:
                    continue
            if count_hosts >= 3:
                # Do not block if env-allowlisted network
                for env_net in _env_consumer_allow_networks():
                    try:
                        if ip_address(ip_str) in env_net:
                            return
                    except Exception:
                        continue
                _add_blocklist_cidr(cidr24, reason="escalate_network_after_multiple_hosts")
    except Exception:
        return


def record_invalid_url_attempt(path: str) -> None:
    """Record a 404 attempt and auto-block abusive IPs.

    If an IP triggers >5 invalid URLs, add the IP/32 to IpBlocklist (unless allowlisted
    via DB or PENTAVISION_BLOCKLIST_CONSUMER_ALLOW_CIDRS). If multiple hosts in the same
    /24 are blocked, escalate by blocking the /24.
    """
    engine = get_user_engine()
    if engine is None:
        return
    ip = _client_ip()
    if not ip:
        return
    record_invalid_url_attempt_for_ip(ip, path)
    return


def record_invalid_url_attempt_for_ip(ip: str, path: str) -> None:
    engine = get_user_engine()
    if engine is None:
        return
    ip = str(ip or "").strip()
    if not ip:
        return
    if _ip_is_allowlisted(ip):
        return
    log_event_for_ip("SECURITY_URL_404", ip, details=f"path={path}")
    pv_log(
        "security",
        "warn",
        "security_url_404",
        component="logging_utils",
        ip=str(ip),
        path=str(path or "")[:512],
    )
    try:
        now = _utcnow()
        day_ago = now - timedelta(days=1)
        with Session(engine) as session:
            AuditEvent.__table__.create(bind=engine, checkfirst=True)
            cnt = (
                session.query(func.count(AuditEvent.id))
                .filter(
                    AuditEvent.ip == ip,
                    AuditEvent.event_type == "SECURITY_URL_404",
                    AuditEvent.when >= day_ago,
                )
                .scalar()
            )
            count = int(cnt or 0)
            if count >= 10:
                pv_log(
                    "security",
                    "error",
                    "security_bad_urls_permanent_block",
                    component="logging_utils",
                    ip=str(ip),
                    count=int(count),
                )
                _add_blocklist_cidr(f"{ip}/32", reason="bad_urls>=10_in_1d")
                _escalate_network_if_needed(ip)
            elif count >= 5:
                until = now + timedelta(minutes=30)
                pv_log(
                    "security",
                    "warn",
                    "security_bad_urls_suspend_30m",
                    component="logging_utils",
                    ip=str(ip),
                    count=int(count),
                    until=until.isoformat(),
                )
                _set_ip_suspend("SECURITY_URL_SUSPEND", ip, until, details=f"count={count}")
    except Exception:
        return

    try:
        addr = ip_address(ip)
    except ValueError:
        return


def ip_is_locked() -> bool:
    """Return True if the current request IP is locked out due to failures.

    This checks for a prior AUTH_IP_LOCKED audit event for the client IP.
    Failures to read from the DB are treated as not locked to avoid
    accidentally blocking legitimate users when the audit DB is unavailable.
    """

    engine = get_user_engine()
    if engine is None:
        return False

    ip = _client_ip()
    if not ip:
        return False

    if _ip_is_allowlisted(ip):
        return False

    # If permanently blocklisted, treat as locked.
    if _ip_in_blocklist(ip):
        return True

    try:
        now = _utcnow()
        day_ago = now - timedelta(days=1)
        with Session(engine) as session:
            AuditEvent.__table__.create(bind=engine, checkfirst=True)

            # Temporary suspensions
            row = (
                session.query(AuditEvent.details)
                .filter(
                    AuditEvent.ip == ip,
                    AuditEvent.event_type == "AUTH_IP_SUSPEND",
                    AuditEvent.when >= day_ago,
                )
                .order_by(AuditEvent.when.desc())
                .first()
            )
            if row and row[0]:
                until = _parse_until(str(row[0]))
                if until and now < until:
                    return True
            return False
    except Exception:  # noqa: BLE001
        return False


def update_ip_lockout_after_failure(threshold: int = 4) -> None:
    """After a failed login attempt, update lockout state for the client IP.

    When the number of recorded failure events for an IP reaches the
    configured threshold, an AUTH_IP_LOCKED event is written. Subsequent
    calls to ip_is_locked() will then treat that IP as blocked.
    """

    engine = get_user_engine()
    if engine is None:
        return

    ip = _client_ip()
    if not ip:
        return

    # Never apply IP lockout to allowlisted IPs/subnets.
    if _ip_is_allowlisted(ip):
        return

    try:
        now = _utcnow()
        day_ago = now - timedelta(days=1)
        failure_events = (
            "AUTH_LOGIN_FAILURE",
            "AUTH_LOGIN_2FA_FAILURE",
            "AUTH_TOTP_VERIFY_FAILURE",
            "AUTH_WEBAUTHN_LOGIN_COMPLETE_FAILURE",
        )

        with Session(engine) as session:
            AuditEvent.__table__.create(bind=engine, checkfirst=True)
            failure_count = (
                session.query(func.count(AuditEvent.id))
                .filter(
                    AuditEvent.ip == ip,
                    AuditEvent.event_type.in_(failure_events),
                    AuditEvent.when >= day_ago,
                )
                .scalar()
            )
        count = int(failure_count or 0)

        # Rules:
        # - 3 failures in 1 day => 5 min
        # - 6 failures in 1 day => 30 min
        # - 9 failures in 1 day => 6 hours
        # - 12 failures in 1 day => permanent blocklist
        if count >= 12:
            pv_log(
                "security",
                "error",
                "auth_ip_permanent_block",
                component="logging_utils",
                ip=str(ip),
                failures=int(count),
            )
            _add_blocklist_cidr(f"{ip}/32", reason="auth_failures>=12_in_1d")
            _escalate_network_if_needed(ip)
            return

        until: Optional[datetime] = None
        if count >= 9:
            until = now + timedelta(hours=6)
        elif count >= 6:
            until = now + timedelta(minutes=30)
        elif count >= 3:
            until = now + timedelta(minutes=5)
        else:
            return

        pv_log(
            "security",
            "warn",
            "auth_ip_suspend",
            component="logging_utils",
            ip=str(ip),
            failures=int(count),
            until=until.isoformat(),
        )
        _set_ip_suspend("AUTH_IP_SUSPEND", ip, until, details=f"failures={count}")
    except Exception:  # noqa: BLE001
        return


def _get_geoip_reader():
    global _geoip_reader, _geoip_init_attempted
    if _geoip_reader or _geoip_init_attempted:
        return _geoip_reader
    _geoip_init_attempted = True
    if not has_request_context():
        return None
    app = current_app._get_current_object()
    path = app.config.get("GEOIP2_DB_PATH")
    if not path:
        return None
    try:  # type: ignore[import]
        import geoip2.database

        _geoip_reader = geoip2.database.Reader(path)
    except Exception:  # noqa: BLE001
        _geoip_reader = None
    return _geoip_reader


def _lookup_country_code(ip: str) -> Optional[str]:
    try:
        ip_address(ip)
    except ValueError:
        return None
    reader = _get_geoip_reader()
    if reader is None:
        return None
    try:
        response = reader.country(ip)
    except Exception:  # noqa: BLE001
        return None
    country = getattr(response, "country", None)
    code = getattr(country, "iso_code", None) if country is not None else None
    if not code:
        return None
    return str(code).upper()


def evaluate_ip_access_policies() -> tuple[bool, Optional[str]]:
    engine = get_user_engine()
    if engine is None:
        return True, None

    ip = _client_ip()
    if not ip:
        return True, None

    if _ip_is_allowlisted(ip):
        return True, None

    try:
        addr = ip_address(ip)
    except ValueError:
        return True, None

    try:
        with Session(engine) as session:
            IpBlocklist.__table__.create(bind=engine, checkfirst=True)
            entries = session.query(IpBlocklist.cidr).all()
        for (cidr,) in entries:
            try:
                net = ip_network(str(cidr), strict=False)
            except ValueError:
                continue
            if addr in net:
                log_event("SECURITY_IP_BLOCKED", details=f"ip={ip}, cidr={cidr}")
                return False, "ip_blocklist"
    except Exception:  # noqa: BLE001
        pass

    policy = None
    try:
        with Session(engine) as session:
            CountryAccessPolicy.__table__.create(bind=engine, checkfirst=True)
            policy = (
                session.query(CountryAccessPolicy)
                .order_by(CountryAccessPolicy.id.asc())
                .first()
            )
    except Exception:  # noqa: BLE001
        policy = None

    if policy is None or not getattr(policy, "mode", None):
        return True, None

    mode = (policy.mode or "").strip().lower()
    if not mode or mode == "disabled":
        return True, None

    country = _lookup_country_code(ip)
    if not country:
        return True, None

    def _codes(raw: Optional[str]) -> set[str]:
        if not raw:
            return set()
        parts = [c.strip().upper() for c in str(raw).split(",")]
        return {c for c in parts if c}

    allowed = _codes(getattr(policy, "allowed_countries", None))
    blocked = _codes(getattr(policy, "blocked_countries", None))

    if mode == "allow_list":
        if allowed and country not in allowed:
            log_event(
                "SECURITY_COUNTRY_BLOCKED",
                details=f"ip={ip}, country={country}, mode=allow_list",
            )
            return False, "country_allow_list"
    elif mode == "block_list":
        if blocked and country in blocked:
            log_event(
                "SECURITY_COUNTRY_BLOCKED",
                details=f"ip={ip}, country={country}, mode=block_list",
            )
            return False, "country_block_list"
    elif mode == "allow_all_except_blocked":
        if blocked and country in blocked:
            log_event(
                "SECURITY_COUNTRY_BLOCKED",
                details=f"ip={ip}, country={country}, mode=allow_all_except_blocked",
            )
            return False, "country_block_except"

    return True, None
