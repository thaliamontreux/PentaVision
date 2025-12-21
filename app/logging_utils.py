from __future__ import annotations

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


def _env_consumer_allow_networks() -> list:
    raw = os.environ.get("PENTAVISION_BLOCKLIST_CONSUMER_ALLOW_CIDRS", "").strip()
    parts = [c.strip() for c in raw.split(",") if c.strip()]
    nets = []
    for c in parts + ["127.0.0.1/32", "::1/128"]:
        try:
            nets.append(ip_network(c, strict=False))
        except ValueError:
            continue
    return nets


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
    if _ip_is_allowlisted(ip):
        return
    # Log the 404 event
    log_event("SECURITY_URL_404", details=f"path={path}")
    try:
        with Session(engine) as session:
            AuditEvent.__table__.create(bind=engine, checkfirst=True)
            cnt = (
                session.query(func.count(AuditEvent.id))
                .filter(AuditEvent.ip == ip, AuditEvent.event_type == "SECURITY_URL_404")
                .scalar()
            )
            if cnt is not None and int(cnt) > 5:
                _add_blocklist_cidr(f"{ip}/32", reason="too_many_invalid_urls")
                _escalate_network_if_needed(ip)
    except Exception:
        return

    try:
        addr = ip_address(ip)
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

    try:
        with Session(engine) as session:
            exists = (
                session.query(AuditEvent.id)
                .filter(
                    AuditEvent.ip == ip,
                    AuditEvent.event_type == "AUTH_IP_LOCKED",
                )
                .first()
            )
            return exists is not None
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
        with Session(engine) as session:
            # If already locked, nothing to do.
            locked = (
                session.query(AuditEvent.id)
                .filter(
                    AuditEvent.ip == ip,
                    AuditEvent.event_type == "AUTH_IP_LOCKED",
                )
                .first()
            )
            if locked is not None:
                return

            failure_events = (
                "AUTH_LOGIN_FAILURE",
                "AUTH_LOGIN_2FA_FAILURE",
                "AUTH_TOTP_VERIFY_FAILURE",
                "AUTH_WEBAUTHN_LOGIN_COMPLETE_FAILURE",
            )

            failure_count = (
                session.query(func.count(AuditEvent.id))
                .filter(
                    AuditEvent.ip == ip,
                    AuditEvent.event_type.in_(failure_events),
                )
                .scalar()
            )

            if failure_count is None or failure_count < threshold:
                return

            lock_event = AuditEvent(
                user_id=None,
                event_type="AUTH_IP_LOCKED",
                ip=ip,
                details=f"ip lockout after {int(failure_count)} failures",
            )
            session.add(lock_event)
            session.commit()
            # Also add to central blocklist and consider network escalation
            if not _ip_is_allowlisted(ip):
                _add_blocklist_cidr(f"{ip}/32", reason=f"auth_failures>={int(failure_count)}")
                _escalate_network_if_needed(ip)
    except Exception:  # noqa: BLE001
        # Never raise from IP lockout bookkeeping.
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
