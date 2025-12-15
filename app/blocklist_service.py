from __future__ import annotations

import csv
import io
import ipaddress
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from flask import Flask, Response, abort, request
from sqlalchemy.orm import Session

from .db import get_user_engine
from .logging_utils import log_event
from .models import IpAllowlist, IpBlocklist


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


def create_blocklist_service() -> Flask:
    app = Flask(__name__)
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    allow_nets = _consumer_allow_networks()
    token = (os.environ.get("PENTAVISION_BLOCKLIST_TOKEN") or "").strip()
    ttl_raw = (os.environ.get("PENTAVISION_BLOCKLIST_TTL_SECONDS") or "5").strip()
    try:
        ttl = max(0, min(int(ttl_raw), 60))
    except ValueError:
        ttl = 5

    rate_raw = (os.environ.get("PENTAVISION_BLOCKLIST_RATE_LIMIT_PER_MIN") or "60").strip()
    try:
        rate = int(rate_raw)
    except ValueError:
        rate = 60
    limiter = _RateLimiter(rate)

    @app.before_request
    def _guard() -> None:
        ip = _client_ip()
        if allow_nets and not _client_allowed(ip, allow_nets):
            abort(403)

        if token:
            auth = (request.headers.get("Authorization") or "").strip()
            if auth != f"Bearer {token}":
                abort(401)

        if not limiter.allow(ip or "?"):
            abort(429)

    @app.get("/healthz")
    def healthz() -> Response:
        return Response("ok\n", mimetype="text/plain; charset=utf-8")

    @app.get("/")
    def root() -> Response:
        return blocklist_csv()

    @app.get("/blocklist.csv")
    def blocklist_csv() -> Response:
        engine = get_user_engine()
        if engine is None:
            abort(503)

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

        resp = Response(csv_text, mimetype="text/csv; charset=utf-8")
        resp.headers["Cache-Control"] = f"no-store, no-cache, max-age={ttl}, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        return resp

    return app
