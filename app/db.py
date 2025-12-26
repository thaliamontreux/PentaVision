from __future__ import annotations

import re
from typing import Dict, Optional

from flask import current_app
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError


_engines: Dict[str, Engine] = {}


def _get_engine(name: str, config_key: str) -> Optional[Engine]:
    """Return a cached SQLAlchemy engine for the given config key.

    If the URL changes between calls, a new engine will be created.
    """
    url = current_app.config.get(config_key)
    if not url:
        return None

    try:
        cfg_url = make_url(str(url)).render_as_string(hide_password=False)
    except Exception:  # noqa: BLE001
        cfg_url = str(url)

    engine = _engines.get(name)
    current_engine_url = None
    if engine is not None:
        try:
            current_engine_url = engine.url.render_as_string(hide_password=False)
        except Exception:  # noqa: BLE001
            current_engine_url = str(engine.url)

    if engine is None or current_engine_url != cfg_url:
        # Use a modest connection pool per process so that, when multiplied by
        # Gunicorn workers, we do not exhaust the database's max_connections.
        # pool_pre_ping keeps connections healthy across MySQL timeouts.
        engine = create_engine(
            url,
            future=True,
            pool_size=2,
            max_overflow=0,
            pool_timeout=30,
            pool_recycle=1800,
            pool_pre_ping=True,
            pool_use_lifo=True,
        )
        _engines[name] = engine
    return engine


def get_user_engine() -> Optional[Engine]:
    return _get_engine("user", "USER_DB_URL")


def get_face_engine() -> Optional[Engine]:
    return _get_engine("face", "FACE_DB_URL")


def get_record_engine() -> Optional[Engine]:
    return _get_engine("record", "RECORD_DB_URL")


def _normalize_property_db_name(property_uid: str) -> str:
    raw = str(property_uid or "").strip().lower()
    raw = raw.replace("-", "")
    raw = re.sub(r"[^a-z0-9_]", "", raw)
    prefix = str(current_app.config.get("PROPERTY_DB_NAME_PREFIX") or "pv_prop_")
    prefix = re.sub(r"[^a-zA-Z0-9_]", "", prefix)
    return f"{prefix}{raw}"


def get_property_engine(property_uid: str) -> Optional[Engine]:
    """Return an engine for the per-property tenant DB.

    This will attempt to CREATE DATABASE when configured to do so.
    """

    app_url_base = str(current_app.config.get("PROPERTY_DB_APP_URL_BASE") or "").strip()
    if not app_url_base:
        return None

    uid_norm = str(property_uid or "").strip().lower()
    if not uid_norm:
        return None

    db_name = _normalize_property_db_name(property_uid)
    cache_key = f"prop:{db_name}"
    engine = _engines.get(cache_key)
    if engine is not None:
        return engine

    try:
        url = make_url(app_url_base)
    except Exception:  # noqa: BLE001
        url = make_url(app_url_base)

    url = url.set(database=db_name)

    # Provision database when admin URL is available.
    admin_url_raw = str(current_app.config.get("PROPERTY_DB_ADMIN_URL") or "").strip()
    if admin_url_raw:
        try:
            admin_url = make_url(admin_url_raw)
            if not admin_url.database:
                admin_url = admin_url.set(database="mysql")
            admin_engine = create_engine(
                admin_url,
                future=True,
                pool_size=1,
                max_overflow=0,
                pool_timeout=30,
                pool_recycle=1800,
                pool_pre_ping=True,
                pool_use_lifo=True,
            )
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "CREATE DATABASE IF NOT EXISTS "
                        + f"`{db_name}`"
                        + " CHARACTER SET utf8mb4"
                    )
                )
        except Exception:  # noqa: BLE001
            pass

    def _build_tenant_engine() -> Engine:
        return create_engine(
            url,
            future=True,
            pool_size=2,
            max_overflow=0,
            pool_timeout=30,
            pool_recycle=1800,
            pool_pre_ping=True,
            pool_use_lifo=True,
        )

    engine = _build_tenant_engine()

    # Verify the DB exists/reachable. If the DB was missing and we have an
    # admin URL, retry provisioning once.
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError:
        if admin_url_raw:
            try:
                admin_url = make_url(admin_url_raw)
                if not admin_url.database:
                    admin_url = admin_url.set(database="mysql")
                admin_engine = create_engine(
                    admin_url,
                    future=True,
                    pool_size=1,
                    max_overflow=0,
                    pool_timeout=30,
                    pool_recycle=1800,
                    pool_pre_ping=True,
                    pool_use_lifo=True,
                )
                with admin_engine.begin() as conn:
                    conn.execute(
                        text(
                            "CREATE DATABASE IF NOT EXISTS "
                            + f"`{db_name}`"
                            + " CHARACTER SET utf8mb4"
                        )
                    )
                engine = _build_tenant_engine()
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
            except Exception:  # noqa: BLE001
                return None
        else:
            return None

    try:
        from .models import create_property_schema

        create_property_schema(engine)
    except Exception:  # noqa: BLE001
        pass

    _engines[cache_key] = engine
    return engine


def diagnose_property_engine(property_uid: str) -> str:
    """Return a human-friendly diagnostic message for tenant DB connectivity.

    This is used by UI routes to show actionable toasts instead of crashing.
    """

    app_url_base = str(
        current_app.config.get("PROPERTY_DB_APP_URL_BASE") or ""
    ).strip()
    if not app_url_base:
        return "Tenant DB is not configured: PROPERTY_DB_APP_URL_BASE is missing."

    uid_norm = str(property_uid or "").strip().lower()
    if not uid_norm:
        return "Tenant DB is not configured for this property (missing uid)."

    db_name = _normalize_property_db_name(uid_norm)

    try:
        url = make_url(app_url_base).set(database=db_name)
    except Exception:  # noqa: BLE001
        url = make_url(app_url_base).set(database=db_name)

    admin_url_raw = str(current_app.config.get("PROPERTY_DB_ADMIN_URL") or "").strip()

    engine = create_engine(
        url,
        future=True,
        pool_size=1,
        max_overflow=0,
        pool_timeout=10,
        pool_recycle=1800,
        pool_pre_ping=True,
        pool_use_lifo=True,
    )
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return "Tenant DB is reachable."
    except OperationalError as exc:
        errno = None
        try:
            args = getattr(getattr(exc, "orig", None), "args", None)
            if args and len(args) > 0:
                errno = int(args[0])
        except Exception:  # noqa: BLE001
            errno = None

        msg = str(exc)
        if "No space left on device" in msg or "Errcode: 28" in msg:
            return (
                "Tenant DB error: disk is full on the database server. "
                "Free disk space and retry."
            )
        if errno == 1049 and not admin_url_raw:
            return (
                "Tenant DB does not exist and auto-provisioning is disabled. "
                "Set PROPERTY_DB_ADMIN_URL so the app can create tenant databases."
            )
        if errno in {1045, 1044}:
            return (
                "Tenant DB authentication failed. Check PROPERTY_DB_APP_URL_BASE "
                "credentials and grants."
            )
        return (
            "Tenant DB connection failed. Check DB host/port, credentials, "
            "and disk space."
        )
