from __future__ import annotations

from typing import Dict, Optional

from flask import current_app
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.engine import make_url


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
