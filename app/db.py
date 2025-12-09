from __future__ import annotations

from typing import Dict, Optional

from flask import current_app
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine


_engines: Dict[str, Engine] = {}


def _get_engine(name: str, config_key: str) -> Optional[Engine]:
    """Return a cached SQLAlchemy engine for the given config key.

    If the URL changes between calls, a new engine will be created.
    """
    url = current_app.config.get(config_key)
    if not url:
        return None

    engine = _engines.get(name)
    if engine is None or str(engine.url) != str(url):
        # Use a modest connection pool per process so that, when multiplied by
        # Gunicorn workers, we do not exhaust the database's max_connections.
        # pool_pre_ping keeps connections healthy across MySQL timeouts.
        engine = create_engine(
            url,
            future=True,
            pool_size=3,
            max_overflow=2,
            pool_recycle=3600,
            pool_pre_ping=True,
        )
        _engines[name] = engine
    return engine


def get_user_engine() -> Optional[Engine]:
    return _get_engine("user", "USER_DB_URL")


def get_face_engine() -> Optional[Engine]:
    return _get_engine("face", "FACE_DB_URL")


def get_record_engine() -> Optional[Engine]:
    return _get_engine("record", "RECORD_DB_URL")
