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
        engine = create_engine(url, future=True)
        _engines[name] = engine
    return engine


def get_user_engine() -> Optional[Engine]:
    return _get_engine("user", "USER_DB_URL")


def get_face_engine() -> Optional[Engine]:
    return _get_engine("face", "FACE_DB_URL")


def get_record_engine() -> Optional[Engine]:
    return _get_engine("record", "RECORD_DB_URL")
