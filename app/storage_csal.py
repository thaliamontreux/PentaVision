from __future__ import annotations

"""Core Storage Abstraction Layer (CSAL).

This module defines the canonical storage contract used by the recording
engine, the administrative UI, and pluggable storage provider modules.

The goal is to keep the core system provider-agnostic: all provider-specific
logic lives in modules that implement the CSAL interface and are discovered at
runtime.
"""

from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from flask import Flask
from sqlalchemy.orm import Session

from .db import get_record_engine
from .models import StorageModule


class StorageError(Exception):
    """Base exception for storage-related failures."""


class StorageAuthError(StorageError):
    """Authentication or authorization failure when talking to a provider."""


class StorageTransientError(StorageError):
    """Transient failure that may succeed on retry (network, rate limits)."""


class StoragePermanentError(StorageError):
    """Permanent failure that should not be retried as-is."""


class StorageModuleBase:
    """Abstract interface implemented by all storage provider modules.

    Concrete modules must subclass this and implement all methods. The CSAL
    code only depends on this interface and on the module manifest metadata,
    never on provider-specific SDKs or APIs.
    """

    def initialize(self, config: Dict[str, Any]) -> None:  # pragma: no cover
        """Initialize the module with static configuration.

        This is called once per process for each storage instance before any
        read/write operations. Implementations should perform lightweight
        setup only (parsing configuration, preparing clients) and avoid any
        expensive network calls.
        """

    def authenticate(self, credentials: Dict[str, Any]) -> None:  # pragma: no cover
        """Authenticate using the provided credentials.

        Modules that rely on explicit credentials (API keys, OAuth tokens,
        service accounts, etc.) should validate or prepare those here. Modules
        that only use ambient credentials can implement this as a no-op.
        """

    def validate(self) -> None:  # pragma: no cover
        """Validate configuration and connectivity.

        Called from the administrative UI when an administrator runs a test
        against a storage instance. Implementations should perform a cheap
        operation such as listing a bucket or writing and deleting a tiny
        object. On failure they must raise a StorageError subclass.
        """

    def write(self, stream: BinaryIO, metadata: Dict[str, Any]) -> Dict[str, Any]:  # pragma: no cover
        """Write a new object from the given binary stream.

        The return value must include at least an ``object_id`` key that can
        be used later with ``read``, ``delete``, and ``stat``.
        """

    def read(
        self,
        object_id: str,
        byte_range: Optional[Tuple[int, int]] = None,
    ) -> BinaryIO:  # pragma: no cover
        """Return a binary stream for the stored object.

        Implementations may honor ``byte_range`` when supported by the
        underlying provider.
        """

    def delete(self, object_id: str) -> None:  # pragma: no cover
        """Delete a stored object if it exists."""

    def list(self, path: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:  # pragma: no cover
        """List objects under a logical path.

        The exact semantics of ``path`` are provider-defined but should be
        stable per module. The return value is a list of dictionaries with at
        least an ``object_id`` key and any additional metadata the provider
        wishes to expose.
        """

    def stat(self, object_id: str) -> Dict[str, Any]:  # pragma: no cover
        """Return metadata for a stored object (size, timestamps, etc.)."""

    def health_check(self) -> Dict[str, Any]:  # pragma: no cover
        """Return a structured health status for this instance.

        The result should include at least ``status`` ("ok", "degraded",
        "offline") and may include provider-specific metrics such as latency
        or recent error counts.
        """

    def shutdown(self) -> None:  # pragma: no cover
        """Clean up any resources held by the module before process exit."""


class StorageInstanceHandle:
    """Lightweight reference to a configured storage instance.

    This binds together the database ``StorageModule`` row with the loaded
    module implementation. The recording engine and admin UI should use the
    logical ``name``/``uuid`` from the database, not provider-specific
    identifiers.
    """

    def __init__(
        self,
        module_row: StorageModule,
        impl: StorageModuleBase,
    ) -> None:
        self.row = module_row
        self.impl = impl

    @property
    def name(self) -> str:
        return self.row.name

    @property
    def provider_type(self) -> str:
        return (self.row.provider_type or "").strip().lower()


class StorageRouter:
    """CSAL router that maps logical storage instances to module objects.

    The router is responsible for:

    - Loading ``StorageModule`` rows from the recordings database.
    - Constructing module implementations using a provider registry.
    - Exposing a small API for the recording engine to perform operations
      against a specific instance name or UUID.

    Provider-specific construction is delegated to a registry of factory
    functions. This keeps the core system decoupled from individual provider
    SDKs.
    """

    def __init__(self, app: Flask) -> None:
        self.app = app
        self._instances: Dict[str, StorageInstanceHandle] = {}
        self._loaded = False

    # Provider registry: mapping provider_type -> factory callable. Factories
    # are registered from provider modules at import time.
    _factories: Dict[str, Any] = {}

    @classmethod
    def register_factory(cls, provider_type: str, factory: Any) -> None:
        key = (provider_type or "").strip().lower()
        if not key:
            return
        cls._factories[key] = factory

    def _load_instances(self) -> None:
        if self._loaded:
            return

        engine = get_record_engine()
        if engine is None:
            self._loaded = True
            return

        StorageModule.__table__.create(bind=engine, checkfirst=True)
        with Session(engine) as session:
            rows = (
                session.query(StorageModule)
                .order_by(StorageModule.id)
                .all()
            )

        for row in rows:
            if not getattr(row, "is_enabled", 0):
                continue
            ptype = (row.provider_type or "").strip().lower()
            factory = self._factories.get(ptype)
            if factory is None:
                continue
            raw_config = getattr(row, "config_json", None) or ""
            config: Dict[str, Any]
            try:
                import json

                config = json.loads(raw_config) if raw_config else {}
            except Exception:  # noqa: BLE001
                config = {}
            try:
                impl = factory(self.app, row, config)
            except Exception:  # noqa: BLE001
                continue
            handle = StorageInstanceHandle(row, impl)
            # Allow lookup by database id and by logical name.
            self._instances[str(row.id)] = handle
            self._instances[handle.name] = handle

        self._loaded = True

    def get_instance(self, key: str) -> Optional[StorageInstanceHandle]:
        self._load_instances()
        return self._instances.get(str(key))

    # Convenience helpers used by the recording engine.

    def write(
        self,
        instance_key: str,
        stream: BinaryIO,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        handle = self.get_instance(instance_key)
        if handle is None:
            raise StoragePermanentError(f"unknown storage instance: {instance_key}")
        return handle.impl.write(stream, metadata)

    def health_check(self, instance_key: str) -> Dict[str, Any]:
        handle = self.get_instance(instance_key)
        if handle is None:
            raise StoragePermanentError(f"unknown storage instance: {instance_key}")
        return handle.impl.health_check()


def get_storage_router(app: Flask) -> StorageRouter:
    """Helper used by workers to obtain a CSAL router instance."""

    # For now this is a simple factory; a future iteration can cache the
    # router on the Flask ``app`` object if needed.
    return StorageRouter(app)
