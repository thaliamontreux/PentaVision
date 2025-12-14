# CSAL Storage Modules Developer Guide

This document explains how to implement **storage modules** for the Core Storage
Abstraction Layer (CSAL) used by PentaVision. It is written for developers who
want to add or extend storage backends (cloud object stores, file-sync
providers, WebDAV/Nextcloud, etc.).

The central goals are:

- Provider **agnostic** core (recording engine and admin UI never speak
  provider-specific SDKs directly).
- **Pluggable** modules that can be added, configured, and upgraded without
  rewriting core logic.
- **Multi-instance** support: the same provider type can be instantiated many
  times with different credentials or roots.

---

## 1. Architecture Overview

### 1.1 Core pieces

The storage stack is split into three layers:

1. **Core Storage Abstraction Layer (CSAL)**
   - Defined in `app/storage_csal.py`.
   - Owns the canonical storage interface and routing logic.
   - Exposes methods used by the recording engine and the admin UI.

2. **Storage modules (providers)**
   - Concrete implementations of `StorageModuleBase`.
   - Handle translation from CSAL operations to provider-specific APIs
     (e.g., AWS S3, GCS, Azure Blob, Dropbox, Google Drive, etc.).

3. **Configuration & persistence**
   - Backed by the `StorageModule` table in `app/models.py`.
   - Each row represents a logical storage instance with:
     - `name` (unique logical key used in policies, per-camera routing).
     - `provider_type` (e.g. `s3`, `gcs`, `azure_blob`, `dropbox`, `webdav`,
       `gdrive`, etc.).
     - `config_json` (JSON document containing instance-specific configuration).
     - `is_enabled` flag and timestamps.

The **recording engine** and **admin UI** only talk to CSAL, never directly to
provider SDKs.

---

## 2. CSAL Interface: `StorageModuleBase`

All modules must subclass `StorageModuleBase` from `app/storage_csal.py` and
implement (or consciously decide to raise a clear error for) the following
methods:

```python
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from app.storage_csal import StorageModuleBase, StorageError,
    StorageTransientError, StoragePermanentError


class MyStorageModule(StorageModuleBase):
    def initialize(self, config: Dict[str, Any]) -> None:
        """One-time setup for this instance.

        - `config` comes from `StorageModule.config_json` (parsed from JSON).
        - Do lightweight setup here: parse options, build client objects, etc.
        - Avoid heavy network calls and blocking operations.
        """
        ...

    def authenticate(self, credentials: Dict[str, Any]) -> None:
        """Prepare authentication credentials (if used).

        In the current implementation, credentials are typically embedded in
        `config`, so many modules can treat this as a no-op.
        """
        ...

    def validate(self) -> None:
        """Validate configuration and basic connectivity.

        Called from the admin UI test button.
        - Should perform a cheap operation like listing a bucket or writing
          and deleting a small test object.
        - On success: return normally.
        - On failure: raise `StorageError` (typically `StorageTransientError`
          or `StoragePermanentError`).
        """
        ...

    def write(self, stream: BinaryIO, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Store data from `stream` and return metadata.

        - `stream` is a binary file-like object; modules should consume it
          entirely (e.g., `data = stream.read()`).
        - `metadata` includes at least a `key_hint` string suggesting a base
          name or prefix (e.g., `camera5_20251213T192000`).
        - Return value **must** include:
          - `object_id`: provider-specific identifier used with `read`,
            `delete`, and `stat`.
          - Optionally other keys like `provider_name`, `size`, `checksum`,
            `url`, etc.
        - On transient errors (network hiccups, throttling), raise
          `StorageTransientError`.
        - On permanent errors (invalid config, not found, etc.), raise
          `StoragePermanentError`.
        """
        ...

    def read(
        self,
        object_id: str,
        byte_range: Optional[Tuple[int, int]] = None,
    ) -> BinaryIO:
        """Return a binary stream for the stored object.

        - `object_id` is what you returned from `write`.
        - `byte_range` is `(start, end)` (optional) for ranged reads when
          supported by the provider.
        """
        ...

    def delete(self, object_id: str) -> None:
        """Delete `object_id` if it exists.

        - Should be idempotent (deleting twice is OK).
        - On transient failures, raise `StorageTransientError`.
        - On provider-limited behavior (e.g., deletion not supported), raise
          `StoragePermanentError` with a clear message.
        """
        ...

    def list(self, path: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """List objects under a logical path.

        - Semantics of `path` are module-defined but should be stable.
        - Return a list of dicts, each with an `object_id` and other metadata
          such as `size`, `modified_at`, etc.
        """
        ...

    def stat(self, object_id: str) -> Dict[str, Any]:
        """Return metadata about a single object (size, timestamps, etc.)."""
        ...

    def health_check(self) -> Dict[str, Any]:
        """Return structured health information.

        - Must include at least a `status` key, typically one of:
          - `"ok"`, `"degraded"`, `"offline"`.
        - May include additional details (`latency_ms`, `last_error`, etc.).
        - The admin UI uses this in the Recording Settings page test action.
        """
        ...

    def shutdown(self) -> None:
        """Clean up resources before process exit.

        - Close client sessions, release file handles, etc.
        """
        ...
```

### 2.1 Error types

All modules should raise CSAL errors from `app/storage_csal.py`:

- `StorageError` – base class.
- `StorageAuthError` – authentication/authorization failures.
- `StorageTransientError` – temporary issues that may succeed on retry
  (network timeouts, rate limits).
- `StoragePermanentError` – persistent configuration or provider problems that
  should **not** be retried as-is.

This makes it possible for the recording engine and admin UI to apply
consistent retry and error reporting policies.

---

## 3. StorageRouter and Factory Registration

The CSAL router (`StorageRouter` in `app/storage_csal.py`) is responsible for
mapping logical storage instances to module objects. Modules are constructed via
**factories** registered on the router.

### 3.1 Factory signature

A factory is any callable with the signature:

```python
def factory(app: Flask, module_row: StorageModule, config: Dict[str, Any]) -> StorageModuleBase:
    ...
```

- `app` – the current Flask application.
- `module_row` – the `StorageModule` row describing this instance.
- `config` – parsed version of `module_row.config_json` (a `dict`).

The factory must return a **fully initialized** `StorageModuleBase` subclass
ready to receive `write/read/...` calls.

### 3.2 Registering a factory

Factories are registered using `StorageRouter.register_factory`:

```python
from app.storage_csal import StorageRouter


def _my_provider_factory(app, module_row, config):
    # Example: initialize and authenticate your module here
    module = MyStorageModule()
    module.initialize(config)
    module.authenticate({})  # or pull secrets from config
    return module

StorageRouter.register_factory("my_provider_type", _my_provider_factory)
```

The `provider_type` string should match `StorageModule.provider_type` for
instances you want this factory to handle.

### 3.3 How the router uses factories

At runtime, when the router needs to load instances, it:

1. Reads all `StorageModule` rows from the recordings DB.
2. For each enabled row:
   - Looks up a factory by `provider_type`.
   - Parses `config_json` into `config`.
   - Calls `factory(app, module_row, config)`.
   - Wraps the result in a `StorageInstanceHandle` and stores it under both:
     - `str(module_row.id)` (numeric id), and
     - `module_row.name` (logical name).

Callers use:

```python
router = get_storage_router(app)
router.write("my-storage-instance-name", stream, metadata)
router.health_check("my-storage-instance-name")
```

---

## 4. Configuration and the StorageModule Model

Each configured storage instance is stored in the `StorageModule` table:

```python
class StorageModule(RecordBase):
    __tablename__ = "storage_modules"

    id: Mapped[int]
    name: Mapped[str]           # unique logical name, e.g. "gcs:corp-backups"
    label: Mapped[Optional[str]]
    provider_type: Mapped[str]  # e.g. "s3", "gcs", "azure_blob", "dropbox", ...
    is_enabled: Mapped[Optional[int]]
    config_json: Mapped[Optional[str]]
    created_at: Mapped[datetime]
    updated_at: Mapped[Optional[datetime]]
```

Key fields for module developers:

- `provider_type`
  - Used to select the appropriate factory.
- `config_json`
  - JSON document with arbitrary configuration needed by your module.
  - Parsed and passed as the `config` argument to the factory.

**Example `config_json` for an S3-style module:**

```json
{
  "bucket": "my-recordings-bucket",
  "endpoint": "https://s3.amazonaws.com",
  "region": "us-east-1",
  "access_key": "AKIA...",
  "secret_key": "..."
}
```

Your factory and module implementation are responsible for interpreting these
keys.

---

## 5. Current Legacy Providers and Adapters

The file `app/storage_providers.py` contains existing provider implementations
(`S3StorageProvider`, `GCSStorageProvider`, `AzureBlobStorageProvider`,
`DropboxStorageProvider`, `WebDAVStorageProvider`, `GoogleDriveStorageProvider`,
`LocalFilesystemStorageProvider`, `DatabaseStorageProvider`).

To integrate these with CSAL without breaking existing code, the project uses:

- `_LegacyProviderAdapter(StorageModuleBase)`
  - Wraps any existing `StorageProvider` (which exposes `upload/get_url/delete`)
    into the CSAL interface.
- `_build_provider_for_module(app, module_row, config)`
  - Central helper that builds a legacy `StorageProvider` instance from a
    `StorageModule` row + config.
- `_csal_factory_from_storage_module(app, module_row, config)`
  - Factory that calls `_build_provider_for_module` and then wraps the result
    in `_LegacyProviderAdapter`.
- `StorageRouter.register_factory(..., _csal_factory_from_storage_module)`
  - Registers this factory for the built-in `provider_type` values:
    `local_fs`, `db`, `s3`, `gcs`, `azure_blob`, `dropbox`, `webdav`, `gdrive`.

When you implement a **new provider type**, you can either:

1. Follow the same pattern (build a `StorageProvider` and then wrap it with
   `_LegacyProviderAdapter`), or
2. Implement a **native CSAL module** and register its factory directly.

Over time, the preferred pattern is to implement direct `StorageModuleBase`
subclasses with no intermediate `StorageProvider` class.

---

## 6. Implementing a New CSAL Module (Step-by-Step)

This is the recommended pattern for new providers:

1. **Choose a `provider_type` key**
   - Lowercase, short string, e.g. `"aws_s3"`, `"r2"`, `"b2"`, `"pcloud"`.

2. **Define your configuration schema**
   - Decide what keys you need in `config_json` (bucket name, endpoint,
     OAuth tokens, etc.).
   - Document these keys in code comments and, if applicable, in the admin UI.

3. **Implement `StorageModuleBase` subclass**

   ```python
   # app/storage_providers_myprovider.py (for example)

   from typing import Any, BinaryIO, Dict, Optional, Tuple

   from flask import current_app

   from app.storage_csal import (
       StorageModuleBase,
       StorageTransientError,
       StoragePermanentError,
   )


   class MyCloudStorageModule(StorageModuleBase):
       def __init__(self) -> None:
           self._client = None
           self._bucket = None

       def initialize(self, config: Dict[str, Any]) -> None:
           self._bucket = config["bucket"]
           endpoint = config.get("endpoint")
           # construct your client here (e.g., boto3.client(...))

       def authenticate(self, credentials: Dict[str, Any]) -> None:
           # optional: if your provider requires explicit login or token refresh
           return

       def validate(self) -> None:
           try:
               # perform a cheap operation, e.g., HEAD bucket
               ...
           except Exception as exc:
               raise StoragePermanentError(f"validation failed: {exc}") from exc

       def write(self, stream: BinaryIO, metadata: Dict[str, Any]) -> Dict[str, Any]:
           try:
               data = stream.read()
           except Exception as exc:
               raise StorageTransientError(f"failed to read stream: {exc}") from exc

           key_hint = str(metadata.get("key_hint") or "segment")
           # build a provider-specific key from key_hint + timestamp
           # perform upload; on success, return object_id
           ...

       def read(self, object_id: str, byte_range: Optional[Tuple[int, int]] = None) -> BinaryIO:
           ...

       def delete(self, object_id: str) -> None:
           ...

       def list(self, path: str, filters: Optional[Dict[str, Any]] = None):
           ...

       def stat(self, object_id: str) -> Dict[str, Any]:
           ...

       def health_check(self) -> Dict[str, Any]:
           # You can reuse validate() or implement a more detailed check
           self.validate()
           return {"status": "ok"}

       def shutdown(self) -> None:
           # Clean up any long-lived resources
           return
   ```

4. **Register a factory for your provider type**

   ```python
   from app.storage_csal import StorageRouter


   def _factory_mycloud(app, module_row, config):
       module = MyCloudStorageModule()
       module.initialize(config)
       module.authenticate({})
       return module


   StorageRouter.register_factory("mycloud", _factory_mycloud)
   ```

5. **Create a StorageModule row** for testing
   - Via admin UI (future: module manager) or manually in the DB.
   - Example row:
     - `name = "mycloud:archive"`
     - `provider_type = "mycloud"`
     - `is_enabled = 1`
     - `config_json = {"bucket": "pv-archive"}` (as JSON string)

6. **Use the instance in policies**
   - In per-camera storage policies (`CameraStoragePolicy.storage_targets`), set
     the target to the `StorageModule.name` (e.g., `"mycloud:archive"`).
   - The recording engine will route writes via CSAL using this name.

---

## 7. Admin UI Integration and Testing

The **Recording Settings** page (`/recording-settings`) exposes a test button
for each `StorageModule` row. When you click **Test**:

1. The view handler loads the `StorageModule` row.
2. It calls `get_storage_router(current_app)` to get a `StorageRouter`.
3. It calls `router.health_check(instance_key)` where `instance_key` is the
   module id as a string.
4. Any `StorageError` is caught and displayed as a failure message.

To make your module test-friendly:

- Ensure `health_check()` is implemented and reasonably fast.
- Raise `StorageError` subclasses with clear, concise messages.

As we extend the Storage admin page into a full **Module Manager**, it will
also:

- List module instances by `name`, `provider_type`, label, and status.
- Allow enabling/disabling instances.
- Expose more advanced metrics returned from `health_check()`.

---

## 8. Provider List and Expectations

The project aims to support a broad set of providers through CSAL modules. The
current roadmap (see `TODO.md`) includes:

- Amazon S3 (AWS)
- Google Cloud Storage (GCS)
- Microsoft Azure Blob Storage
- Dropbox (API v2)
- Google Drive (Drive API)
- Microsoft OneDrive / Microsoft Graph
- Box
- Backblaze B2
- DigitalOcean Spaces
- Wasabi
- Linode Object Storage
- IBM Cloud Object Storage
- Oracle Cloud Object Storage
- Rackspace Cloud Files / OpenStack Swift
- OVHcloud Object Storage
- Scaleway Object Storage
- Cloudflare R2
- pCloud
- MEGA
- Nextcloud (WebDAV)

Each module for these providers is expected to:

- Implement the **full CSAL contract** (or explicitly raise
  `StoragePermanentError` for unsupported operations).
- Handle **authentication** securely (API keys, OAuth, service accounts, etc.).
- Respect provider **rate limits** and error semantics.
- Provide clear `health_check()` output for the admin UI.

---

## 9. Coding Guidelines and Best Practices

- **Avoid blocking** in `initialize`: do minimal, predictable work.
- **Use timeouts** and conservative retry behavior in network calls.
- **Do not log secrets** (tokens, access keys, passwords) at any log level.
- **Mask sensitive values** if you must include them in messages or debug logs.
- **Normalize errors** through `StorageError` subclasses; avoid leaking raw
  stack traces to the UI.
- **Keep provider-specific logic isolated** in its module file so it can be
  upgraded or swapped independently.

If you add a new module, please also update:

- `TODO.md` under **CSAL pluggable storage modules to implement** (check the
  appropriate item).
- Any relevant admin UI forms once the Module Manager UI is fully in place.

This guide will evolve as the CSAL/Module Manager matures; keep it up to date
when you introduce new provider types or patterns.
