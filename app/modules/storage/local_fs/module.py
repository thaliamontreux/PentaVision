from __future__ import annotations

# This module is intentionally light: the legacy adapter factory already exists.
# Importing storage_providers registers the CSAL factory for local_fs.
from app import storage_providers as _storage_providers  # noqa: F401
