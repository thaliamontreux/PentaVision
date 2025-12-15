from __future__ import annotations

import importlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy.orm import Session


@dataclass(frozen=True)
class StorageModuleDefinition:
    provider_type: str
    display_name: str
    category: str
    fields: List[Dict[str, Any]]
    template: str
    module_dir: str


def _storage_modules_root() -> str:
    return os.path.join(os.path.dirname(__file__))


def _safe_read_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def discover_storage_module_definitions() -> List[StorageModuleDefinition]:
    root = _storage_modules_root()
    defs: List[StorageModuleDefinition] = []

    try:
        entries = sorted(os.listdir(root))
    except Exception:
        return defs

    for name in entries:
        if name.startswith("_"):
            continue
        if name.strip().lower() == "gdrive":
            continue
        module_dir = os.path.join(root, name)
        if not os.path.isdir(module_dir):
            continue

        definition_path = os.path.join(module_dir, "definition.json")
        template_path = os.path.join(module_dir, "template.html")
        if not os.path.exists(definition_path) or not os.path.exists(template_path):
            continue

        raw = _safe_read_json(definition_path)
        provider_type = str(raw.get("provider_type") or name).strip().lower()
        if not provider_type:
            continue

        defs.append(
            StorageModuleDefinition(
                provider_type=provider_type,
                display_name=str(raw.get("display_name") or provider_type),
                category=str(raw.get("category") or "Custom"),
                fields=list(raw.get("fields") or []),
                template=f"modules/storage/{name}/template.html",
                module_dir=module_dir,
            )
        )

    return defs


def load_storage_provider_plugins() -> None:
    root = _storage_modules_root()
    try:
        entries = sorted(os.listdir(root))
    except Exception:
        return

    for name in entries:
        if name.startswith("_"):
            continue
        if name.strip().lower() == "gdrive":
            continue
        module_dir = os.path.join(root, name)
        if not os.path.isdir(module_dir):
            continue
        py_path = os.path.join(module_dir, "module.py")
        if not os.path.exists(py_path):
            continue
        import_path = f"app.modules.storage.{name}.module"
        try:
            importlib.import_module(import_path)
        except Exception:
            continue


def sync_installed_storage_provider_modules(record_engine) -> None:
    if record_engine is None:
        return

    defs = discover_storage_module_definitions()
    now = datetime.now(timezone.utc)

    try:
        from app.models import StorageProviderModule  # noqa: PLC0415
    except Exception:
        return

    try:
        with Session(record_engine) as session:
            try:
                session.query(StorageProviderModule).update(
                    {StorageProviderModule.is_installed: 0}
                )
            except Exception:
                pass

            for d in defs:
                row = (
                    session.query(StorageProviderModule)
                    .filter(StorageProviderModule.provider_type == d.provider_type)
                    .first()
                )

                definition_path = os.path.join(d.module_dir, "definition.json")
                raw_def = _safe_read_json(definition_path)
                try:
                    raw_def_text = json.dumps(raw_def)
                except Exception:
                    raw_def_text = None

                wizard_path_fs = os.path.join(d.module_dir, "wizard.html")
                wizard_template = (
                    f"modules/storage/{os.path.basename(d.module_dir)}/wizard.html"
                    if os.path.exists(wizard_path_fs)
                    else None
                )

                if row is None:
                    row = StorageProviderModule(
                        provider_type=d.provider_type,
                        display_name=d.display_name,
                        category=d.category,
                        definition_json=raw_def_text,
                        template_path=d.template,
                        wizard_path=wizard_template,
                        is_installed=1,
                        last_seen_at=now,
                    )
                    session.add(row)
                else:
                    row.display_name = d.display_name
                    row.category = d.category
                    row.definition_json = raw_def_text
                    row.template_path = d.template
                    row.wizard_path = wizard_template
                    row.is_installed = 1
                    row.last_seen_at = now
                    row.updated_at = now

            session.commit()
    except Exception:
        return
