from __future__ import annotations

import io
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone

from flask import (
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import func
from sqlalchemy.orm import Session

from .db import get_record_engine
from .models import (
    CameraRecording,
    StorageModule,
    StorageModuleHealthCheck,
    StorageModuleEvent,
    StorageModuleWriteStat,
    UploadQueueItem,
)
from .security import (
    get_current_user,
    validate_global_csrf_token,
)
from .storage_csal import StorageError, get_storage_router


def storage_settings_page():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))

    errors: list[str] = []
    saved = False
    module_test_result: dict | None = None
    module_test_ready = False
    wizard_draft: dict[str, object] | None = None
    wizard_step = 1

    record_engine = get_record_engine()

    edit_module = None
    edit_module_config: dict[str, object] | None = None
    if record_engine is not None:
        edit_id_raw = request.args.get("edit_module") or ""
        try:
            edit_id = int(edit_id_raw) if edit_id_raw else None
        except ValueError:
            edit_id = None
        if edit_id is not None:
            with Session(record_engine) as session_db:
                StorageModule.__table__.create(
                    bind=record_engine,
                    checkfirst=True,
                )
                row = session_db.get(StorageModule, edit_id)
            if row is not None:
                edit_module = row
                if row.config_json:
                    try:
                        edit_module_config = json.loads(row.config_json)
                    except Exception:
                        edit_module_config = {}

                if edit_module_config is None:
                    edit_module_config = {}
                provider_type = row.provider_type or ""
                if provider_type.strip().lower() == "local_drive":
                    if (
                        isinstance(edit_module_config, dict)
                        and "base_dir" not in edit_module_config
                        and "local_drive_path" in edit_module_config
                    ):
                        edit_module_config["base_dir"] = (
                            edit_module_config.get("local_drive_path")
                        )

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        if not validate_global_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")
        else:
            if action in {
                "module_create",
                "module_update",
                "module_delete",
                "module_toggle",
                "module_test",
                "module_draft_test",
                "module_write_test",
                "module_draft_write_test",
                "module_clone",
            }:
                if record_engine is None:
                    errors.append("Record database is not configured.")

                def _wants_json() -> bool:
                    try:
                        hdr = (
                            request.headers.get("X-Requested-With") or ""
                        ).strip().lower()
                        if hdr == "xmlhttprequest":
                            return True
                        accept = (request.headers.get("Accept") or "").lower()
                        if "application/json" in accept:
                            return True
                    except Exception:  # noqa: BLE001
                        return False
                    return False

                def _get_last_module_test() -> dict[str, object] | None:
                    try:
                        raw = session.get("storage_module_last_test")
                    except Exception:  # noqa: BLE001
                        return None
                    if not isinstance(raw, dict):
                        return None
                    return raw

                def _set_last_module_test(fingerprint: str, ok: bool) -> None:
                    try:
                        session["storage_module_last_test"] = {
                            "fingerprint": str(fingerprint or ""),
                            "ok": bool(ok),
                        }
                    except Exception:  # noqa: BLE001
                        pass

                def _fingerprint_module_payload(
                    provider_type: str,
                    name: str,
                    config: dict[str, object],
                    module_id: int | None = None,
                ) -> str:
                    payload = {
                        "provider_type": (provider_type or "").strip().lower(),
                        "name": (name or "").strip(),
                        "module_id": int(module_id) if module_id is not None else None,
                        "config": config,
                    }
                    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

                def _load_provider_definition(provider_type: str) -> dict:
                    provider_type = (provider_type or "").strip().lower()
                    if not provider_type:
                        return {}
                    try:
                        from .modules.storage.registry import (  # noqa: PLC0415
                            _safe_read_json,
                        )
                    except Exception:  # noqa: BLE001
                        return {}
                    try:
                        base_dir = os.path.join(
                            os.path.dirname(__file__),
                            "modules",
                            "storage",
                            provider_type,
                            "definition.json",
                        )
                        return _safe_read_json(base_dir)
                    except Exception:  # noqa: BLE001
                        return {}

                def _default_form_key(provider_type: str, key: str) -> str:
                    provider_type = (provider_type or "").strip().lower()
                    key = (key or "").strip()
                    if provider_type == "local_fs" and key == "base_dir":
                        return "module_cfg_base_dir"
                    if provider_type == "local_drive" and key == "base_dir":
                        return "module_cfg_local_drive_path"
                    return f"module_cfg_{provider_type}_{key}"

                def _coerce_value(raw: str, field_type: str):
                    field_type = (field_type or "text").strip().lower()
                    if field_type in {"number", "int", "integer"}:
                        try:
                            return int(str(raw).strip())
                        except Exception:  # noqa: BLE001
                            return None
                    if field_type in {"bool", "boolean"}:
                        if raw is None:
                            return False
                        sval = str(raw).strip().lower()
                        if sval in {"1", "true", "on", "yes"}:
                            return True
                        if sval in {"0", "false", "off", "no"}:
                            return False
                        return bool(sval)
                    return str(raw)

                def _build_module_config_from_form(
                    provider_type: str,
                ) -> dict[str, object]:
                    provider_type = (provider_type or "").strip().lower()
                    definition = _load_provider_definition(provider_type)
                    fields = list(definition.get("fields") or [])
                    config: dict[str, object] = {}

                    for f in fields:
                        if not isinstance(f, dict):
                            continue
                        key = str(f.get("key") or "").strip()
                        if not key:
                            continue
                        form_key = (
                            str(f.get("form_key") or "").strip()
                            or _default_form_key(provider_type, key)
                        )
                        ftype = str(f.get("type") or "text").strip().lower()

                        if ftype in {"bool", "boolean"}:
                            raw = request.form.get(form_key)
                            if raw is None:
                                present = request.form.get(f"{form_key}_present")
                                if present is None:
                                    continue
                                config[key] = False
                                continue
                            config[key] = bool(_coerce_value(raw, ftype))
                            continue

                        raw_val = request.form.get(form_key)
                        if raw_val is None:
                            continue
                        raw_val = str(raw_val).strip()
                        if raw_val == "":
                            continue

                        coerced = _coerce_value(raw_val, ftype)
                        if coerced is None:
                            continue
                        config[key] = coerced

                    if not fields:
                        try:
                            if provider_type == "sql_db":
                                raw_type = request.form.get("module_cfg_sql_db_type")
                                raw_host = request.form.get("module_cfg_sql_db_host")
                                raw_port = request.form.get("module_cfg_sql_db_port")
                                raw_db = request.form.get("module_cfg_sql_db_database")
                                raw_user = request.form.get("module_cfg_sql_db_username")
                                raw_pass = request.form.get("module_cfg_sql_db_password")
                                raw_driver = request.form.get("module_cfg_sql_db_mssql_driver")

                                if raw_type is not None and str(raw_type).strip():
                                    config["db_type"] = str(raw_type).strip().lower()
                                if raw_host is not None and str(raw_host).strip():
                                    config["host"] = str(raw_host).strip()
                                if raw_port is not None and str(raw_port).strip() != "":
                                    try:
                                        config["port"] = int(str(raw_port).strip())
                                    except Exception:  # noqa: BLE001
                                        pass
                                if raw_db is not None and str(raw_db).strip():
                                    config["database"] = str(raw_db).strip()
                                if raw_user is not None and str(raw_user).strip():
                                    config["username"] = str(raw_user).strip()
                                if raw_pass is not None and str(raw_pass).strip():
                                    config["password"] = str(raw_pass).strip()
                                if raw_driver is not None and str(raw_driver).strip():
                                    config["mssql_driver"] = str(raw_driver).strip()
                        except Exception:  # noqa: BLE001
                            pass
                        return config

                    try:
                        if provider_type == "local_drive" and "base_dir" not in config:
                            raw_base_dir = request.form.get("module_cfg_local_drive_path")
                            if raw_base_dir is not None:
                                raw_base_dir = str(raw_base_dir).strip()
                                if raw_base_dir:
                                    config["base_dir"] = raw_base_dir
                    except Exception:  # noqa: BLE001
                        pass
                    return config

                def _validate_provider_config(
                    provider_type: str,
                    config: dict[str, object],
                ) -> list[str]:
                    provider_type = (provider_type or "").strip().lower()
                    definition = _load_provider_definition(provider_type)
                    fields = list(definition.get("fields") or [])
                    missing: list[str] = []
                    for f in fields:
                        try:
                            if not isinstance(f, dict):
                                continue
                            if not bool(f.get("required")):
                                continue
                            key = str(f.get("key") or "").strip()
                            if not key:
                                continue
                            val = config.get(key)
                            if val is None:
                                missing.append(key)
                                continue
                            if isinstance(val, str) and not val.strip():
                                missing.append(key)
                                continue
                        except Exception:  # noqa: BLE001
                            continue
                    return missing

                if not errors and record_engine is not None:
                    with Session(record_engine) as session_db:
                        StorageModule.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )

                        if action == "module_test":
                            module_id_raw = (request.form.get("module_id") or "").strip()
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None

                            module = session_db.get(StorageModule, module_id) if module_id is not None else None
                            if module is None:
                                module_test_result = {
                                    "ok": False,
                                    "module_name": f"#{module_id_raw}",
                                    "message": "Storage module not found.",
                                }
                            else:
                                router = get_storage_router(current_app)
                                instance_key = str(module.id)
                                try:
                                    status = router.health_check(instance_key)
                                except StorageError as exc:
                                    module_test_result = {
                                        "ok": False,
                                        "module_name": module.name,
                                        "message": str(exc)[:300],
                                    }
                                except Exception as exc:  # noqa: BLE001
                                    module_test_result = {
                                        "ok": False,
                                        "module_name": module.name,
                                        "message": str(exc)[:300],
                                    }
                                else:
                                    status_text = str(status.get("status") or "ok")
                                    message = status.get("message") or (
                                        f"Health check status: {status_text}"
                                    )
                                    module_test_result = {
                                        "ok": status_text == "ok",
                                        "module_name": module.name,
                                        "message": str(message)[:300],
                                    }

                            if _wants_json():
                                return jsonify(
                                    {
                                        "ok": bool(module_test_result.get("ok")) if isinstance(module_test_result, dict) else False,
                                        "module_name": str(module_test_result.get("module_name") or "") if isinstance(module_test_result, dict) else "",
                                        "message": str(module_test_result.get("message") or "") if isinstance(module_test_result, dict) else "",
                                    }
                                )

                        elif action == "module_draft_test" or action == "module_draft_write_test":
                            module_id_raw = (request.form.get("module_id") or "").strip()
                            try:
                                module_id = int(module_id_raw) if module_id_raw else None
                            except ValueError:
                                module_id = None

                            try:
                                draft: dict[str, object] = {}
                                for k in request.form.keys():
                                    if not k:
                                        continue
                                    if k in {"csrf_token", "action"}:
                                        continue
                                    if k.startswith("module_") or k.startswith("module_cfg_"):
                                        draft[k] = request.form.get(k)
                                draft["_step"] = 3
                                session["storage_wizard_draft"] = draft
                                wizard_draft = draft
                                wizard_step = 3
                            except Exception:  # noqa: BLE001
                                pass

                            name = (request.form.get("module_name") or "").strip()
                            label = (request.form.get("module_label") or "").strip()
                            provider_type = (request.form.get("module_provider") or "").strip().lower()

                            existing_module: StorageModule | None = None
                            if module_id is not None:
                                existing_module = session_db.get(StorageModule, module_id)
                                if existing_module is None:
                                    errors.append("Storage module not found.")
                                else:
                                    provider_type = (
                                        (existing_module.provider_type or "").strip().lower()
                                    )
                                    if not name:
                                        name = existing_module.name
                                    if not label:
                                        label = existing_module.label or ""

                            if not name:
                                errors.append("Module name is required.")
                            if not provider_type:
                                errors.append("Provider type is required.")

                            config = _build_module_config_from_form(provider_type)
                            if existing_module is not None:
                                try:
                                    current_cfg = (
                                        json.loads(existing_module.config_json)
                                        if existing_module.config_json
                                        else {}
                                    )
                                except Exception:  # noqa: BLE001
                                    current_cfg = {}
                                merged_cfg = dict(current_cfg)
                                merged_cfg.update(config)
                                config = merged_cfg

                            try:
                                if provider_type == "local_drive":
                                    raw_base_dir = request.form.get("module_cfg_local_drive_path")
                                    if raw_base_dir is not None:
                                        raw_base_dir = str(raw_base_dir).strip()
                                        if raw_base_dir:
                                            config["base_dir"] = raw_base_dir
                            except Exception:  # noqa: BLE001
                                pass

                            if not errors:
                                missing_fields = _validate_provider_config(provider_type, config)
                                if missing_fields:
                                    errors.append(
                                        "Missing required fields: "
                                        + ", ".join(missing_fields)
                                    )

                            started = time.monotonic()
                            fp = ""
                            ok_flag = False

                            if errors:
                                module_test_result = {
                                    "ok": False,
                                    "module_name": name,
                                    "message": "; ".join(errors)[:300],
                                }
                                duration_ms = int((time.monotonic() - started) * 1000)
                                _set_last_module_test("", False)
                                errors = []
                            else:
                                tmp_module = StorageModule(
                                    name=name,
                                    label=label or None,
                                    provider_type=provider_type,
                                    is_enabled=1,
                                    config_json=None,
                                )
                                try:
                                    from .storage_providers import (  # noqa: PLC0415
                                        _LegacyProviderAdapter,
                                        _build_provider_for_module,
                                    )

                                    provider = _build_provider_for_module(
                                        current_app,
                                        tmp_module,
                                        config,
                                    )
                                    if provider is None:
                                        raise StorageError("Failed to build provider")
                                    provider.name = name
                                    adapter = _LegacyProviderAdapter(provider)

                                    if action == "module_draft_write_test":
                                        payload = b"pv_write_test"
                                        adapter.write(
                                            io.BytesIO(payload),
                                            {"key_hint": "pv_write_test"},
                                        ).get("object_id")
                                        module_test_result = {
                                            "ok": True,
                                            "module_name": name,
                                            "message": f"Write test OK ({len(payload)} bytes).",
                                        }
                                        ok_flag = True
                                        duration_ms = int((time.monotonic() - started) * 1000)
                                    else:
                                        status = adapter.health_check()
                                        status_text = str(status.get("status") or "ok")
                                        ok_flag = status_text == "ok"
                                        message = status.get("message") or (
                                            f"Health check status: {status_text}"
                                        )
                                        module_test_result = {
                                            "ok": ok_flag,
                                            "module_name": name,
                                            "message": str(message)[:300],
                                        }
                                        duration_ms = int((time.monotonic() - started) * 1000)
                                except StorageError as exc:
                                    module_test_result = {
                                        "ok": False,
                                        "module_name": name,
                                        "message": str(exc)[:300],
                                    }
                                    ok_flag = False
                                    duration_ms = int((time.monotonic() - started) * 1000)
                                except Exception as exc:  # noqa: BLE001
                                    module_test_result = {
                                        "ok": False,
                                        "module_name": name,
                                        "message": str(exc)[:300],
                                    }
                                    ok_flag = False
                                    duration_ms = int((time.monotonic() - started) * 1000)
                                else:
                                    fp = _fingerprint_module_payload(
                                        provider_type,
                                        name,
                                        config,
                                        int(existing_module.id) if existing_module is not None else None,
                                    )
                                    _set_last_module_test(fp, ok_flag)
                                    module_test_ready = bool(ok_flag)
                                    try:
                                        if wizard_draft is not None and isinstance(wizard_draft, dict):
                                            wizard_draft["_step"] = 4 if ok_flag else 3
                                            session["storage_wizard_draft"] = wizard_draft
                                            wizard_step = int(wizard_draft.get("_step") or 3)
                                    except Exception:  # noqa: BLE001
                                        pass

                            if _wants_json():
                                return jsonify(
                                    {
                                        "ok": bool(module_test_result.get("ok")) if isinstance(module_test_result, dict) else False,
                                        "module_name": str(module_test_result.get("module_name") or "") if isinstance(module_test_result, dict) else name,
                                        "message": str(module_test_result.get("message") or "") if isinstance(module_test_result, dict) else "",
                                        "module_test_ready": bool(module_test_ready),
                                        "wizard_step": int(wizard_step or 3),
                                        "fingerprint": str(fp or ""),
                                    }
                                )

                        elif action == "module_create":
                            name = (request.form.get("module_name") or "").strip()
                            label = (request.form.get("module_label") or "").strip()
                            provider_type = (
                                request.form.get("module_provider") or ""
                            ).strip().lower()
                            enabled_flag = 1 if request.form.get("module_enabled") == "1" else 0
                            priority_raw = (request.form.get("module_priority") or "").strip()
                            try:
                                priority_val = int(priority_raw) if priority_raw else 100
                            except ValueError:
                                priority_val = 100

                            if not name:
                                errors.append("Module name is required.")
                            if not provider_type:
                                errors.append("Provider type is required.")

                            existing = None
                            if not errors:
                                existing = (
                                    session_db.query(StorageModule)
                                    .filter(StorageModule.name == name)
                                    .first()
                                )
                                if existing is not None:
                                    errors.append(
                                        "A storage module with this name already exists."
                                    )

                            if not errors:
                                config = _build_module_config_from_form(provider_type)
                                missing_fields = _validate_provider_config(provider_type, config)
                                if missing_fields:
                                    errors.append(
                                        "Missing required fields: "
                                        + ", ".join(missing_fields)
                                    )

                            if not errors:
                                fp_expected = _fingerprint_module_payload(
                                    provider_type,
                                    name,
                                    config,
                                    None,
                                )
                                last_test = _get_last_module_test() or {}
                                client_ok = (request.form.get("module_test_ok") or "").strip() == "1"
                                client_fp = (request.form.get("module_test_fingerprint") or "").strip()
                                client_matches = bool(client_ok and client_fp and client_fp == fp_expected)
                                if client_matches:
                                    _set_last_module_test(fp_expected, True)
                                elif not last_test or not last_test.get("ok"):
                                    errors.append(
                                        "Please test this storage provider successfully before saving."
                                    )
                                elif str(last_test.get("fingerprint") or "") != fp_expected:
                                    errors.append(
                                        "The storage provider configuration changed. Please test again before saving."
                                    )

                            if not errors:
                                now_dt = datetime.now(timezone.utc)
                                module = StorageModule(
                                    name=name,
                                    label=label or None,
                                    provider_type=provider_type,
                                    is_enabled=enabled_flag,
                                    priority=int(priority_val),
                                    config_json=json.dumps(config) if config else None,
                                    updated_at=now_dt,
                                )
                                session_db.add(module)
                                session_db.commit()
                                saved = True
                                edit_module = module
                                edit_module_config = dict(config)
                                try:
                                    session.pop("storage_wizard_draft", None)
                                except Exception:  # noqa: BLE001
                                    pass

                        elif action == "module_update":
                            module_id_raw = request.form.get("module_id") or ""
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None
                            if module_id is None:
                                errors.append("Invalid storage module id.")
                                module = None
                            else:
                                module = session_db.get(StorageModule, module_id)
                                if module is None:
                                    errors.append("Storage module not found.")

                            if not errors and module is not None:
                                new_name = (request.form.get("module_name") or "").strip()
                                new_label = (request.form.get("module_label") or "").strip()
                                enabled_flag = 1 if request.form.get("module_enabled") == "1" else 0
                                priority_raw = (request.form.get("module_priority") or "").strip()
                                try:
                                    priority_val = int(priority_raw) if priority_raw else 100
                                except ValueError:
                                    priority_val = 100

                                if not new_name:
                                    errors.append("Module name is required.")
                                else:
                                    existing = (
                                        session_db.query(StorageModule)
                                        .filter(StorageModule.name == new_name)
                                        .filter(StorageModule.id != module.id)
                                        .first()
                                    )
                                    if existing is not None:
                                        errors.append(
                                            "A storage module with this name already exists."
                                        )

                                provider_type = (
                                    (module.provider_type or "").strip().lower()
                                )
                                try:
                                    current_cfg = (
                                        json.loads(module.config_json)
                                        if module.config_json
                                        else {}
                                    )
                                except Exception:  # noqa: BLE001
                                    current_cfg = {}
                                new_cfg = _build_module_config_from_form(provider_type)
                                merged_cfg = dict(current_cfg)
                                merged_cfg.update(new_cfg)

                                fp_expected = _fingerprint_module_payload(
                                    provider_type,
                                    new_name,
                                    merged_cfg,
                                    int(module.id),
                                )
                                last_test = _get_last_module_test() or {}
                                client_ok = (request.form.get("module_test_ok") or "").strip() == "1"
                                client_fp = (request.form.get("module_test_fingerprint") or "").strip()
                                client_matches = bool(client_ok and client_fp and client_fp == fp_expected)
                                if client_matches:
                                    _set_last_module_test(client_fp, True)
                                elif not last_test or not last_test.get("ok"):
                                    errors.append(
                                        "Please test this storage provider successfully before saving."
                                    )
                                elif str(last_test.get("fingerprint") or "") != fp_expected:
                                    errors.append(
                                        "The storage provider configuration changed. Please test again before saving."
                                    )

                            if not errors and module is not None:
                                module.name = new_name
                                module.label = new_label or None
                                module.is_enabled = enabled_flag
                                module.priority = int(priority_val)
                                module.config_json = json.dumps(merged_cfg) if merged_cfg else None
                                module.updated_at = datetime.now(timezone.utc)
                                session_db.add(module)
                                session_db.commit()
                                saved = True
                                edit_module = module
                                edit_module_config = dict(merged_cfg)

                        elif action == "module_clone":
                            module_id_raw = request.form.get("module_id") or ""
                            new_name = (request.form.get("clone_name") or "").strip()
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None
                            if module_id is None:
                                errors.append("Invalid storage module id.")
                            if not new_name:
                                errors.append("Clone name is required.")

                            src = session_db.get(StorageModule, module_id) if module_id is not None else None
                            if src is None and not errors:
                                errors.append("Storage module not found.")

                            if not errors:
                                existing = (
                                    session_db.query(StorageModule)
                                    .filter(StorageModule.name == new_name)
                                    .first()
                                )
                                if existing is not None:
                                    errors.append(
                                        "A storage module with this name already exists."
                                    )

                            if not errors and src is not None:
                                now_dt = datetime.now(timezone.utc)
                                clone_row = StorageModule(
                                    name=new_name,
                                    label=(src.label or None),
                                    provider_type=src.provider_type,
                                    is_enabled=0,
                                    priority=int(getattr(src, "priority", 100) or 100),
                                    config_json=src.config_json,
                                    updated_at=now_dt,
                                )
                                session_db.add(clone_row)
                                session_db.commit()
                                saved = True

                        elif action == "module_delete":
                            module_id_raw = request.form.get("module_id") or ""
                            force_delete = (request.form.get("force_delete") or "").strip()
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None
                            if module_id is not None:
                                module = session_db.get(StorageModule, module_id)
                                if module is not None:
                                    CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
                                    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
                                    active_streams = (
                                        session_db.query(func.count(func.distinct(CameraRecording.device_id)))
                                        .filter(
                                            CameraRecording.storage_provider == module.name,
                                            CameraRecording.created_at >= cutoff,
                                        )
                                        .scalar()
                                        or 0
                                    )
                                    any_segments = (
                                        session_db.query(func.count(CameraRecording.id))
                                        .filter(CameraRecording.storage_provider == module.name)
                                        .scalar()
                                        or 0
                                    )
                                    if (int(active_streams) > 0 or int(any_segments) > 0) and force_delete != "1":
                                        errors.append(
                                            "This module has existing recordings or active streams. Tick 'Force delete' and submit again to confirm."
                                        )
                                        module = None

                                if module is not None:
                                    session_db.delete(module)
                                    session_db.commit()
                                    saved = True

                        elif action == "module_toggle":
                            module_id_raw = request.form.get("module_id") or ""
                            enable_raw = request.form.get("enable") or ""
                            force_disable = (request.form.get("force_disable") or "").strip()
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None
                            enable_flag = 1 if str(enable_raw) == "1" else 0
                            if module_id is not None:
                                module = session_db.get(StorageModule, module_id)
                                if module is not None:
                                    if enable_flag == 0:
                                        CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
                                        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
                                        active_streams = (
                                            session_db.query(func.count(func.distinct(CameraRecording.device_id)))
                                            .filter(
                                                CameraRecording.storage_provider == module.name,
                                                CameraRecording.created_at >= cutoff,
                                            )
                                            .scalar()
                                            or 0
                                        )
                                        if int(active_streams) > 0 and force_disable != "1":
                                            errors.append(
                                                "This module has active streams. Tick 'Force disable' and submit again to confirm."
                                            )
                                            module = None
                                if module is not None:
                                    module.is_enabled = enable_flag
                                    module.updated_at = datetime.now(timezone.utc)
                                    session_db.add(module)
                                    session_db.commit()
                                    saved = True

                        elif action == "module_write_test":
                            module_id_raw = request.form.get("module_id") or ""
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None
                            module = session_db.get(StorageModule, module_id) if module_id is not None else None
                            if module is None:
                                module_test_result = {
                                    "ok": False,
                                    "module_name": f"#{module_id_raw}",
                                    "message": "Storage module not found.",
                                }
                            else:
                                try:
                                    router = get_storage_router(current_app)
                                    payload = b"pv_write_test"
                                    _ = router.write(
                                        str(module.id),
                                        io.BytesIO(payload),
                                        {"key_hint": "pv_write_test"},
                                    )
                                except Exception as exc:  # noqa: BLE001
                                    module_test_result = {
                                        "ok": False,
                                        "module_name": str(module.name),
                                        "message": str(exc)[:300],
                                    }
                                else:
                                    module_test_result = {
                                        "ok": True,
                                        "module_name": str(module.name),
                                        "message": f"Write test OK ({len(payload)} bytes).",
                                    }

                            if _wants_json():
                                return jsonify(
                                    {
                                        "ok": bool(module_test_result.get("ok")) if isinstance(module_test_result, dict) else False,
                                        "module_name": str(module_test_result.get("module_name") or "") if isinstance(module_test_result, dict) else "",
                                        "message": str(module_test_result.get("message") or "") if isinstance(module_test_result, dict) else "",
                                    }
                                )

            elif action == "test_module":
                module_id_raw = request.form.get("module_id") or ""
                try:
                    module_id = int(module_id_raw)
                except ValueError:
                    module_id = None

                if module_id is None:
                    errors.append("Missing module id.")
                elif record_engine is None:
                    errors.append("Record database is not configured.")
                else:
                    with Session(record_engine) as session_db:
                        StorageModule.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        module = session_db.get(StorageModule, module_id)
                    if module is None:
                        module_test_result = {
                            "ok": False,
                            "module_name": f"#{module_id_raw}",
                            "message": "Storage module not found.",
                        }
                    else:
                        router = get_storage_router(current_app)
                        instance_key = str(module.id)
                        try:
                            status = router.health_check(instance_key)
                        except StorageError as exc:
                            module_test_result = {
                                "ok": False,
                                "module_name": module.name,
                                "message": str(exc)[:300],
                            }
                        except Exception as exc:
                            module_test_result = {
                                "ok": False,
                                "module_name": module.name,
                                "message": str(exc)[:300],
                            }
                        else:
                            status_text = str(status.get("status") or "ok")
                            message = status.get("message") or (
                                f"Health check status: {status_text}"
                            )
                            module_test_result = {
                                "ok": status_text == "ok",
                                "module_name": module.name,
                                "message": str(message)[:300],
                            }

    modules: list[dict] = []
    module_definitions = []
    if record_engine is not None:
        health_by_module_id: dict[int, StorageModuleHealthCheck] = {}
        with Session(record_engine) as session_db:
            StorageModule.__table__.create(
                bind=record_engine,
                checkfirst=True,
            )
            StorageModuleHealthCheck.__table__.create(
                bind=record_engine,
                checkfirst=True,
            )
            rows = (
                session_db.query(StorageModule)
                .order_by(
                    getattr(StorageModule, "priority", StorageModule.id),
                    StorageModule.id,
                )
                .all()
            )

            recent_health = (
                session_db.query(StorageModuleHealthCheck)
                .order_by(StorageModuleHealthCheck.created_at.desc())
                .limit(200)
                .all()
            )
            for h in recent_health:
                try:
                    mid = int(getattr(h, "module_id", 0) or 0)
                except Exception:
                    continue
                if mid <= 0:
                    continue
                if mid not in health_by_module_id:
                    health_by_module_id[mid] = h
        for m in rows:
            try:
                if (
                    str(getattr(m, "provider_type", "") or "")
                    .strip()
                    .lower()
                ) == "gdrive":
                    continue
            except Exception:
                pass
            h = health_by_module_id.get(int(m.id))
            ok_flag = False
            try:
                ok_flag = bool(
                    h is not None
                    and int(getattr(h, "ok", 0)) == 1
                )
            except Exception:
                ok_flag = False
            status = "unknown"
            if ok_flag:
                status = "ok"
            elif h is not None:
                status = "warn"
            status_message = ""
            try:
                status_message = str(getattr(h, "message", "") or "")
            except Exception:
                status_message = ""
            modules.append(
                {
                    "id": m.id,
                    "name": m.name,
                    "label": m.label or "",
                    "provider_type": m.provider_type,
                    "is_enabled": bool(getattr(m, "is_enabled", 0)),
                    "priority": int(getattr(m, "priority", 100) or 100),
                    "status": status,
                    "status_message": status_message,
                }
            )

    selected_metrics = None
    streams_rows: list[object] = []
    upload_rows: list[object] = []
    logs_rows: list[object] = []
    recent_error_rows: list[object] = []
    if record_engine is not None and edit_module is not None:
        CameraRecording.__table__.create(
            bind=record_engine,
            checkfirst=True,
        )
        UploadQueueItem.__table__.create(
            bind=record_engine,
            checkfirst=True,
        )
        StorageModuleEvent.__table__.create(
            bind=record_engine,
            checkfirst=True,
        )
        StorageModuleWriteStat.__table__.create(
            bind=record_engine,
            checkfirst=True,
        )

        selected_module_id = None
        try:
            selected_module_id = int(
                getattr(edit_module, "id", 0) or 0
            )
        except Exception:
            selected_module_id = None

        selected_module_name = ""
        try:
            selected_module_name = str(getattr(edit_module, "name", "") or "")
        except Exception:
            selected_module_name = ""

        with Session(record_engine) as session_db:
            StorageModuleHealthCheck.__table__.create(
                bind=record_engine,
                checkfirst=True,
            )

            latest_health = (
                session_db.query(StorageModuleHealthCheck)
                .filter(
                    StorageModuleHealthCheck.module_id
                    == selected_module_id
                )
                .order_by(StorageModuleHealthCheck.created_at.desc())
                .first()
            )

            is_stale = False
            if latest_health is not None:
                try:
                    age_s = (
                        datetime.now(timezone.utc)
                        - latest_health.created_at
                    ).total_seconds()
                    is_stale = age_s >= 300
                except Exception:
                    is_stale = False

            if latest_health is None or is_stale:
                started = time.monotonic()
                status = None
                try:
                    router = get_storage_router(current_app)
                    status = router.health_check(str(selected_module_id))
                except Exception:
                    status = None
                duration_ms = int(
                    (time.monotonic() - started) * 1000
                )

                if status is not None:
                    try:
                        status_text = str(status.get("status") or "ok")
                        ok = 1 if status_text == "ok" else 0
                        msg = str(status.get("message") or "")
                    except Exception:
                        ok = 0
                        msg = ""
                    try:
                        session_db.add(
                            StorageModuleHealthCheck(
                                module_id=int(selected_module_id or 0),
                                module_name=str(
                                    selected_module_name or ""
                                )[:160],
                                provider_type=str(
                                    getattr(
                                        edit_module,
                                        "provider_type",
                                        "",
                                    )
                                    or ""
                                )[:64]
                                or None,
                                ok=int(ok),
                                message=msg[:512] if msg else None,
                                duration_ms=int(duration_ms),
                            )
                        )
                        session_db.commit()
                    except Exception:
                        pass

                    latest_health = (
                        session_db.query(StorageModuleHealthCheck)
                        .filter(
                            StorageModuleHealthCheck.module_id
                            == selected_module_id
                        )
                        .order_by(StorageModuleHealthCheck.created_at.desc())
                        .first()
                    )

            try:
                if latest_health is not None:
                    setattr(
                        edit_module,
                        "status",
                        (
                            "ok"
                            if int(getattr(latest_health, "ok", 0)) == 1
                            else "warn"
                        ),
                    )
                    msg = str(getattr(latest_health, "message", "") or "")
                    setattr(edit_module, "status_message", msg)
                else:
                    setattr(edit_module, "status", "unknown")
                    setattr(
                        edit_module,
                        "status_message",
                        "No recent status.",
                    )
            except Exception:
                pass

            last_row = (
                session_db.query(CameraRecording)
                .filter(
                    CameraRecording.storage_provider
                    == selected_module_name
                )
                .order_by(CameraRecording.created_at.desc())
                .first()
            )
            last_write_text = "n/a"
            last_write_stat = (
                session_db.query(StorageModuleWriteStat)
                .filter(
                    StorageModuleWriteStat.module_name == selected_module_name
                )
                .order_by(StorageModuleWriteStat.created_at.desc())
                .first()
            )
            if last_write_stat is not None and getattr(
                last_write_stat,
                "created_at",
                None,
            ):
                last_write_text = str(last_write_stat.created_at)
            elif last_row is not None and getattr(
                last_row,
                "created_at",
                None,
            ):
                last_write_text = str(last_row.created_at)

            cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
            active_streams = (
                session_db.query(
                    func.count(
                        func.distinct(CameraRecording.device_id)
                    )
                )
                .filter(
                    CameraRecording.storage_provider == selected_module_name,
                    CameraRecording.created_at >= cutoff,
                )
                .scalar()
                or 0
            )

            cutoff_15m = datetime.now(timezone.utc) - timedelta(minutes=15)
            last_ok_row = (
                session_db.query(StorageModuleWriteStat)
                .filter(
                    StorageModuleWriteStat.module_name
                    == selected_module_name,
                    StorageModuleWriteStat.ok == 1,
                )
                .order_by(StorageModuleWriteStat.created_at.desc())
                .first()
            )
            last_err_row = (
                session_db.query(StorageModuleWriteStat)
                .filter(
                    StorageModuleWriteStat.module_name
                    == selected_module_name,
                    StorageModuleWriteStat.ok == 0,
                )
                .order_by(StorageModuleWriteStat.created_at.desc())
                .first()
            )
            recent_ok = (
                session_db.query(
                    func.count(StorageModuleWriteStat.id),
                    func.coalesce(
                        func.sum(StorageModuleWriteStat.bytes_written),
                        0,
                    ),
                )
                .filter(
                    StorageModuleWriteStat.module_name
                    == selected_module_name,
                    StorageModuleWriteStat.ok == 1,
                    StorageModuleWriteStat.created_at >= cutoff_15m,
                )
                .first()
            )
            writes_15m = int(recent_ok[0] or 0) if recent_ok else 0
            bytes_15m = int(recent_ok[1] or 0) if recent_ok else 0

            recent_error_rows = (
                session_db.query(StorageModuleEvent)
                .filter(
                    (
                        StorageModuleEvent.module_id
                        == int(selected_module_id or 0)
                    )
                    | (
                        StorageModuleEvent.module_name
                        == selected_module_name
                    )
                )
                .filter(StorageModuleEvent.level == "error")
                .order_by(StorageModuleEvent.created_at.desc())
                .limit(5)
                .all()
            )

            selected_metrics = {
                "last_write_text": last_write_text,
                "active_streams": int(active_streams),
                "last_ok_text": (
                    str(last_ok_row.created_at)
                    if (
                        last_ok_row is not None
                        and getattr(last_ok_row, "created_at", None)
                    )
                    else "n/a"
                ),
                "last_error_text": (
                    str(last_err_row.created_at)
                    if last_err_row is not None
                    and getattr(last_err_row, "created_at", None)
                    else "n/a"
                ),
                "last_error_message": (
                    str(last_err_row.error)[:200]
                    if last_err_row is not None
                    and getattr(last_err_row, "error", None)
                    else ""
                ),
                "writes_15m": writes_15m,
                "bytes_15m": bytes_15m,
            }

            streams_rows = (
                session_db.query(CameraRecording)
                .filter(
                    CameraRecording.storage_provider
                    == selected_module_name
                )
                .order_by(CameraRecording.created_at.desc())
                .limit(25)
                .all()
            )
            upload_rows = (
                session_db.query(UploadQueueItem)
                .filter(UploadQueueItem.provider_name == selected_module_name)
                .order_by(UploadQueueItem.created_at.desc())
                .limit(25)
                .all()
            )
            logs_rows = (
                session_db.query(StorageModuleEvent)
                .filter(
                    (
                        StorageModuleEvent.module_id
                        == int(selected_module_id or 0)
                    )
                    | (
                        StorageModuleEvent.module_name
                        == selected_module_name
                    )
                )
                .order_by(StorageModuleEvent.created_at.desc())
                .limit(25)
                .all()
            )
    global_csrf_token = None
    try:
        global_csrf_token = session.get("global_csrf")
    except Exception:
        global_csrf_token = None
    if not global_csrf_token:
        try:
            import secrets

            global_csrf_token = secrets.token_urlsafe(32)
            session["global_csrf"] = global_csrf_token
        except Exception:
            global_csrf_token = None

    open_wizard = False
    try:
        open_wizard = bool(request.args.get("wizard"))
    except Exception:  # noqa: BLE001
        open_wizard = False
    try:
        raw_draft = session.get("storage_wizard_draft")
    except Exception:  # noqa: BLE001
        raw_draft = None
    if isinstance(raw_draft, dict):
        wizard_draft = raw_draft
        try:
            wizard_step = int(raw_draft.get("_step") or 1)
        except Exception:  # noqa: BLE001
            wizard_step = 1
    if request.method == "POST":
        try:
            if (request.form.get("action") or "").strip() == "module_draft_test" and edit_module is None:
                open_wizard = True
        except Exception:  # noqa: BLE001
            pass

    return render_template(
        "storage_modules.html",
        global_csrf_token=global_csrf_token,
        modules=modules,
        module_test_result=module_test_result,
        module_test_ready=module_test_ready,
        open_wizard=open_wizard,
        wizard_draft=wizard_draft,
        wizard_step=wizard_step,
        selected_module=edit_module,
        selected_metrics=selected_metrics,
        streams_rows=streams_rows,
        upload_rows=upload_rows,
        logs_rows=logs_rows,
        recent_error_rows=recent_error_rows,
        gcs=None,
        dropbox=None,
        webdav=None,
        errors=errors,
        saved=saved,
        edit_module=edit_module,
        edit_module_config=edit_module_config,
        module_definitions=module_definitions,
    )
