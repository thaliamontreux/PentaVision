from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import (
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.orm import Session

from .db import get_record_engine
from .models import StorageModule, StorageSettings
from .security import (
    get_current_user,
    user_has_role,
    validate_global_csrf_token,
)
from .storage_providers import _load_storage_settings
from .storage_csal import StorageError, get_storage_router


def storage_settings_page():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))
    if not user_has_role(user, "System Administrator"):
        from flask import abort

        abort(403)

    cfg = current_app.config
    errors: list[str] = []
    saved = False
    module_test_result: dict | None = None
    module_test_ready = False
    wizard_draft: dict[str, object] | None = None
    wizard_step = 1

    db_settings = _load_storage_settings() or {}

    raw_targets = db_settings.get("storage_targets") or str(
        cfg.get("STORAGE_TARGETS", "local_fs") or "local_fs"
    )

    form = {
        "storage_targets": raw_targets,
        "local_storage_path": db_settings.get("local_storage_path")
        or str(
            cfg.get("LOCAL_STORAGE_PATH")
            or cfg.get("RECORDING_BASE_DIR")
            or ""
        ),
        "recording_base_dir": db_settings.get("recording_base_dir")
        or str(cfg.get("RECORDING_BASE_DIR") or ""),
        "s3_bucket": db_settings.get("s3_bucket")
        or str(cfg.get("S3_BUCKET") or ""),
        "s3_endpoint": db_settings.get("s3_endpoint")
        or str(cfg.get("S3_ENDPOINT") or ""),
        "s3_region": db_settings.get("s3_region")
        or str(cfg.get("S3_REGION") or ""),
        "s3_access_key": "",
        "s3_secret_key": "",
        "gcs_bucket": db_settings.get("gcs_bucket")
        or str(cfg.get("GCS_BUCKET") or ""),
        "azure_blob_connection_string": "",
        "azure_blob_container": db_settings.get("azure_blob_container")
        or str(cfg.get("AZURE_BLOB_CONTAINER") or ""),
        "dropbox_access_token": "",
        "webdav_base_url": db_settings.get("webdav_base_url")
        or str(cfg.get("WEBDAV_BASE_URL") or ""),
        "webdav_username": db_settings.get("webdav_username")
        or str(cfg.get("WEBDAV_USERNAME") or ""),
        "webdav_password": "",
    }

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
        action = request.form.get("action") or ""
        if not validate_global_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")
        else:
            if not action or action == "save_legacy":
                for key in form.keys():
                    form[key] = (request.form.get(key) or "").strip()

                if not form["storage_targets"]:
                    form["storage_targets"] = "local_fs"

                if record_engine is None:
                    errors.append("Record database is not configured.")

                if not errors and record_engine is not None:
                    with Session(record_engine) as session_db:
                        StorageSettings.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        settings = (
                            session_db.query(StorageSettings)
                            .order_by(StorageSettings.id)
                            .first()
                        )
                        if settings is None:
                            settings = StorageSettings()
                            session_db.add(settings)

                        settings.storage_targets = (
                            form["storage_targets"] or None
                        )
                        settings.local_storage_path = (
                            form["local_storage_path"] or None
                        )
                        settings.recording_base_dir = (
                            form["recording_base_dir"] or None
                        )
                        settings.s3_bucket = form["s3_bucket"] or None
                        settings.s3_endpoint = form["s3_endpoint"] or None
                        settings.s3_region = form["s3_region"] or None
                        if form["s3_access_key"]:
                            settings.s3_access_key = form["s3_access_key"]
                        if form["s3_secret_key"]:
                            settings.s3_secret_key = form["s3_secret_key"]
                        settings.gcs_bucket = form["gcs_bucket"] or None
                        if form["azure_blob_connection_string"]:
                            settings.azure_blob_connection_string = form[
                                "azure_blob_connection_string"
                            ]
                        settings.azure_blob_container = (
                            form["azure_blob_container"] or None
                        )
                        if form["dropbox_access_token"]:
                            settings.dropbox_access_token = (
                                form["dropbox_access_token"]
                            )
                        settings.webdav_base_url = (
                            form["webdav_base_url"] or None
                        )
                        settings.webdav_username = (
                            form["webdav_username"] or None
                        )
                        if form["webdav_password"]:
                            settings.webdav_password = form["webdav_password"]
                        settings.updated_at = datetime.now(
                            timezone.utc,
                        )

                        session_db.add(settings)
                        session_db.commit()

                    saved = True
                    db_settings = _load_storage_settings() or {}
                    raw_targets = db_settings.get("storage_targets") or str(
                        cfg.get("STORAGE_TARGETS", "local_fs") or "local_fs"
                    )
                    form["storage_targets"] = raw_targets
                    form["local_storage_path"] = db_settings.get(
                        "local_storage_path"
                    ) or str(
                        cfg.get("LOCAL_STORAGE_PATH")
                        or cfg.get("RECORDING_BASE_DIR")
                        or ""
                    )
                    form["recording_base_dir"] = db_settings.get(
                        "recording_base_dir"
                    ) or str(cfg.get("RECORDING_BASE_DIR") or "")
                    form["s3_bucket"] = db_settings.get("s3_bucket") or str(
                        cfg.get("S3_BUCKET") or ""
                    )
                    form["s3_endpoint"] = db_settings.get(
                        "s3_endpoint"
                    ) or str(cfg.get("S3_ENDPOINT") or "")
                    form["s3_region"] = db_settings.get("s3_region") or str(
                        cfg.get("S3_REGION") or ""
                    )
                    form["gcs_bucket"] = db_settings.get("gcs_bucket") or str(
                        cfg.get("GCS_BUCKET") or ""
                    )
                    form["azure_blob_container"] = db_settings.get(
                        "azure_blob_container"
                    ) or str(cfg.get("AZURE_BLOB_CONTAINER") or "")
                    form["webdav_base_url"] = db_settings.get(
                        "webdav_base_url"
                    ) or str(cfg.get("WEBDAV_BASE_URL") or "")
                    form["webdav_username"] = db_settings.get(
                        "webdav_username"
                    ) or str(cfg.get("WEBDAV_USERNAME") or "")
                    form["s3_access_key"] = ""
                    form["s3_secret_key"] = ""
                    form["azure_blob_connection_string"] = ""
                    form["dropbox_access_token"] = ""
                    form["webdav_password"] = ""

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
        with Session(record_engine) as session_db:
            StorageModule.__table__.create(
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
            modules.append(
                {
                    "id": m.id,
                    "name": m.name,
                    "label": m.label or "",
                    "provider_type": m.provider_type,
                    "is_enabled": bool(getattr(m, "is_enabled", 0)),
                    "priority": int(getattr(m, "priority", 100) or 100),
                }
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

    return render_template(
        "storage_modules.html",
        config=form,
        modules=modules,
        module_test_result=module_test_result,
        module_test_ready=module_test_ready,
        open_wizard=False,
        wizard_draft=wizard_draft,
        wizard_step=wizard_step,
        selected_module=edit_module,
        selected_metrics=None,
        streams_rows=[],
        upload_rows=[],
        logs_rows=[],
        recent_error_rows=[],
        s3=None,
        gcs=None,
        azure=None,
        dropbox=None,
        webdav=None,
        form=form,
        errors=errors,
        saved=saved,
        edit_module=edit_module,
        edit_module_config=edit_module_config,
        module_definitions=module_definitions,
    )
