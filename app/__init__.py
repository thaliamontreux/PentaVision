import sys
import traceback
import json
import os
from datetime import datetime, timezone

from flask import Flask, request
from werkzeug.exceptions import HTTPException

from jinja2 import ChoiceLoader, FileSystemLoader

from sqlalchemy.orm import Session

from .admin import bp as admin_bp
from .auth import bp as auth_bp
from .camera_admin import bp as camera_admin_bp
from .config import load_config
from .db import get_face_engine, get_record_engine, get_user_engine
from .diagnostics import (
    bp as diagnostics_bp,
)
from .installer import bp as installer_bp
from .property_manager import bp as pm_bp
from .models import (
    create_face_schema,
    create_record_schema,
    create_user_schema,
    StorageModule,
    # Enhanced Plugins models - must be imported to register with RecordBase.metadata
    EnhancedPlugin,
    PluginPropertyAssignment,
    PluginHealthCheck,
    PluginEvent,
    PluginTestRun,
    PluginApiKeyRotation,
)
from .plugin_routes import plugin_bp  # Import after models to ensure tables are registered
from .security import (
    apply_sql_seed_file,
    init_security,
    seed_system_admin_role_for_email,
)
from .storage_startup import start_storage_startup_checks
from .url_healthcheck import start_startup_url_healthcheck
from .views import bp as main_bp
from .logging_utils import pv_log, pv_log_exception


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(load_config())
    init_security(app)
    app.jinja_loader = ChoiceLoader(
        [
            app.jinja_loader,
            FileSystemLoader(app.root_path),
        ]
    )

    try:
        from .modules.storage.registry import (  # noqa: PLC0415
            load_storage_provider_plugins,
        )

        load_storage_provider_plugins()
    except Exception:  # noqa: BLE001
        pass

    with app.app_context():
        engine = None
        try:
            engine = get_user_engine()
            if engine is not None:
                create_user_schema(engine)
                try:
                    seed_path = os.path.abspath(
                        os.path.join(
                            os.path.dirname(__file__),
                            "..",
                            "deploy",
                            "pentavision_rbac_seed.sql",
                        )
                    )
                    apply_sql_seed_file(engine, seed_path)
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            pass

        if engine is not None:
            try:
                bootstrap_email = str(
                    app.config.get("BOOTSTRAP_SYSTEM_ADMIN_EMAIL") or ""
                ).strip().lower()
                if bootstrap_email:
                    seed_system_admin_role_for_email(bootstrap_email)
            except Exception:  # noqa: BLE001
                pass
        try:
            engine = get_face_engine()
            if engine is not None:
                create_face_schema(engine)
        except Exception:  # noqa: BLE001
            pass
        try:
            engine = get_record_engine()
            if engine is not None:
                create_record_schema(engine)
                try:
                    from .modules.storage.registry import (  # noqa: PLC0415
                        sync_installed_storage_provider_modules,
                    )

                    sync_installed_storage_provider_modules(engine)
                except Exception:  # noqa: BLE001
                    pass

                try:
                    with Session(engine) as session_db:
                        StorageModule.__table__.create(
                            bind=engine,
                            checkfirst=True,
                        )
                        enabled_count = (
                            session_db.query(StorageModule)
                            .filter(StorageModule.is_enabled != 0)
                            .count()
                        )
                        if enabled_count <= 0:
                            base_dir = (
                                app.config.get("LOCAL_STORAGE_PATH")
                                or app.config.get("RECORDING_BASE_DIR")
                                or os.path.join(app.instance_path, "recordings")
                            )
                            now_dt = datetime.now(timezone.utc)

                            candidate = (
                                session_db.query(StorageModule)
                                .filter(StorageModule.name == "local_fs")
                                .first()
                            )
                            if candidate is None:
                                candidate = (
                                    session_db.query(StorageModule)
                                    .filter(
                                        StorageModule.provider_type
                                        == "local_fs"
                                    )
                                    .order_by(StorageModule.id)
                                    .first()
                                )
                            if candidate is None:
                                candidate = (
                                    session_db.query(StorageModule)
                                    .order_by(
                                        StorageModule.priority,
                                        StorageModule.id,
                                    )
                                    .first()
                                )

                            if candidate is not None:
                                candidate.is_enabled = 1
                                candidate.updated_at = now_dt
                                if (
                                    (candidate.provider_type or "").strip().lower()
                                    == "local_fs"
                                ):
                                    cfg = {}
                                    try:
                                        cfg = json.loads(
                                            candidate.config_json
                                            or "{}"
                                        )
                                    except Exception:  # noqa: BLE001
                                        cfg = {}
                                    if not str(cfg.get("base_dir") or "").strip():
                                        cfg["base_dir"] = str(base_dir)
                                        try:
                                            candidate.config_json = json.dumps(cfg)
                                        except Exception:  # noqa: BLE001
                                            pass
                            else:
                                cfg_text = None
                                try:
                                    cfg_text = json.dumps(
                                        {"base_dir": str(base_dir)}
                                    )
                                except Exception:  # noqa: BLE001
                                    cfg_text = None
                                session_db.add(
                                    StorageModule(
                                        name="local_fs",
                                        label="Local filesystem",
                                        provider_type="local_fs",
                                        is_enabled=1,
                                        priority=100,
                                        config_json=cfg_text,
                                        created_at=now_dt,
                                        updated_at=now_dt,
                                    )
                                )
                            session_db.commit()
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            pass

    start_storage_startup_checks(app)
    start_startup_url_healthcheck(app)

    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(installer_bp, url_prefix="/install")
    app.register_blueprint(auth_bp)
    app.register_blueprint(diagnostics_bp)
    app.register_blueprint(camera_admin_bp)
    app.register_blueprint(pm_bp)
    app.register_blueprint(plugin_bp)

    @app.errorhandler(Exception)
    def _handle_uncaught(err):  # pragma: no cover - error wiring
        if isinstance(err, HTTPException):
            return err
        try:
            traceback.print_exc(file=sys.stderr)
        except Exception:
            pass
        try:
            pv_log_exception(
                "system",
                "uncaught_exception",
                component="flask",
                exc=err,
                path=str(getattr(request, "path", "") or "")[:512],
                method=str(getattr(request, "method", "") or "")[:32],
            )
        except Exception:
            pass
        return ("Internal Server Error", 500)

    @app.errorhandler(404)
    def _handle_404(err):  # pragma: no cover - error wiring
        try:
            from .logging_utils import record_invalid_url_attempt
            path = request.path or ""
            record_invalid_url_attempt(path)
        except Exception:
            pass
        return ("Not Found", 404)

    try:
        pv_log("system", "info", "system_startup", component="app")
    except Exception:
        pass
    return app
