from flask import Flask, request
from werkzeug.exceptions import HTTPException

from jinja2 import ChoiceLoader, FileSystemLoader

from .admin import bp as admin_bp
from .auth import bp as auth_bp
from .camera_admin import bp as camera_admin_bp
from .config import load_config
from .db import get_face_engine, get_record_engine, get_user_engine
from .installer import bp as installer_bp
from .models import create_face_schema, create_record_schema, create_user_schema
from .security import init_security
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
        try:
            engine = get_user_engine()
            if engine is not None:
                create_user_schema(engine)
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
        except Exception:  # noqa: BLE001
            pass

    start_storage_startup_checks(app)
    start_startup_url_healthcheck(app)

    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(installer_bp, url_prefix="/install")
    app.register_blueprint(auth_bp)
    app.register_blueprint(camera_admin_bp)

    @app.errorhandler(Exception)
    def _handle_uncaught(err):  # pragma: no cover - error wiring
        if isinstance(err, HTTPException):
            return err
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
