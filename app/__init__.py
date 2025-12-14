from flask import Flask

from .admin import bp as admin_bp
from .auth import bp as auth_bp
from .camera_admin import bp as camera_admin_bp
from .config import load_config
from .db import get_face_engine, get_record_engine, get_user_engine
from .installer import bp as installer_bp
from .models import create_face_schema, create_record_schema, create_user_schema
from .security import init_security
from .views import bp as main_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(load_config())
    init_security(app)

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
        except Exception:  # noqa: BLE001
            pass

    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(installer_bp, url_prefix="/install")
    app.register_blueprint(auth_bp)
    app.register_blueprint(camera_admin_bp)
    return app
