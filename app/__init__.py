from flask import Flask

from .auth import bp as auth_bp
from .camera_admin import bp as camera_admin_bp
from .config import load_config
from .installer import bp as installer_bp
from .views import bp as main_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(load_config())
    app.register_blueprint(main_bp)
    app.register_blueprint(installer_bp, url_prefix="/install")
    app.register_blueprint(auth_bp)
    app.register_blueprint(camera_admin_bp)
    return app
