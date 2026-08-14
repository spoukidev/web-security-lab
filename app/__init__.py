"""Application factory for the local Web Security Lab."""
from __future__ import annotations
from pathlib import Path
from flask import Flask
from .config import Config
from .database import init_app as init_database_app
from .routes import register_blueprints


def create_app(test_config: dict[str, object] | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config is not None:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_DIRECTORY"]).mkdir(parents=True, exist_ok=True)
    init_database_app(app)
    register_blueprints(app)
    with app.app_context():
        from .database import initialize_database
        initialize_database()
    return app
