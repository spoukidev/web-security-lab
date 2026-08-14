"""Route registration for the application."""
from flask import Flask
from . import auth, fetch, search, upload, users


def register_blueprints(app: Flask) -> None:
    for blueprint in (auth.blueprint, users.blueprint, search.blueprint, upload.blueprint, fetch.blueprint):
        app.register_blueprint(blueprint)
