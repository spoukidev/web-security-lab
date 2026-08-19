"""Route registration for the application."""
from flask import Flask
from . import auth, csrf, fetch, search, upload, users, xss


def register_blueprints(app: Flask) -> None:
    for blueprint in (auth.blueprint, users.blueprint, search.blueprint, xss.blueprint, upload.blueprint, fetch.blueprint, csrf.blueprint):
        app.register_blueprint(blueprint)
