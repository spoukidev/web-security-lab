"""Authentication lab route placeholder."""
from flask import Blueprint, render_template
blueprint = Blueprint("auth", __name__)


@blueprint.get("/login")
def login() -> str:
    return render_template("login.html")
