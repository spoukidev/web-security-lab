"""File upload route placeholder."""
from flask import Blueprint, render_template
blueprint = Blueprint("upload", __name__)


@blueprint.get("/upload")
def upload() -> str:
    return render_template("upload.html")
