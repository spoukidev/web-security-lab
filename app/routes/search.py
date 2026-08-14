"""SQL injection route placeholder."""
from flask import Blueprint, render_template
blueprint = Blueprint("search", __name__)


@blueprint.get("/search")
def search() -> str:
    return render_template("search.html")
