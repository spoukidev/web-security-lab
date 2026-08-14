"""SSRF route placeholder."""
from flask import Blueprint, render_template
blueprint = Blueprint("fetch", __name__)


@blueprint.get("/fetch")
def fetch() -> str:
    return render_template("lab.html", title="SSRF", phase="Planned for Phase 5")
