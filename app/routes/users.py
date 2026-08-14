"""Dashboard and user-lab route placeholders."""
from flask import Blueprint, jsonify, render_template
blueprint = Blueprint("users", __name__)


@blueprint.get("/")
def index() -> str:
    return render_template("index.html")


@blueprint.get("/health")
def health() -> tuple[dict[str, str], int]:
    return jsonify({"status": "ok", "scope": "local-web-security-lab"}), 200


@blueprint.get("/profile/<int:user_id>")
def profile(user_id: int) -> str:
    """Placeholder; IDOR behavior is implemented only in Phase 4."""
    return render_template("profile.html", user_id=user_id)


@blueprint.get("/labs/<string:lab_name>")
def lab_placeholder(lab_name: str) -> tuple[str, int] | str:
    labs = {"sql-injection": "SQL Injection", "xss": "Cross-Site Scripting", "idor": "Insecure Direct Object Reference", "ssrf": "Server-Side Request Forgery", "jwt": "JWT / Authentication", "file-upload": "Insecure File Upload", "csrf": "Cross-Site Request Forgery"}
    if lab_name not in labs:
        return render_template("lab.html", title="Lab not found", phase="Unknown lab"), 404
    return render_template("lab.html", title=labs[lab_name], phase="Planned for a later phase")
