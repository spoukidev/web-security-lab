"""Dashboard and controlled IDOR lab routes."""
from __future__ import annotations
from typing import Literal
from flask import Blueprint, abort, jsonify, redirect, render_template, request, session, url_for
from app.database import get_database
blueprint = Blueprint("users", __name__)


@blueprint.get("/")
def index() -> str:
    return render_template("index.html")


@blueprint.get("/health")
def health() -> tuple[dict[str, str], int]:
    return jsonify({"status": "ok", "scope": "local-web-security-lab"}), 200


AccessMode = Literal["vulnerable", "secure"]


def get_lab_actor_id() -> int:
    """Return the selected fake lab actor; this is not real authentication."""
    actor_id = session.get("lab_actor_id", 1)
    return actor_id if isinstance(actor_id, int) else 1


@blueprint.post("/lab/select-actor")
def select_lab_actor() -> object:
    """Set the fake actor used solely to demonstrate authorization behavior."""
    actor_id = request.form.get("actor_id", type=int)
    target_id = request.form.get("target_id", default=1, type=int)
    mode = "secure" if request.form.get("mode") == "secure" else "vulnerable"
    if actor_id is None:
        abort(400)
    actor = get_database().execute("SELECT id FROM users WHERE id = ?", (actor_id,)).fetchone()
    if actor is None:
        abort(400)
    session["lab_actor_id"] = actor_id
    return redirect(url_for("users.profile", user_id=target_id, mode=mode))


@blueprint.get("/profile/<int:user_id>")
def profile(user_id: int) -> tuple[str, int] | str:
    """Show deliberately missing or enforced object-level authorization."""
    requested_mode = request.args.get("mode", "vulnerable")
    mode: AccessMode = "secure" if requested_mode == "secure" else "vulnerable"
    database = get_database()
    actor_id = get_lab_actor_id()
    actor = database.execute("SELECT id, username FROM users WHERE id = ?", (actor_id,)).fetchone()
    profile_row = database.execute(
        "SELECT users.id, users.username, users.email, users.role, profiles.display_name, profiles.bio "
        "FROM users JOIN profiles ON profiles.user_id = users.id WHERE users.id = ?",
        (user_id,),
    ).fetchone()
    if actor is None or profile_row is None:
        abort(404)

    if mode == "vulnerable":
        # INTENTIONALLY VULNERABLE
        # This code exists only for the local Web Security Lab.
        # The requested profile is returned without checking the actor's ownership.
        return render_template("profile.html", mode=mode, actor=actor, profile=profile_row)

    if actor_id != user_id:
        # The fix enforces server-side, object-level authorization before data is rendered.
        return render_template("profile.html", mode=mode, actor=actor, profile=None), 403
    return render_template("profile.html", mode=mode, actor=actor, profile=profile_row)


@blueprint.get("/labs/<string:lab_name>")
def lab_placeholder(lab_name: str) -> tuple[str, int] | str:
    labs = {"sql-injection": "SQL Injection", "xss": "Cross-Site Scripting", "idor": "Insecure Direct Object Reference", "ssrf": "Server-Side Request Forgery", "jwt": "JWT / Authentication", "file-upload": "Insecure File Upload", "csrf": "Cross-Site Request Forgery"}
    if lab_name not in labs:
        return render_template("lab.html", title="Lab not found", phase="Unknown lab"), 404
    return render_template("lab.html", title=labs[lab_name], phase="Planned for a later phase")
