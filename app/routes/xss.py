"""Controlled reflected and stored XSS demonstration routes."""

from __future__ import annotations

from typing import Literal

from flask import Blueprint, Response, redirect, render_template, request, url_for

from app.database import get_database

blueprint = Blueprint("xss", __name__)
RenderMode = Literal["vulnerable", "secure"]

SECURE_CSP = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"


def selected_mode(value: str | None) -> RenderMode:
    """Return a known lab mode and default unknown values to vulnerable."""
    return "secure" if value == "secure" else "vulnerable"


@blueprint.route("/comments", methods=["GET", "POST"])
def comments() -> Response | str:
    """Show reflected and stored XSS behavior against local fake comments."""
    mode = selected_mode(request.values.get("mode"))

    if request.method == "POST":
        body = request.form.get("body", "").strip()
        if body:
            # Data storage is parameterized; the intentional flaw is the
            # unsafe HTML rendering path below, not SQL query construction.
            database = get_database()
            database.execute("INSERT INTO comments (user_id, body) VALUES (?, ?)", (1, body))
            database.commit()
        return redirect(url_for("xss.comments", mode=mode, saved="1"))

    preview = request.args.get("preview", "")
    comments_list = get_database().execute(
        "SELECT comments.id, users.username, comments.body, comments.created_at "
        "FROM comments JOIN users ON users.id = comments.user_id ORDER BY comments.id DESC"
    ).fetchall()
    response = Response(
        render_template(
            "comments.html",
            mode=mode,
            preview=preview,
            comments=comments_list,
            saved=request.args.get("saved") == "1",
        )
    )
    if mode == "secure":
        # CSP is defense in depth; Jinja autoescaping is the primary fix here.
        response.headers["Content-Security-Policy"] = SECURE_CSP
    return response
