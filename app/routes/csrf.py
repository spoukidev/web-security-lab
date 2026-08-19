"""Controlled CSRF lab for a fake local email-change action."""
from __future__ import annotations
import hmac
import secrets
from urllib.parse import urlsplit
from flask import Blueprint, abort, render_template, request, session
from app.database import get_database

blueprint = Blueprint("csrf", __name__)


def current_user():
    user_id = session.get("authenticated_user_id")
    if not isinstance(user_id, int):
        return None
    return get_database().execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,)).fetchone()


def csrf_token() -> str:
    """Create one session-bound synchronizer token for the local secure lab."""
    token = session.get("csrf_token")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def is_same_origin_request() -> bool:
    """Require Origin or Referer to match the host for secure state changes."""
    expected = request.host_url.rstrip("/")
    origin = request.headers.get("Origin")
    if origin:
        return hmac.compare_digest(origin.rstrip("/"), expected)
    referer = request.headers.get("Referer")
    if not referer:
        return False
    parsed = urlsplit(referer)
    return hmac.compare_digest(f"{parsed.scheme}://{parsed.netloc}", expected)


@blueprint.route("/change-email", methods=["GET", "POST"])
def change_email() -> tuple[str, int] | str:
    """Demonstrate an unprotected and a token-protected local state change."""
    mode = "secure" if request.values.get("mode") == "secure" else "vulnerable"
    user = current_user()
    if user is None:
        return render_template("change_email.html", mode=mode, user=None, token=None, message=None, error_message="Issue a fake local token in the JWT lab before changing an email."), 401
    message: str | None = None
    error_message: str | None = None
    token = csrf_token()
    if request.method == "POST":
        new_email = request.form.get("email", "").strip()
        if not new_email.endswith("@example.test"):
            error_message = "Use a fake @example.test address only."
        elif mode == "secure" and (not hmac.compare_digest(request.form.get("csrf_token", ""), token) or not is_same_origin_request()):
            error_message = "Secure mode rejected the request: CSRF token or request origin is invalid."
        else:
            # INTENTIONALLY VULNERABLE
            # This code exists only for the local Web Security Lab.
            # Vulnerable mode performs a state change with no CSRF validation.
            get_database().execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user["id"]))
            get_database().commit()
            user = get_database().execute("SELECT id, username, email FROM users WHERE id = ?", (user["id"],)).fetchone()
            message = "The fake local email address was changed."
    return render_template("change_email.html", mode=mode, user=user, token=token, message=message, error_message=error_message)
