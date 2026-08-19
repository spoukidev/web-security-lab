"""Controlled JWT authentication-flaw lab using fake accounts only."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import time
from typing import Any, Literal
from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from app.database import get_database

blueprint = Blueprint("auth", __name__)
AuthMode = Literal["vulnerable", "secure"]
WEAK_LAB_SECRET = "lab-weak-secret"


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_token(user_id: int, username: str, role: str, mode: AuthMode) -> str:
    """Create a local JWT-shaped token for comparing validation behavior."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload: dict[str, Any] = {"sub": str(user_id), "username": username, "role": role}
    secret = WEAK_LAB_SECRET
    if mode == "secure":
        payload.update({"iat": now, "exp": now + 900, "iss": current_app.config["JWT_ISSUER"], "aud": current_app.config["JWT_AUDIENCE"]})
        secret = current_app.config["JWT_SECURE_SECRET"]
    signing_input = f"{b64url_encode(json.dumps(header, separators=(',', ':')).encode())}.{b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(signature)}"


def validate_token(token: str, mode: AuthMode) -> dict[str, Any]:
    """Validate a lab token; secure mode validates claims and fixed algorithm."""
    try:
        header_part, payload_part, signature_part = token.split(".")
        header = json.loads(b64url_decode(header_part))
        payload = json.loads(b64url_decode(payload_part))
        secret = WEAK_LAB_SECRET if mode == "vulnerable" else current_app.config["JWT_SECURE_SECRET"]
        expected = hmac.new(secret.encode(), f"{header_part}.{payload_part}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64url_decode(signature_part)):
            raise ValueError("Signature verification failed.")
        if mode == "secure":
            if header.get("alg") != "HS256":
                raise ValueError("Unexpected token algorithm.")
            if payload.get("exp", 0) < time.time():
                raise ValueError("Token has expired.")
            if payload.get("iss") != current_app.config["JWT_ISSUER"] or payload.get("aud") != current_app.config["JWT_AUDIENCE"]:
                raise ValueError("Issuer or audience is invalid.")
        # INTENTIONALLY VULNERABLE mode validates only a signature made with a
        # publicly documented weak secret and does not validate token claims.
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("Token is not accepted by this mode.") from error


def mode_from_request() -> AuthMode:
    return "secure" if request.values.get("mode") == "secure" else "vulnerable"


@blueprint.route("/login", methods=["GET", "POST"])
def login() -> str:
    mode = mode_from_request()
    token: str | None = None
    message: str | None = None
    if request.method == "POST":
        username = request.form.get("username", "")
        user = get_database().execute("SELECT id, username, role FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            message = "Unknown fake lab account."
        else:
            token = create_token(user["id"], user["username"], user["role"], mode)
            session["authenticated_user_id"] = user["id"]
            session["authenticated_username"] = user["username"]
            session["authenticated_mode"] = mode
            message = "A local demonstration token was issued."
    return render_template("login.html", mode=mode, token=token, message=message)


@blueprint.post("/token/inspect")
def inspect_token() -> str:
    mode = mode_from_request()
    token = request.form.get("token", "")
    try:
        claims = validate_token(token, mode)
        return render_template("login.html", mode=mode, token=token, message="Token accepted.", claims=claims)
    except ValueError as error:
        return render_template("login.html", mode=mode, token=token, message=str(error), claims=None), 400


@blueprint.post("/logout")
def logout() -> object:
    session.clear()
    return redirect(url_for("auth.login", mode="secure"))
