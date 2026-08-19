"""Controlled file-upload validation lab; uploaded files are never executed."""
from __future__ import annotations
import secrets
from pathlib import Path
from typing import Literal
from flask import Blueprint, current_app, render_template, request, session
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from app.database import get_database

blueprint = Blueprint("upload", __name__)
UploadMode = Literal["vulnerable", "secure"]
ALLOWED_EXTENSIONS = {"txt", "png", "jpg", "jpeg"}
MAX_UPLOAD_BYTES = 1_048_576


def selected_mode() -> UploadMode:
    return "secure" if request.values.get("mode") == "secure" else "vulnerable"


def extension_of(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def validate_secure_upload(upload: FileStorage) -> tuple[str, bytes]:
    """Validate extension, declared MIME type, bytes, and magic signature."""
    extension = extension_of(upload.filename or "")
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Extension is not on the secure allowlist.")
    content = upload.read(MAX_UPLOAD_BYTES + 1)
    if not content:
        raise ValueError("The uploaded file is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("The file exceeds the 1 MiB lab limit.")
    expected_types = {"txt": {"text/plain"}, "png": {"image/png"}, "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"}}
    if upload.mimetype not in expected_types[extension]:
        raise ValueError("Declared MIME type does not match the extension.")
    if extension == "txt":
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Text uploads must be UTF-8 text.") from error
    else:
        is_expected_image = content.startswith(b"\x89PNG\r\n\x1a\n") if extension == "png" else content.startswith(b"\xff\xd8\xff")
        if not is_expected_image:
            raise ValueError("File signature does not match the claimed image type.")
    return extension, content


def save_local_upload(upload: FileStorage, mode: UploadMode, user_id: int) -> str:
    """Save a harmless lab file under a safe generated name outside static paths."""
    original_name = secure_filename(upload.filename or "upload")
    if not original_name:
        raise ValueError("The filename is invalid.")
    if mode == "vulnerable":
        # INTENTIONALLY VULNERABLE
        # This code exists only for the local Web Security Lab.
        # It trusts filename extension and supplied MIME type, not file bytes.
        extension = extension_of(original_name)
        if extension not in ALLOWED_EXTENSIONS or upload.mimetype not in {"text/plain", "image/png", "image/jpeg"}:
            raise ValueError("Vulnerable mode permits only harmless .txt, .png, and .jpg files.")
        content = upload.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            raise ValueError("The file exceeds the 1 MiB lab limit.")
        stored_name = original_name
    else:
        extension, content = validate_secure_upload(upload)
        stored_name = f"{secrets.token_urlsafe(18)}.{extension}"
    destination = Path(current_app.config["UPLOAD_DIRECTORY"]) / stored_name
    destination.write_bytes(content)
    destination.chmod(0o600)
    database = get_database()
    database.execute("INSERT INTO uploads (user_id, original_name, stored_name, content_type) VALUES (?, ?, ?, ?)", (user_id, original_name, stored_name, upload.mimetype))
    database.commit()
    return stored_name


@blueprint.route("/upload", methods=["GET", "POST"])
def upload() -> str:
    mode = selected_mode()
    user_id = session.get("authenticated_user_id", 1)
    message: str | None = None
    error_message: str | None = None
    if request.method == "POST":
        file = request.files.get("file")
        if file is None or not file.filename:
            error_message = "Choose a harmless test file first."
        else:
            try:
                stored_name = save_local_upload(file, mode, user_id)
                message = f"Saved outside static paths as {stored_name}."
            except ValueError as error:
                error_message = str(error)
    uploads = get_database().execute("SELECT original_name, stored_name, content_type, created_at FROM uploads ORDER BY id DESC LIMIT 8").fetchall()
    return render_template("upload.html", mode=mode, message=message, error_message=error_message, uploads=uploads)
