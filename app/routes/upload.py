"""Controlled file-upload validation lab; uploaded files are never executed."""
from __future__ import annotations
import secrets
import zlib
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


def validate_png_structure(content: bytes) -> None:
    """Reject truncated or structurally invalid PNG files without external dependencies."""
    signature = b"\x89PNG\r\n\x1a\n"
    if not content.startswith(signature):
        raise ValueError("File signature does not match the claimed image type.")

    offset = len(signature)
    chunk_index = 0
    saw_idat = False
    while offset < len(content):
        if len(content) - offset < 12:
            raise ValueError("PNG structure is truncated.")

        length = int.from_bytes(content[offset:offset + 4], "big")
        chunk_type = content[offset + 4:offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(content):
            raise ValueError("PNG structure is truncated.")

        chunk_data = content[data_start:data_end]
        stored_crc = int.from_bytes(content[data_end:crc_end], "big")
        computed_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        if stored_crc != computed_crc:
            raise ValueError("PNG chunk checksum is invalid.")

        if chunk_index == 0 and (chunk_type != b"IHDR" or length != 13):
            raise ValueError("PNG must begin with a valid IHDR chunk.")
        if chunk_type == b"IDAT":
            saw_idat = True
        if chunk_type == b"IEND":
            if length != 0 or not saw_idat or crc_end != len(content):
                raise ValueError("PNG must end with a valid IEND chunk after image data.")
            return

        chunk_index += 1
        offset = crc_end

    raise ValueError("PNG is missing its IEND chunk.")


def validate_jpeg_structure(content: bytes) -> None:
    """Reject truncated JPEG containers while tolerating normal entropy-coded data."""
    if not content.startswith(b"\xff\xd8"):
        raise ValueError("File signature does not match the claimed image type.")

    offset = 2
    saw_frame = False
    while offset < len(content):
        if content[offset] != 0xFF:
            raise ValueError("JPEG marker structure is invalid.")
        while offset < len(content) and content[offset] == 0xFF:
            offset += 1
        if offset >= len(content):
            raise ValueError("JPEG structure is truncated.")

        marker = content[offset]
        offset += 1
        if marker == 0xD9:
            if not saw_frame or offset != len(content):
                raise ValueError("JPEG end marker is invalid.")
            return
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if offset + 2 > len(content):
            raise ValueError("JPEG structure is truncated.")

        segment_length = int.from_bytes(content[offset:offset + 2], "big")
        if segment_length < 2 or offset + segment_length > len(content):
            raise ValueError("JPEG segment length is invalid.")

        if marker in {*range(0xC0, 0xC4), *range(0xC5, 0xC8), *range(0xC9, 0xCC), *range(0xCD, 0xD0)}:
            saw_frame = True

        if marker == 0xDA:
            if not saw_frame:
                raise ValueError("JPEG scan appears before a frame header.")
            scan_offset = offset + segment_length
            while scan_offset < len(content) - 1:
                if content[scan_offset] != 0xFF:
                    scan_offset += 1
                    continue
                next_byte = content[scan_offset + 1]
                if next_byte == 0x00 or 0xD0 <= next_byte <= 0xD7:
                    scan_offset += 2
                    continue
                if next_byte == 0xD9:
                    if scan_offset + 2 != len(content):
                        raise ValueError("JPEG contains trailing data after the end marker.")
                    return
                raise ValueError("JPEG scan data contains an unexpected marker.")
            raise ValueError("JPEG is missing its end marker.")

        offset += segment_length

    raise ValueError("JPEG is missing its end marker.")


def validate_secure_upload(upload: FileStorage) -> tuple[str, bytes]:
    """Validate extension, declared MIME type, bytes, and image container structure."""
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
    elif extension == "png":
        validate_png_structure(content)
    else:
        validate_jpeg_structure(content)
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
