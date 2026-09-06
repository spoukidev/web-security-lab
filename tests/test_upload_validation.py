from __future__ import annotations

import io
import zlib

from werkzeug.datastructures import FileStorage

from app.routes.upload import validate_secure_upload


def png_chunk(chunk_type: bytes, data: bytes = b"") -> bytes:
    checksum = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return len(data).to_bytes(4, "big") + chunk_type + data + checksum.to_bytes(4, "big")


def minimal_structural_png() -> bytes:
    ihdr = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    return b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr) + png_chunk(b"IDAT") + png_chunk(b"IEND")


def test_secure_upload_rejects_png_that_only_has_magic_bytes() -> None:
    upload = FileStorage(stream=io.BytesIO(b"\x89PNG\r\n\x1a\nnot-a-container"), filename="image.png", content_type="image/png")

    try:
        validate_secure_upload(upload)
    except ValueError as error:
        assert "PNG" in str(error)
    else:
        raise AssertionError("secure validation accepted a malformed PNG container")


def test_secure_upload_rejects_jpeg_that_only_has_magic_bytes() -> None:
    upload = FileStorage(stream=io.BytesIO(b"\xff\xd8\xffgarbage"), filename="image.jpg", content_type="image/jpeg")

    try:
        validate_secure_upload(upload)
    except ValueError as error:
        assert "JPEG" in str(error)
    else:
        raise AssertionError("secure validation accepted a malformed JPEG container")


def test_secure_upload_accepts_structurally_complete_png() -> None:
    upload = FileStorage(stream=io.BytesIO(minimal_structural_png()), filename="image.png", content_type="image/png")

    extension, content = validate_secure_upload(upload)

    assert extension == "png"
    assert content.endswith(png_chunk(b"IEND"))
