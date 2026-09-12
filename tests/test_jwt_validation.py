from __future__ import annotations

import base64
import hashlib
import hmac

import pytest


def test_secure_inspect_rejects_invalid_base64_without_server_error(client) -> None:
    response = client.post(
        "/token/inspect",
        data={"mode": "secure", "token": "%%%.e30.invalid"},
    )

    assert response.status_code == 400
    assert b"Token is not accepted by this mode." in response.data


def test_validator_rejects_non_object_json_payload(app) -> None:
    from app.routes.auth import b64url_encode, validate_token

    header = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = b64url_encode(b"[]")
    signing_input = f"{header}.{payload}"
    secret = app.config["JWT_SECURE_SECRET"]
    signature = b64url_encode(
        hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    )
    token = f"{signing_input}.{signature}"

    with app.app_context(), pytest.raises(ValueError, match="Token is not accepted"):
        validate_token(token, "secure")


def test_strict_base64url_decoder_rejects_invalid_characters() -> None:
    from app.routes.auth import b64url_decode

    with pytest.raises(ValueError):
        try:
            b64url_decode("%%%")
        except Exception as error:
            raise ValueError("invalid base64url") from error
