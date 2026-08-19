from __future__ import annotations


def test_application_starts(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert b"WEB SECURITY LAB" in response.data
    assert b"All core labs active" in response.data
    assert b'href="/search"' in response.data


def test_health_endpoint_is_available(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"scope": "local-web-security-lab", "status": "ok"}


def test_database_has_deterministic_fake_users(app) -> None:
    with app.app_context():
        from app.database import get_database
        rows = get_database().execute("SELECT username FROM users ORDER BY id").fetchall()
    assert [row["username"] for row in rows] == ["alice", "bob", "carol"]


def test_planned_lab_is_not_vulnerable_yet(client) -> None:
    response = client.get("/labs/sql-injection")
    assert response.status_code == 200
    assert b"no exploitable behavior" in response.data


def test_vulnerable_search_returns_matching_fake_user(client) -> None:
    response = client.get("/search?q=alice&mode=vulnerable")
    assert response.status_code == 200
    assert b"1 fake user returned" in response.data
    assert b"alice@example.test" in response.data


def test_boolean_injection_changes_vulnerable_search_result(client) -> None:
    response = client.get(
        "/search", query_string={"q": "' OR '1'='1' -- ", "mode": "vulnerable"}
    )
    assert response.status_code == 200
    assert b"3 fake users returned" in response.data


def test_boolean_injection_is_literal_in_secure_search(client) -> None:
    response = client.get(
        "/search", query_string={"q": "' OR '1'='1' -- ", "mode": "secure"}
    )
    assert response.status_code == 200
    assert b"0 fake users returned" in response.data
    assert b"WHERE username LIKE ?" in response.data


def test_reflected_xss_is_rendered_in_vulnerable_mode(client) -> None:
    payload = '<script>alert("XSS demonstration")</script>'
    response = client.get("/comments", query_string={"preview": payload, "mode": "vulnerable"})
    assert response.status_code == 200
    assert payload.encode() in response.data
    assert "Content-Security-Policy" not in response.headers


def test_reflected_xss_is_encoded_and_has_csp_in_secure_mode(client) -> None:
    payload = '<script>alert("XSS demonstration")</script>'
    response = client.get("/comments", query_string={"preview": payload, "mode": "secure"})
    assert response.status_code == 200
    assert b"&lt;script&gt;alert" in response.data
    assert payload.encode() not in response.data
    assert response.headers["Content-Security-Policy"] == "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"


def test_stored_xss_is_encoded_in_secure_mode(client) -> None:
    payload = '<script>alert("XSS demonstration")</script>'
    response = client.post("/comments", data={"body": payload, "mode": "vulnerable"})
    assert response.status_code == 302

    vulnerable = client.get("/comments?mode=vulnerable")
    secure = client.get("/comments?mode=secure")
    assert payload.encode() in vulnerable.data
    assert b"&lt;script&gt;alert" in secure.data


def select_fake_actor(client, actor_id: int, target_id: int, mode: str) -> None:
    response = client.post(
        "/lab/select-actor",
        data={"actor_id": actor_id, "target_id": target_id, "mode": mode},
    )
    assert response.status_code == 302


def test_idor_vulnerable_mode_discloses_another_fake_profile(client) -> None:
    select_fake_actor(client, actor_id=1, target_id=1, mode="vulnerable")
    response = client.get("/profile/2?mode=vulnerable")
    assert response.status_code == 200
    assert b"Bob Blue Team" in response.data
    assert b"bob@example.test" in response.data


def test_idor_secure_mode_denies_another_fake_profile(client) -> None:
    select_fake_actor(client, actor_id=1, target_id=1, mode="secure")
    response = client.get("/profile/2?mode=secure")
    assert response.status_code == 403
    assert b"Access denied (403)" in response.data
    assert b"Bob Blue Team" not in response.data
    assert b"bob@example.test" not in response.data


def test_idor_secure_mode_allows_owned_fake_profile(client) -> None:
    select_fake_actor(client, actor_id=2, target_id=2, mode="secure")
    response = client.get("/profile/2?mode=secure")
    assert response.status_code == 200
    assert b"Bob Blue Team" in response.data


def test_ssrf_vulnerable_mode_rejects_non_lab_destinations(client) -> None:
    response = client.get(
        "/fetch", query_string={"mode": "vulnerable", "url": "https://example.com"}
    )
    assert response.status_code == 200
    assert b"limited to the controlled lab service" in response.data


def test_ssrf_secure_mode_rejects_internal_mock_before_fetch(client) -> None:
    response = client.get(
        "/fetch", query_string={"mode": "secure", "url": "http://internal-service:8000/"}
    )
    assert response.status_code == 200
    assert b"Secure mode permits HTTPS only" in response.data


def test_ssrf_secure_mode_rejects_unallowlisted_hostname(client) -> None:
    response = client.get(
        "/fetch", query_string={"mode": "secure", "url": "https://example.com"}
    )
    assert response.status_code == 200
    assert b"not on the secure public allowlist" in response.data


def test_ssrf_lab_target_validation_is_strict() -> None:
    from app.routes.fetch import is_controlled_lab_target

    assert is_controlled_lab_target("http://internal-service:8000/")
    assert not is_controlled_lab_target("http://internal-service:8080/")
    assert not is_controlled_lab_target("file:///etc/passwd")


def test_jwt_vulnerable_token_is_accepted_in_vulnerable_mode(app) -> None:
    from app.routes.auth import create_token, validate_token
    with app.app_context():
        token = create_token(1, "alice", "student", "vulnerable")
        claims = validate_token(token, "vulnerable")
    assert claims["username"] == "alice"


def test_jwt_secure_token_requires_secure_validation(app) -> None:
    from app.routes.auth import create_token, validate_token
    with app.app_context():
        token = create_token(1, "alice", "student", "secure")
        claims = validate_token(token, "secure")
    assert claims["iss"] == "web-security-lab"
    assert claims["aud"] == "web-security-lab-browser"


def test_jwt_secure_mode_rejects_vulnerable_token(app) -> None:
    import pytest
    from app.routes.auth import create_token, validate_token
    with app.app_context():
        token = create_token(1, "alice", "student", "vulnerable")
        with pytest.raises(ValueError):
            validate_token(token, "secure")


def test_vulnerable_upload_trusts_harmless_filename_and_mime(client) -> None:
    import io
    response = client.post("/upload", data={"mode": "vulnerable", "file": (io.BytesIO(b"not a png"), "notes.png", "image/png")}, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"Saved outside static paths" in response.data


def test_secure_upload_rejects_mismatched_file_signature(client) -> None:
    import io
    response = client.post("/upload", data={"mode": "secure", "file": (io.BytesIO(b"not a png"), "notes.png", "image/png")}, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"signature does not match" in response.data


def test_secure_upload_accepts_utf8_text_with_generated_name(client) -> None:
    import io
    response = client.post("/upload", data={"mode": "secure", "file": (io.BytesIO(b"harmless local test"), "notes.txt", "text/plain")}, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"Saved outside static paths as" in response.data
    assert b"notes.txt" in response.data


def login_fake_user(client, mode: str = "secure") -> None:
    response = client.post("/login", data={"username": "alice", "mode": mode})
    assert response.status_code == 200


def test_csrf_vulnerable_mode_changes_fake_email_without_token(client) -> None:
    login_fake_user(client)
    response = client.post("/change-email?mode=vulnerable", data={"email": "csrf-vulnerable@example.test"})
    assert response.status_code == 200
    assert b"fake local email address was changed" in response.data


def test_csrf_secure_mode_rejects_missing_token(client) -> None:
    login_fake_user(client)
    response = client.post("/change-email?mode=secure", data={"email": "csrf-secure@example.test"}, headers={"Origin": "http://localhost"})
    assert response.status_code == 200
    assert b"CSRF token or request origin is invalid" in response.data


def test_csrf_secure_mode_accepts_valid_token_and_origin(client) -> None:
    login_fake_user(client)
    form = client.get("/change-email?mode=secure")
    with client.session_transaction() as session_data:
        token = session_data["csrf_token"]
    response = client.post("/change-email?mode=secure", data={"email": "csrf-secure@example.test", "csrf_token": token}, headers={"Origin": "http://localhost"})
    assert form.status_code == 200
    assert response.status_code == 200
    assert b"fake local email address was changed" in response.data
