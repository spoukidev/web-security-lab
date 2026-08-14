from __future__ import annotations


def test_application_starts(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert b"WEB SECURITY LAB" in response.data
    assert b"Phase 2 active" in response.data
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
