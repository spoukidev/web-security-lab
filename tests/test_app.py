from __future__ import annotations


def test_application_starts(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert b"WEB SECURITY LAB" in response.data
    assert b"Phase 1 foundation" in response.data


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
