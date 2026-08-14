from __future__ import annotations
from pathlib import Path
import pytest
from app import create_app


@pytest.fixture()
def app(tmp_path: Path):
    application = create_app({"TESTING": True, "DATABASE": tmp_path / "lab.sqlite3", "UPLOAD_DIRECTORY": tmp_path / "uploads", "SECRET_KEY": "test-key"})
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()
