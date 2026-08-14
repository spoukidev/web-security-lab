"""Configuration values for local development and tests."""
from pathlib import Path


class Config:
    """Default local-only configuration; not a production template."""
    BASE_DIRECTORY = Path(__file__).resolve().parent.parent
    SECRET_KEY = "phase-1-local-lab-key-not-for-production"
    DATABASE = BASE_DIRECTORY / "instance" / "web_security_lab.sqlite3"
    UPLOAD_DIRECTORY = BASE_DIRECTORY / "instance" / "uploads"
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
    TESTING = False
