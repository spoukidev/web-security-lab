"""Configuration values for local development and tests."""
import os
import secrets
from pathlib import Path


class Config:
    """Default local-only configuration; not a production template."""
    BASE_DIRECTORY = Path(__file__).resolve().parent.parent
    # Random defaults avoid shipping a reusable production secret. Set these
    # environment variables when a stable development session is needed.
    SECRET_KEY = os.environ.get("LAB_SESSION_SECRET", secrets.token_urlsafe(32))
    JWT_SECURE_SECRET = os.environ.get("LAB_JWT_SECRET", secrets.token_urlsafe(32))
    JWT_ISSUER = "web-security-lab"
    JWT_AUDIENCE = "web-security-lab-browser"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("LAB_HTTPS", "false").lower() == "true"
    DATABASE = BASE_DIRECTORY / "instance" / "web_security_lab.sqlite3"
    UPLOAD_DIRECTORY = BASE_DIRECTORY / "instance" / "uploads"
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
    TESTING = False
