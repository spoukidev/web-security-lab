"""SQLite helpers and deterministic fake seed data."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from flask import Flask, current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, role TEXT NOT NULL DEFAULT 'student');
CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE, display_name TEXT NOT NULL, bio TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users (id));
CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id));
CREATE TABLE IF NOT EXISTS uploads (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, original_name TEXT NOT NULL, stored_name TEXT NOT NULL, content_type TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id));
"""
SEED_USERS = ((1, "alice", "alice@example.test", "student"), (2, "bob", "bob@example.test", "student"), (3, "carol", "carol@example.test", "instructor"))
SEED_PROFILES = ((1, 1, "Alice Analyst", "Fake student profile used only in this lab."), (2, 2, "Bob Blue Team", "Fake student profile used only in this lab."), (3, 3, "Carol Coach", "Fake instructor profile used only in this lab."))


def get_database() -> sqlite3.Connection:
    if "database" not in g:
        path = Path(current_app.config["DATABASE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        g.database = connection
    return g.database


def close_database(_: BaseException | None = None) -> None:
    connection = g.pop("database", None)
    if connection is not None:
        connection.close()


def initialize_database() -> None:
    """Create schema and seed fake data exactly once."""
    database = get_database()
    database.executescript(SCHEMA)
    if database.execute("SELECT id FROM users LIMIT 1").fetchone() is None:
        database.executemany("INSERT INTO users (id, username, email, role) VALUES (?, ?, ?, ?)", SEED_USERS)
        database.executemany("INSERT INTO profiles (id, user_id, display_name, bio) VALUES (?, ?, ?, ?)", SEED_PROFILES)
    database.commit()


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_database)

    @app.cli.command("init-db")
    def init_db_command() -> None:
        initialize_database()
        print("Initialized the local Web Security Lab database.")
