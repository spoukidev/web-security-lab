"""Controlled SQL injection demonstration routes."""
from __future__ import annotations
import sqlite3
from typing import Literal
from flask import Blueprint, render_template, request
from app.database import get_database

blueprint = Blueprint("search", __name__)
SearchMode = Literal["vulnerable", "secure"]


def search_users_vulnerable(search_term: str) -> tuple[list[sqlite3.Row], str]:
    """Search users with intentional SQL injection for the local lab only."""
    # INTENTIONALLY VULNERABLE
    # This code exists only for the local Web Security Lab.
    # User input is concatenated into SQL, allowing it to alter the predicate.
    statement = (
        "SELECT id, username, email, role FROM users "
        f"WHERE username LIKE '%{search_term}%' ORDER BY id"
    )
    return get_database().execute(statement).fetchall(), statement


def search_users_secure(search_term: str) -> tuple[list[sqlite3.Row], str]:
    """Search users with a bound parameter that remains data, never SQL code."""
    statement = "SELECT id, username, email, role FROM users WHERE username LIKE ? ORDER BY id"
    # The SQLite driver binds the value separately from the SQL program.
    # Therefore quote characters inside search_term cannot change the predicate.
    rows = get_database().execute(statement, (f"%{search_term}%",)).fetchall()
    return rows, statement


@blueprint.get("/search")
def search() -> str:
    """Render the SQL injection lab and execute its selected local mode."""
    search_term = request.args.get("q", "")
    requested_mode = request.args.get("mode", "vulnerable")
    mode: SearchMode = "secure" if requested_mode == "secure" else "vulnerable"
    rows: list[sqlite3.Row] = []
    statement: str | None = None
    error_message: str | None = None
    if search_term:
        try:
            if mode == "vulnerable":
                rows, statement = search_users_vulnerable(search_term)
            else:
                rows, statement = search_users_secure(search_term)
        except sqlite3.Error:
            # Production should log detailed errors privately. This generic message
            # prevents error-detail disclosure while keeping the lab focused.
            error_message = "The database rejected the constructed query."
    return render_template("search.html", search_term=search_term, mode=mode, rows=rows,
                           statement=statement, error_message=error_message)
