"""Explicit PostgreSQL locks; SQLite already holds BEGIN IMMEDIATE."""

import sqlite3

from .connection import Connection


def lock_key(db: Connection, key: str) -> None:
    if not isinstance(db, sqlite3.Connection):
        db.execute("SELECT pg_advisory_xact_lock(hashtextextended(?::text, 0))", (key,))


def locked(db: Connection, sql: str) -> str:
    return sql + ("" if isinstance(db, sqlite3.Connection) else " FOR UPDATE")
