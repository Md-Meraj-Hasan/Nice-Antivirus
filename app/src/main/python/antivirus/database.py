"""SQLite storage for malware signatures and scan history."""
from __future__ import annotations

import sqlite3
from pathlib import Path


def connect(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.execute("""
        CREATE TABLE IF NOT EXISTS signatures (
            sha256 TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            source_version INTEGER NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            sha256 TEXT,
            status TEXT NOT NULL,
            scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    connection.commit()
    return connection


def load_signatures(connection: sqlite3.Connection) -> dict[str, dict]:
    rows = connection.execute(
        "SELECT sha256, label, severity, description FROM signatures"
    ).fetchall()
    return {
        row[0]: {"label": row[1], "severity": row[2], "description": row[3]}
        for row in rows
    }


def record_scan(connection: sqlite3.Connection, path: str, sha256: str | None, status: str) -> None:
    connection.execute(
        "INSERT INTO scan_history (path, sha256, status) VALUES (?, ?, ?)",
        (str(path), sha256, str(status)),
    )
    connection.commit()


def recent_scans(connection: sqlite3.Connection, limit: int = 50) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    rows = connection.execute(
        "SELECT path, sha256, status, scanned_at FROM scan_history "
        "ORDER BY id DESC LIMIT ?",
        (safe_limit,),
    ).fetchall()
    return [
        {"path": row[0], "sha256": row[1], "status": row[2], "scanned_at": row[3]}
        for row in rows
    ]


def clear_scan_history(connection: sqlite3.Connection) -> int:
    """Delete scan-history rows only; preserve signatures and metadata."""
    cursor = connection.execute("DELETE FROM scan_history")
    connection.commit()
    return cursor.rowcount
