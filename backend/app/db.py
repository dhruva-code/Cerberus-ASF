"""
SQLite persistence layer for user accounts, sessions, per-user AI provider
credentials, and scan history. No ORM — the schema is small and stable
enough that stdlib sqlite3 keeps this simple and dependency-free.
"""

import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.environ.get(
    "CERBERUS_DB_PATH",
    os.path.join(os.path.dirname(__file__), "cerberus-asf.db"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS ai_credentials (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    base_url TEXT,
    model_name TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    package_name TEXT,
    app_name TEXT,
    file_name TEXT,
    security_score INTEGER,
    deep_scan_used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
"""


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)


# --- users ---

def create_user(username: str, password_hash: str) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        return cur.lastrowid


def get_user_by_username(username: str):
    with get_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id: int):
    with get_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


# --- sessions ---

def create_session(token: str, user_id: int):
    with get_connection() as conn:
        conn.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id))


def get_user_by_session_token(token: str):
    with get_connection() as conn:
        return conn.execute(
            """SELECT users.* FROM sessions
               JOIN users ON users.id = sessions.user_id
               WHERE sessions.token = ?""",
            (token,),
        ).fetchone()


def delete_session(token: str):
    with get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


# --- ai_credentials ---

def upsert_ai_credential(user_id: int, provider: str, api_key_encrypted: str, base_url: str, model_name: str):
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO ai_credentials (user_id, provider, api_key_encrypted, base_url, model_name, updated_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(user_id) DO UPDATE SET
                   provider = excluded.provider,
                   api_key_encrypted = excluded.api_key_encrypted,
                   base_url = excluded.base_url,
                   model_name = excluded.model_name,
                   updated_at = excluded.updated_at""",
            (user_id, provider, api_key_encrypted, base_url, model_name),
        )


def get_ai_credential(user_id: int):
    with get_connection() as conn:
        return conn.execute("SELECT * FROM ai_credentials WHERE user_id = ?", (user_id,)).fetchone()


# --- scans ---

def create_scan(user_id: int, package_name: str, app_name: str, file_name: str,
                 security_score, deep_scan_used: bool, result_json: str) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO scans (user_id, package_name, app_name, file_name, security_score, deep_scan_used, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, package_name, app_name, file_name, security_score, int(deep_scan_used), result_json),
        )
        return cur.lastrowid


def list_scans_for_user(user_id: int):
    with get_connection() as conn:
        return conn.execute(
            """SELECT id, package_name, app_name, file_name, security_score, deep_scan_used, created_at
               FROM scans WHERE user_id = ? ORDER BY created_at DESC""",
            (user_id,),
        ).fetchall()


def get_scan(scan_id: int):
    with get_connection() as conn:
        return conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
