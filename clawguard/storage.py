"""SQLite storage layer for ClawGuard events."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator

from .models import DashboardStats, SanitizedEmailEvent

DEFAULT_DB_PATH = Path("clawguard.db")


class UserStore:
    """SQLite-backed storage for users, API keys, and Gmail accounts."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    key_hash TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    prefix TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    last_used_at TEXT,
                    is_revoked INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS user_gmail_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    gmail_email TEXT NOT NULL DEFAULT '',
                    token_json_encrypted TEXT NOT NULL,
                    connected_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
                CREATE INDEX IF NOT EXISTS idx_gmail_user ON user_gmail_accounts(user_id);
            """)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # --- User management ---

    def create_user(self, email: str, password_hash: str, display_name: str = "", role: str = "user") -> dict | None:
        """Create a user. Returns the user dict or None if email exists."""
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO users (email, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
                    (email, password_hash, display_name, role),
                )
                row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                return dict(row) if row else None
        except sqlite3.IntegrityError:
            return None

    def get_user_by_email(self, email: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, email, display_name, role, created_at FROM users ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_user(self, user_id: int) -> bool:
        with self._conn() as conn:
            cursor = conn.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
            return cursor.rowcount > 0

    def update_user_password(self, user_id: int, password_hash: str) -> bool:
        with self._conn() as conn:
            cursor = conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
            return cursor.rowcount > 0

    # --- API key management ---

    def create_api_key(self, user_id: int, key_hash: str, name: str, prefix: str) -> dict:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO api_keys (user_id, key_hash, name, prefix) VALUES (?, ?, ?, ?)",
                (user_id, key_hash, name, prefix),
            )
            row = conn.execute(
                "SELECT id, user_id, name, prefix, created_at, last_used_at, is_revoked FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            return dict(row)

    def get_user_by_api_key_hash(self, key_hash: str) -> dict | None:
        """Look up user by API key hash. Also updates last_used_at."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT u.* FROM users u
                   JOIN api_keys k ON k.user_id = u.id
                   WHERE k.key_hash = ? AND k.is_revoked = 0""",
                (key_hash,),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE api_keys SET last_used_at = datetime('now') WHERE key_hash = ?",
                    (key_hash,),
                )
                return dict(row)
            return None

    def list_api_keys(self, user_id: int) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, name, prefix, created_at, last_used_at, is_revoked FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def revoke_api_key(self, key_id: int, user_id: int) -> bool:
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET is_revoked = 1 WHERE id = ? AND user_id = ?",
                (key_id, user_id),
            )
            return cursor.rowcount > 0

    # --- Gmail account management ---

    def store_gmail_account(self, user_id: int, gmail_email: str, token_json_encrypted: str) -> dict:
        """Store or update a Gmail account for a user."""
        with self._conn() as conn:
            # Upsert: if user already connected this gmail, update the token
            existing = conn.execute(
                "SELECT id FROM user_gmail_accounts WHERE user_id = ? AND gmail_email = ?",
                (user_id, gmail_email),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE user_gmail_accounts SET token_json_encrypted = ?, connected_at = datetime('now') WHERE id = ?",
                    (token_json_encrypted, existing["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO user_gmail_accounts (user_id, gmail_email, token_json_encrypted) VALUES (?, ?, ?)",
                    (user_id, gmail_email, token_json_encrypted),
                )
            row = conn.execute(
                "SELECT * FROM user_gmail_accounts WHERE user_id = ? AND gmail_email = ?",
                (user_id, gmail_email),
            ).fetchone()
            return dict(row)

    def list_gmail_accounts(self, user_id: int) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, user_id, gmail_email, connected_at FROM user_gmail_accounts WHERE user_id = ?",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_gmail_token(self, user_id: int, gmail_email: str) -> str | None:
        """Get encrypted token for a specific Gmail account."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT token_json_encrypted FROM user_gmail_accounts WHERE user_id = ? AND gmail_email = ?",
                (user_id, gmail_email),
            ).fetchone()
            return row["token_json_encrypted"] if row else None

    def get_all_gmail_tokens(self) -> list[dict]:
        """Get all Gmail accounts (for admin). Returns id, user_id, gmail_email, token_json_encrypted."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM user_gmail_accounts").fetchall()
            return [dict(r) for r in rows]

    def delete_gmail_account(self, account_id: int, user_id: int) -> bool:
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM user_gmail_accounts WHERE id = ? AND user_id = ?",
                (account_id, user_id),
            )
            return cursor.rowcount > 0


class EventStore:
    """SQLite-backed storage for sanitized email events."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sanitized_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    provider TEXT NOT NULL DEFAULT 'generic',
                    received_at TEXT NOT NULL,
                    from_addr TEXT NOT NULL DEFAULT '',
                    to_addr TEXT NOT NULL DEFAULT '',
                    subject_sanitized TEXT NOT NULL DEFAULT '',
                    body_sanitized TEXT NOT NULL DEFAULT '',
                    risk_flags TEXT NOT NULL DEFAULT '[]',
                    injection_detected INTEGER NOT NULL DEFAULT 0,
                    truncated INTEGER NOT NULL DEFAULT 0,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    raw_payload_masked TEXT,
                    sanitized_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_received_at ON sanitized_events(received_at);
                CREATE INDEX IF NOT EXISTS idx_injection ON sanitized_events(injection_detected);
                CREATE INDEX IF NOT EXISTS idx_risk_score ON sanitized_events(risk_score);
            """)
            # Migrate existing DBs: add columns if missing
            for col, defn in [
                ("to_addr", "TEXT NOT NULL DEFAULT ''"),
                ("user_id", "INTEGER"),
            ]:
                try:
                    conn.execute(f"ALTER TABLE sanitized_events ADD COLUMN {col} {defn}")
                except Exception:
                    pass
            try:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_to_addr ON sanitized_events(to_addr)")
            except Exception:
                pass
            try:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON sanitized_events(user_id)")
            except Exception:
                pass

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def store_event(self, event: SanitizedEmailEvent, raw_masked: str | None = None, user_id: int | None = None) -> None:
        """Store a sanitized event."""
        to_addr = event.to_addrs[0] if event.to_addrs else ""
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO sanitized_events
                   (event_id, provider, received_at, from_addr, to_addr, subject_sanitized,
                    body_sanitized, risk_flags, injection_detected, truncated,
                    risk_score, raw_payload_masked, sanitized_json, user_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id,
                    event.provider,
                    event.received_at.isoformat() if event.received_at else datetime.utcnow().isoformat(),
                    event.from_addr,
                    to_addr,
                    event.subject_sanitized,
                    event.body_sanitized,
                    json.dumps([f.value for f in event.risk.flags]),
                    int(event.risk.injection_detected),
                    int(event.risk.truncated),
                    event.risk.risk_score,
                    raw_masked,
                    event.model_dump_json(),
                    user_id,
                ),
            )

    def get_event(self, event_id: str) -> dict | None:
        """Get a single event by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sanitized_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row:
                return dict(row)
        return None

    def list_events(self, limit: int = 50, offset: int = 0, from_addr: str | None = None, to_addr: str | None = None) -> list[dict]:
        """List events ordered by received_at descending, optionally filtered by sender or recipient account."""
        conditions = []
        params: list = []
        if from_addr:
            conditions.append("from_addr LIKE ?")
            params.append(f"%{from_addr}%")
        if to_addr:
            conditions.append("to_addr LIKE ?")
            params.append(f"%{to_addr}%")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM sanitized_events {where} ORDER BY received_at DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    def list_senders(self, to_addr: str | None = None) -> list[dict]:
        """List unique senders with email counts, optionally scoped to one account."""
        where = "WHERE to_addr LIKE ?" if to_addr else ""
        params = [f"%{to_addr}%"] if to_addr else []
        with self._conn() as conn:
            rows = conn.execute(
                f"""SELECT from_addr,
                          COUNT(*) as total,
                          SUM(CASE WHEN injection_detected = 1 THEN 1 ELSE 0 END) as injections,
                          MAX(received_at) as last_seen
                   FROM sanitized_events {where}
                   GROUP BY from_addr
                   ORDER BY total DESC""",
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    def list_accounts(self) -> list[dict]:
        """List distinct recipient accounts (inboxes) connected to this server."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT to_addr,
                          COUNT(*) as total,
                          SUM(CASE WHEN injection_detected = 1 THEN 1 ELSE 0 END) as injections,
                          MAX(received_at) as last_seen
                   FROM sanitized_events
                   WHERE to_addr != ''
                   GROUP BY to_addr
                   ORDER BY total DESC"""
            ).fetchall()
            return [dict(r) for r in rows]

    def list_risky_events(self, min_score: int = 1, limit: int = 50) -> list[dict]:
        """List events with risk score >= min_score."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM sanitized_events WHERE risk_score >= ? ORDER BY risk_score DESC LIMIT ?",
                (min_score, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> DashboardStats:
        """Get dashboard statistics."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM sanitized_events").fetchone()[0]
            risky = conn.execute(
                "SELECT COUNT(*) FROM sanitized_events WHERE risk_score > 0"
            ).fetchone()[0]
            injections = conn.execute(
                "SELECT COUNT(*) FROM sanitized_events WHERE injection_detected = 1"
            ).fetchone()[0]

            # Count blocked attachments from sanitized_json
            blocked = 0
            rows = conn.execute(
                "SELECT sanitized_json FROM sanitized_events"
            ).fetchall()
            for row in rows:
                try:
                    data = json.loads(row[0])
                    for att in data.get("attachments_sanitized", []):
                        if not att.get("allowed", True):
                            blocked += 1
                except (json.JSONDecodeError, TypeError):
                    pass

            avg_score_row = conn.execute(
                "SELECT AVG(risk_score) FROM sanitized_events"
            ).fetchone()
            avg_score = avg_score_row[0] if avg_score_row[0] is not None else 0.0

            today = datetime.utcnow().date().isoformat()
            today_count = conn.execute(
                "SELECT COUNT(*) FROM sanitized_events WHERE received_at >= ?",
                (today,),
            ).fetchone()[0]

            return DashboardStats(
                total_processed=total,
                risky_count=risky,
                injection_count=injections,
                attachments_blocked=blocked,
                avg_risk_score=round(avg_score, 1),
                events_today=today_count,
            )

    def get_timeline(self, days: int = 7) -> list[dict]:
        """Get event counts per day for the timeline graph."""
        with self._conn() as conn:
            since = (datetime.utcnow() - timedelta(days=days)).isoformat()
            rows = conn.execute(
                """SELECT DATE(received_at) as day,
                          COUNT(*) as total,
                          SUM(CASE WHEN injection_detected = 1 THEN 1 ELSE 0 END) as injections,
                          SUM(CASE WHEN risk_score > 0 THEN 1 ELSE 0 END) as risky
                   FROM sanitized_events
                   WHERE received_at >= ?
                   GROUP BY DATE(received_at)
                   ORDER BY day""",
                (since,),
            ).fetchall()
            return [dict(r) for r in rows]
