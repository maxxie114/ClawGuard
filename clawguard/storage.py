"""SQLite storage layer for ClawGuard skill."""

import json
import sqlite3
from pathlib import Path

from clawguard.models import EmailRecord, SanitizedEmailEvent

DB_PATH = Path("clawguard_emails.db")

_conn: sqlite3.Connection | None = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
    return _conn


def init_db() -> None:
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sanitized_emails (
            event_id TEXT PRIMARY KEY,
            provider TEXT,
            received_at TEXT,
            from_addr TEXT,
            to_addrs TEXT,
            subject TEXT,
            body TEXT,
            attachments TEXT,
            risk_flags TEXT,
            injection_detected INTEGER,
            truncated INTEGER
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_received_at ON sanitized_emails(received_at)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_injection ON sanitized_emails(injection_detected)
    """)
    conn.commit()


def store_event(event: SanitizedEmailEvent) -> bool:
    """Store a sanitized email event. Returns True if inserted, False if duplicate."""
    conn = _get_conn()
    cursor = conn.execute(
        """INSERT OR IGNORE INTO sanitized_emails
           (event_id, provider, received_at, from_addr, to_addrs,
            subject, body, attachments, risk_flags, injection_detected, truncated)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event.event_id,
            event.provider,
            event.received_at.isoformat(),
            event.from_addr,
            json.dumps(event.to_addrs),
            event.subject_sanitized,
            event.body_sanitized,
            json.dumps([a for a in event.attachments_sanitized]),
            json.dumps(event.risk.flags),
            int(event.risk.injection_detected),
            int(event.risk.truncated),
        ),
    )
    conn.commit()
    return cursor.rowcount > 0


def _row_to_record(row: sqlite3.Row) -> EmailRecord:
    return EmailRecord(
        event_id=row["event_id"],
        provider=row["provider"],
        received_at=row["received_at"],
        from_addr=row["from_addr"],
        to_addrs=json.loads(row["to_addrs"]),
        subject=row["subject"],
        body=row["body"],
        attachments=json.loads(row["attachments"]),
        risk_flags=json.loads(row["risk_flags"]),
        injection_detected=bool(row["injection_detected"]),
        truncated=bool(row["truncated"]),
    )


def get_recent_emails(limit: int = 10) -> list[EmailRecord]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM sanitized_emails ORDER BY received_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_record(r) for r in rows]


def get_risky_emails(limit: int = 10) -> list[EmailRecord]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM sanitized_emails WHERE injection_detected = 1 ORDER BY received_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_record(r) for r in rows]


def search_emails(query: str, limit: int = 10) -> list[EmailRecord]:
    conn = _get_conn()
    pattern = f"%{query}%"
    rows = conn.execute(
        "SELECT * FROM sanitized_emails WHERE subject LIKE ? OR body LIKE ? ORDER BY received_at DESC LIMIT ?",
        (pattern, pattern, limit),
    ).fetchall()
    return [_row_to_record(r) for r in rows]


def get_email_count() -> int:
    conn = _get_conn()
    return conn.execute("SELECT COUNT(*) FROM sanitized_emails").fetchone()[0]


def get_risky_count() -> int:
    conn = _get_conn()
    return conn.execute(
        "SELECT COUNT(*) FROM sanitized_emails WHERE injection_detected = 1"
    ).fetchone()[0]


def reset_db() -> None:
    """Drop and recreate tables. Used for testing."""
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None
    if DB_PATH.exists():
        DB_PATH.unlink()
