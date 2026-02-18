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
                CREATE INDEX IF NOT EXISTS idx_to_addr ON sanitized_events(to_addr);
            """)
            # Migrate existing DBs that don't have to_addr yet
            try:
                conn.execute("ALTER TABLE sanitized_events ADD COLUMN to_addr TEXT NOT NULL DEFAULT ''")
            except Exception:
                pass  # Column already exists

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def store_event(self, event: SanitizedEmailEvent, raw_masked: str | None = None) -> None:
        """Store a sanitized event."""
        to_addr = event.to_addrs[0] if event.to_addrs else ""
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO sanitized_events
                   (event_id, provider, received_at, from_addr, to_addr, subject_sanitized,
                    body_sanitized, risk_flags, injection_detected, truncated,
                    risk_score, raw_payload_masked, sanitized_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
