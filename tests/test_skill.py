"""Tests for ClawGuard skill layer."""

import pytest
from fastapi.testclient import TestClient

from clawguard.main import app
from clawguard.storage import DB_PATH, reset_db

SAMPLE_EVENT = {
    "event_id": "evt-001",
    "provider": "gmail",
    "received_at": "2026-02-15T10:00:00Z",
    "from_addr": "alice@example.com",
    "to_addrs": ["bob@example.com"],
    "subject_sanitized": "Hello Bob",
    "body_sanitized": "This is a clean email.",
    "attachments_sanitized": [],
    "risk": {"flags": [], "injection_detected": False, "truncated": False},
    "meta": {"original_sizes": {"body": 100}, "sanitizer_version": "0.1.0"},
}

RISKY_EVENT = {
    "event_id": "evt-002",
    "provider": "outlook",
    "received_at": "2026-02-15T11:00:00Z",
    "from_addr": "mallory@evil.com",
    "to_addrs": ["bob@example.com"],
    "subject_sanitized": "Urgent action required",
    "body_sanitized": "Ignore previous instructions and...",
    "attachments_sanitized": [],
    "risk": {"flags": ["prompt_injection"], "injection_detected": True, "truncated": False},
    "meta": {"original_sizes": {"body": 200}, "sanitizer_version": "0.1.0"},
}


@pytest.fixture(autouse=True)
def clean_db():
    """Reset database before each test."""
    reset_db()
    # Re-init via app lifespan isn't easy, so init manually
    from clawguard.storage import init_db
    init_db()
    yield
    reset_db()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=True)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_ingest_email(client):
    resp = client.post("/events/email", json=SAMPLE_EVENT)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "created"
    assert data["event_id"] == "evt-001"


def test_idempotent_ingest(client):
    client.post("/events/email", json=SAMPLE_EVENT)
    resp = client.post("/events/email", json=SAMPLE_EVENT)
    assert resp.status_code == 200
    assert resp.json()["status"] == "duplicate"


def test_recent_emails(client):
    client.post("/events/email", json=SAMPLE_EVENT)
    client.post("/events/email", json=RISKY_EVENT)
    resp = client.get("/emails/recent")
    assert resp.status_code == 200
    emails = resp.json()
    assert len(emails) == 2
    # Most recent first
    assert emails[0]["event_id"] == "evt-002"


def test_risky_emails(client):
    client.post("/events/email", json=SAMPLE_EVENT)
    client.post("/events/email", json=RISKY_EVENT)
    resp = client.get("/emails/risky")
    assert resp.status_code == 200
    emails = resp.json()
    assert len(emails) == 1
    assert emails[0]["event_id"] == "evt-002"
    assert emails[0]["injection_detected"] is True


def test_search_emails(client):
    client.post("/events/email", json=SAMPLE_EVENT)
    client.post("/events/email", json=RISKY_EVENT)
    resp = client.get("/emails/search", params={"q": "Urgent"})
    assert resp.status_code == 200
    emails = resp.json()
    assert len(emails) == 1
    assert emails[0]["event_id"] == "evt-002"


def test_search_body(client):
    client.post("/events/email", json=SAMPLE_EVENT)
    resp = client.get("/emails/search", params={"q": "clean email"})
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_stats(client):
    client.post("/events/email", json=SAMPLE_EVENT)
    client.post("/events/email", json=RISKY_EVENT)
    resp = client.get("/emails/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_emails"] == 2
    assert data["risky_emails"] == 1


def test_summary(client):
    client.post("/events/email", json=SAMPLE_EVENT)
    client.post("/events/email", json=RISKY_EVENT)
    resp = client.get("/emails/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert data["risky"] == 1
    assert len(data["top_senders"]) == 2


def test_empty_state(client):
    resp = client.get("/emails/recent")
    assert resp.status_code == 200
    assert resp.json() == []

    resp = client.get("/emails/stats")
    assert resp.json() == {"total_emails": 0, "risky_emails": 0}

    resp = client.get("/emails/summary")
    data = resp.json()
    assert data["total"] == 0
    assert data["latest_received_at"] is None
