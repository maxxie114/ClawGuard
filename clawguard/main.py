"""ClawGuard FastAPI application.

Secure inbound sanitization layer for LLM agents.
Accepts email webhooks, sanitizes content, and forwards safe payloads.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from .config import Config, load_config
from .forwarder import forward_to_openclaw, forward_to_skill
from .models import DashboardStats, RawEmailPayload, SanitizedEmailEvent
from .sanitizer import sanitize_email
from .storage import EventStore

logger = logging.getLogger("clawguard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

# --- App setup ---

config = load_config()
store = EventStore(db_path=config.db_path)

# Gmail client (lazy init)
_gmail_client = None


def _get_gmail_client():
    global _gmail_client
    if _gmail_client is None:
        from .gmail import GmailClient
        _gmail_client = GmailClient(
            credentials_path=config.gmail_credentials_path,
            token_path=config.gmail_token_path,
        )
        _gmail_client.authenticate()
        logger.info("Gmail client initialized")
    return _gmail_client


# Track last known historyId for Pub/Sub
_last_history_id: str | None = None

app = FastAPI(
    title="ClawGuard",
    description="Secure inbound sanitization layer for LLM agents",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Rate limiting (in-memory) ---

_rate_limit: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    window = 60.0
    _rate_limit[client_ip] = [t for t in _rate_limit[client_ip] if now - t < window]
    if len(_rate_limit[client_ip]) >= config.rate_limit_per_minute:
        return False
    _rate_limit[client_ip].append(now)
    return True


# --- Auth (in-memory token store) ---

_auth_tokens: set[str] = set()


def _require_auth(authorization: str | None = Header(None)):
    """Dependency that validates Bearer token on protected routes.

    Accepts either:
    - The static API key (config.api_key) — survives restarts, for skill/automation use
    - An ephemeral UI session token from /auth/login — for dashboard use
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization[len("Bearer "):]
    if token == config.api_key or token in _auth_tokens:
        return
    raise HTTPException(status_code=401, detail="Invalid token")


def _verify_signature(payload: bytes, signature: str | None, secret: str) -> bool:
    if not secret or not config.require_verification:
        return True
    if not signature:
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _mask_raw_payload(payload: dict[str, Any]) -> str:
    """Mask sensitive fields in raw payload for storage."""
    masked = dict(payload)
    # Keep structure but truncate long values
    for key in ("body", "body_html", "html", "text", "body_plain"):
        if key in masked and isinstance(masked[key], str):
            val = masked[key]
            if len(val) > 200:
                masked[key] = val[:200] + f"... [{len(val)} chars total]"
    # Mask attachment data
    if "attachments" in masked and isinstance(masked["attachments"], list):
        for att in masked["attachments"]:
            if isinstance(att, dict):
                att.pop("content", None)
                att.pop("data", None)
    return json.dumps(masked, default=str)


# --- Health ---

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


# --- Auth endpoints ---

@app.post("/auth/login")
async def auth_login(request: Request):
    """Validate admin password and return a session token."""
    body = await request.json()
    password = body.get("password", "")
    if not password or password != config.admin_password:
        raise HTTPException(status_code=401, detail="Wrong password")
    token = str(uuid.uuid4())
    _auth_tokens.add(token)
    logger.info("Admin login successful — new token issued")
    return {"token": token}


@app.get("/auth/check")
async def auth_check(authorization: str | None = Header(None)):
    """Quick check whether a token is still valid."""
    try:
        _require_auth(authorization)
    except HTTPException:
        return {"authenticated": False}
    return {"authenticated": True}


# --- Webhook ingestion ---

@app.post("/webhook/email")
async def receive_email_webhook(
    request: Request,
    x_clawguard_signature: str | None = Header(None),
):
    """Receive an inbound email webhook, sanitize it, store it, and forward it."""
    client_ip = request.client.host if request.client else "unknown"

    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # Read body
    body = await request.body()
    if len(body) > config.max_payload_size:
        raise HTTPException(status_code=413, detail="Payload too large")

    # Verify signature
    if not _verify_signature(body, x_clawguard_signature, config.webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse payload
    try:
        payload_dict = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    try:
        raw = RawEmailPayload(**payload_dict)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload: {e}")

    # Sanitize
    sanitized = sanitize_email(raw)

    # Store
    masked_raw = _mask_raw_payload(payload_dict)
    store.store_event(sanitized, raw_masked=masked_raw)

    logger.info(
        f"Processed email event_id={sanitized.event_id} "
        f"from={sanitized.from_addr} "
        f"risk_score={sanitized.risk.risk_score} "
        f"injection={sanitized.risk.injection_detected}"
    )

    # Forward to skill and/or OpenClaw
    forwarded_skill = await forward_to_skill(sanitized, config)
    forwarded_openclaw = await forward_to_openclaw(sanitized, config)

    return JSONResponse(
        status_code=200,
        content={
            "status": "processed",
            "event_id": sanitized.event_id,
            "risk_score": sanitized.risk.risk_score,
            "injection_detected": sanitized.risk.injection_detected,
            "forwarded_to_skill": forwarded_skill,
            "forwarded_to_openclaw": forwarded_openclaw,
        },
    )


# --- Test endpoint: send a test email ---

@app.post("/test/send")
async def send_test_email(request: Request):
    """Accept a test email payload directly (no signature needed) for demo purposes."""
    body = await request.body()
    try:
        payload_dict = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    try:
        raw = RawEmailPayload(**payload_dict)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload: {e}")

    sanitized = sanitize_email(raw)
    masked_raw = _mask_raw_payload(payload_dict)
    store.store_event(sanitized, raw_masked=masked_raw)

    await forward_to_skill(sanitized, config)
    await forward_to_openclaw(sanitized, config)

    return {
        "status": "processed",
        "event_id": sanitized.event_id,
        "sanitized": sanitized.model_dump(mode="json"),
    }


# --- API endpoints for UI ---

@app.get("/api/stats")
async def get_stats() -> DashboardStats:
    return store.get_stats()


@app.get("/api/events")
async def list_events(limit: int = 50, offset: int = 0, from_addr: str | None = None, _auth=Depends(_require_auth)):
    return store.list_events(limit=limit, offset=offset, from_addr=from_addr)


@app.get("/api/senders")
async def list_senders(_auth=Depends(_require_auth)):
    return store.list_senders()


@app.get("/api/events/risky")
async def list_risky_events(min_score: int = 1, limit: int = 50, _auth=Depends(_require_auth)):
    return store.list_risky_events(min_score=min_score, limit=limit)


@app.get("/api/events/{event_id}")
async def get_event(event_id: str, _auth=Depends(_require_auth)):
    event = store.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.get("/api/timeline")
async def get_timeline(days: int = 7, _auth=Depends(_require_auth)):
    return store.get_timeline(days=days)


# --- Gmail integration endpoints ---

async def _process_and_store(raw: RawEmailPayload, raw_dict: dict | None = None) -> SanitizedEmailEvent:
    """Shared pipeline: sanitize, store, forward."""
    sanitized = sanitize_email(raw)
    masked_raw = None
    if raw_dict:
        masked_raw = _mask_raw_payload(raw_dict)
    store.store_event(sanitized, raw_masked=masked_raw)

    logger.info(
        f"Processed email event_id={sanitized.event_id} "
        f"from={sanitized.from_addr} "
        f"risk_score={sanitized.risk.risk_score} "
        f"injection={sanitized.risk.injection_detected}"
    )

    await forward_to_skill(sanitized, config)
    await forward_to_openclaw(sanitized, config)
    return sanitized


@app.post("/gmail/pubsub")
async def gmail_pubsub_push(request: Request):
    """Receive GCP Pub/Sub push notifications for Gmail.

    When a new email arrives in Gmail, Google Pub/Sub sends a notification here.
    We then fetch the new message(s) via Gmail API, sanitize, and store.
    """
    global _last_history_id

    if not config.gmail_enabled:
        raise HTTPException(status_code=404, detail="Gmail integration not enabled")

    body = await request.body()
    try:
        envelope = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Pub/Sub message format: {"message": {"data": "<base64>", "messageId": "...", ...}, "subscription": "..."}
    message = envelope.get("message", {})
    data_b64 = message.get("data", "")

    if not data_b64:
        return {"status": "ignored", "reason": "no data"}

    try:
        data = json.loads(base64.b64decode(data_b64))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub data")

    # Gmail notification contains: {"emailAddress": "...", "historyId": "123456"}
    email_address = data.get("emailAddress", "")
    history_id = str(data.get("historyId", ""))
    logger.info(f"Gmail Pub/Sub notification: email={email_address} historyId={history_id}")

    if not history_id:
        return {"status": "ignored", "reason": "no historyId"}

    # Fetch new messages using history API
    try:
        gmail = _get_gmail_client()
        start_id = _last_history_id or history_id
        message_ids = gmail.get_history(start_id)
        _last_history_id = history_id

        results = []
        for msg_id in message_ids:
            raw = gmail.fetch_message(msg_id)
            if raw:
                sanitized = await _process_and_store(raw)
                results.append({
                    "event_id": sanitized.event_id,
                    "risk_score": sanitized.risk.risk_score,
                    "injection_detected": sanitized.risk.injection_detected,
                })

        logger.info(f"Processed {len(results)} new messages from Gmail Pub/Sub notification")
        return {"status": "processed", "messages_processed": len(results), "results": results}

    except Exception as e:
        logger.error(f"Failed to process Gmail Pub/Sub notification: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gmail/fetch")
async def gmail_fetch_recent(max_results: int = 10, query: str = "in:inbox", _auth=Depends(_require_auth)):
    """Manually trigger a fetch of recent Gmail messages.

    The skill or admin can call this to pull latest emails on demand.
    """
    if not config.gmail_enabled:
        raise HTTPException(status_code=404, detail="Gmail integration not enabled")

    try:
        gmail = _get_gmail_client()
        raw_emails = gmail.fetch_recent_messages(max_results=max_results, query=query)

        results = []
        skipped = 0
        for raw in raw_emails:
            # Skip if we already have this message (by checking from+subject+timestamp combo)
            # For dedup, we store and rely on event_id uniqueness per content
            sanitized = await _process_and_store(raw)
            results.append({
                "event_id": sanitized.event_id,
                "from": sanitized.from_addr,
                "subject": sanitized.subject_sanitized[:80],
                "risk_score": sanitized.risk.risk_score,
                "injection_detected": sanitized.risk.injection_detected,
            })

        return {
            "status": "fetched",
            "total_fetched": len(results),
            "results": results,
        }

    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"Gmail fetch failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gmail/setup-watch")
async def gmail_setup_watch(_auth=Depends(_require_auth)):
    """Set up Gmail Pub/Sub watch for real-time notifications.

    Requires GCP_PUBSUB_TOPIC to be configured.
    """
    if not config.gmail_enabled:
        raise HTTPException(status_code=404, detail="Gmail integration not enabled")
    if not config.gcp_pubsub_topic:
        raise HTTPException(status_code=400, detail="GCP_PUBSUB_TOPIC not configured")

    try:
        gmail = _get_gmail_client()
        result = gmail.setup_watch(config.gcp_pubsub_topic)
        global _last_history_id
        _last_history_id = str(result.get("historyId", ""))
        return {
            "status": "watch_active",
            "historyId": result.get("historyId"),
            "expiration": result.get("expiration"),
        }
    except Exception as e:
        logger.error(f"Gmail watch setup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/gmail/status")
async def gmail_status(_auth=Depends(_require_auth)):
    """Check Gmail integration status."""
    return {
        "enabled": config.gmail_enabled,
        "credentials_exist": config.gmail_credentials_path.exists(),
        "token_exist": config.gmail_token_path.exists(),
        "pubsub_topic": config.gcp_pubsub_topic or None,
        "authenticated": _gmail_client is not None,
        "last_history_id": _last_history_id,
    }


# --- Admin UI ---

_STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
async def dashboard_ui():
    """Serve the ClawGuard admin dashboard."""
    html_path = _STATIC_DIR / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

