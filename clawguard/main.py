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
import os
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials

from .auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_api_key,
    get_api_key_prefix,
    hash_api_key,
    hash_password,
    verify_password,
)
from .config import Config, load_config
from .forwarder import forward_to_openclaw, forward_to_skill
from .models import DashboardStats, RawEmailPayload, SanitizedEmailEvent
from .sanitizer import sanitize_email
from .storage import EventStore, UserStore

logger = logging.getLogger("clawguard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

# --- App setup ---

config = load_config()
store = EventStore(db_path=config.db_path)
user_store = UserStore(db_path=config.db_path)

# Encryption for Gmail tokens at rest
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = config.encryption_key
        if not key:
            # Generate and warn — in production this MUST be set via env
            key = Fernet.generate_key().decode()
            logger.warning(
                "CLAWGUARD_ENCRYPTION_KEY not set! Generated ephemeral key. "
                "Gmail tokens will be lost on restart. Set CLAWGUARD_ENCRYPTION_KEY in .env."
            )
        else:
            # Ensure key is valid Fernet key (base64, 32 bytes)
            try:
                Fernet(key.encode() if isinstance(key, str) else key)
                key = key if isinstance(key, str) else key.decode()
            except Exception:
                # If the env var isn't a valid Fernet key, derive one from it
                import hashlib
                derived = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())
                key = derived.decode()
        _fernet = Fernet(key.encode() if isinstance(key, str) else key)
    return _fernet


def encrypt_token(token_json: str) -> str:
    return _get_fernet().encrypt(token_json.encode()).decode()


def decrypt_token(encrypted: str) -> str:
    return _get_fernet().decrypt(encrypted.encode()).decode()


# Ensure admin user exists
def _ensure_admin():
    admin = user_store.get_user_by_email(config.admin_email)
    if not admin:
        pw_hash = hash_password(config.admin_password)
        user_store.create_user(
            email=config.admin_email,
            password_hash=pw_hash,
            display_name="Admin",
            role="admin",
        )
        logger.info(f"Admin user created: {config.admin_email}")
    else:
        # Update admin password if it changed in .env
        if not verify_password(config.admin_password, admin["password_hash"]):
            user_store.update_user_password(admin["id"], hash_password(config.admin_password))
            logger.info("Admin password updated from .env")


_ensure_admin()

# Gmail clients per user (lazy init)
_gmail_clients: dict[int, Any] = {}

# Track last known historyId for Pub/Sub
_last_history_id: str | None = None

app = FastAPI(
    title="ClawGuard",
    description="Secure inbound sanitization layer for LLM agents",
    version="0.2.0",
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
_auth_rate_limit: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(client_ip: str, limit: int = 0, store_dict: dict | None = None) -> bool:
    if limit == 0:
        limit = config.rate_limit_per_minute
    if store_dict is None:
        store_dict = _rate_limit
    now = time.time()
    window = 60.0
    store_dict[client_ip] = [t for t in store_dict[client_ip] if now - t < window]
    if len(store_dict[client_ip]) >= limit:
        return False
    store_dict[client_ip].append(now)
    return True


# --- Auth dependencies ---

def _get_current_user(authorization: str | None = Header(None)) -> dict:
    """Dependency: extract and validate user from JWT or API key.
    Returns user dict with id, email, role.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization[len("Bearer "):]

    # Check if it's an API key (starts with cg_)
    if token.startswith("cg_"):
        key_hash = hash_api_key(token)
        user = user_store.get_user_by_api_key_hash(key_hash)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return user

    # Otherwise treat as JWT
    payload = decode_token(token, config.jwt_secret)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = int(payload["sub"])
    user = user_store.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def _require_admin(user: dict = Depends(_get_current_user)) -> dict:
    """Dependency: require admin role."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# Legacy auth for backward compat (webhook ingestion still uses static api_key)
def _require_auth(authorization: str | None = Header(None)):
    """Legacy auth: accepts static API key OR new JWT/API key."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization[len("Bearer "):]
    # Accept legacy static API key
    if token == config.api_key:
        return
    # Try new auth
    try:
        _get_current_user(authorization)
    except HTTPException:
        raise HTTPException(status_code=401, detail="Invalid token")


def _verify_signature(payload: bytes, signature: str | None, secret: str) -> bool:
    if not secret or not config.require_verification:
        return True
    if not signature:
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _mask_raw_payload(payload: dict[str, Any]) -> str:
    masked = dict(payload)
    for key in ("body", "body_html", "html", "text", "body_plain"):
        if key in masked and isinstance(masked[key], str):
            val = masked[key]
            if len(val) > 200:
                masked[key] = val[:200] + f"... [{len(val)} chars total]"
    if "attachments" in masked and isinstance(masked["attachments"], list):
        for att in masked["attachments"]:
            if isinstance(att, dict):
                att.pop("content", None)
                att.pop("data", None)
    return json.dumps(masked, default=str)


# --- Static files ---

_STATIC_DIR = Path(__file__).parent / "static"

# --- Health ---


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}


# ============================================================
# Auth endpoints
# ============================================================

@app.post("/auth/login")
async def auth_login(request: Request):
    """Login with email + password. Returns JWT access + refresh tokens."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip, limit=10, store_dict=_auth_rate_limit):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    body = await request.json()
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")

    user = user_store.get_user_by_email(email)
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = create_access_token(user["id"], user["email"], user["role"], config.jwt_secret)
    refresh_token = create_refresh_token(user["id"], config.jwt_secret)

    logger.info(f"Login successful: {email} (role={user['role']})")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
    }


@app.post("/auth/refresh")
async def auth_refresh(request: Request):
    """Exchange a refresh token for a new access token."""
    body = await request.json()
    refresh_token = body.get("refresh_token", "")

    payload = decode_token(refresh_token, config.jwt_secret)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user_id = int(payload["sub"])
    user = user_store.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    access_token = create_access_token(user["id"], user["email"], user["role"], config.jwt_secret)
    return {"access_token": access_token}


@app.get("/auth/check")
async def auth_check(authorization: str | None = Header(None)):
    """Check whether a token is valid. Returns user info if authenticated."""
    try:
        user = _get_current_user(authorization)
        return {
            "authenticated": True,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "display_name": user["display_name"],
                "role": user["role"],
            },
        }
    except HTTPException:
        return {"authenticated": False}


# ============================================================
# Admin endpoints — manage beta users
# ============================================================

@app.get("/admin/users")
async def admin_list_users(admin: dict = Depends(_require_admin)):
    """List all users."""
    return user_store.list_users()


@app.post("/admin/users")
async def admin_create_user(request: Request, admin: dict = Depends(_require_admin)):
    """Create a new beta user. Admin sets email + temporary password."""
    body = await request.json()
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    display_name = body.get("display_name", "")

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    pw_hash = hash_password(password)
    user = user_store.create_user(email=email, password_hash=pw_hash, display_name=display_name, role="user")
    if not user:
        raise HTTPException(status_code=409, detail="User with this email already exists")

    logger.info(f"Admin created beta user: {email}")
    return {
        "id": user["id"],
        "email": user["email"],
        "display_name": user["display_name"],
        "role": user["role"],
    }


@app.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: int, admin: dict = Depends(_require_admin)):
    """Remove a beta user (cannot delete admin)."""
    if not user_store.delete_user(user_id):
        raise HTTPException(status_code=404, detail="User not found or cannot delete admin")
    logger.info(f"Admin deleted user id={user_id}")
    return {"status": "deleted"}


# ============================================================
# API Key management
# ============================================================

@app.get("/api/keys")
async def list_api_keys(user: dict = Depends(_get_current_user)):
    """List current user's API keys."""
    return user_store.list_api_keys(user["id"])


@app.post("/api/keys")
async def create_api_key_endpoint(request: Request, user: dict = Depends(_get_current_user)):
    """Generate a new API key. Returns the raw key ONCE."""
    body = await request.json()
    name = body.get("name", "Untitled Key")

    raw_key, key_hash = generate_api_key()
    prefix = get_api_key_prefix(raw_key)

    key_record = user_store.create_api_key(
        user_id=user["id"],
        key_hash=key_hash,
        name=name,
        prefix=prefix,
    )

    logger.info(f"API key created for user {user['email']}: {prefix}")
    return {
        "key": raw_key,  # Only shown once!
        "id": key_record["id"],
        "name": key_record["name"],
        "prefix": prefix,
        "created_at": key_record["created_at"],
    }


@app.delete("/api/keys/{key_id}")
async def revoke_api_key_endpoint(key_id: int, user: dict = Depends(_get_current_user)):
    """Revoke an API key."""
    if not user_store.revoke_api_key(key_id, user["id"]):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "revoked"}


# ============================================================
# Webhook ingestion (unchanged, uses legacy auth or signature)
# ============================================================

@app.post("/webhook/email")
async def receive_email_webhook(
    request: Request,
    x_clawguard_signature: str | None = Header(None),
):
    """Receive an inbound email webhook, sanitize it, store it, and forward it."""
    client_ip = request.client.host if request.client else "unknown"

    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    body = await request.body()
    if len(body) > config.max_payload_size:
        raise HTTPException(status_code=413, detail="Payload too large")

    if not _verify_signature(body, x_clawguard_signature, config.webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid signature")

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

    logger.info(
        f"Processed email event_id={sanitized.event_id} "
        f"from={sanitized.from_addr} "
        f"risk_score={sanitized.risk.risk_score} "
        f"injection={sanitized.risk.injection_detected}"
    )

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


# ============================================================
# Test endpoint (public, rate limited)
# ============================================================

_demo_rate_limit: dict[str, list[float]] = defaultdict(list)


@app.post("/test/send")
async def send_test_email(request: Request):
    """Accept a test email payload directly (no auth) for demo purposes. Rate limited."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip, limit=10, store_dict=_demo_rate_limit):
        raise HTTPException(status_code=429, detail="Demo rate limit exceeded (10/min)")

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

    return {
        "status": "processed",
        "event_id": sanitized.event_id,
        "sanitized": sanitized.model_dump(mode="json"),
    }


# ============================================================
# API endpoints for dashboard
# ============================================================

@app.get("/api/stats")
async def get_stats() -> DashboardStats:
    return store.get_stats()


@app.get("/api/events")
async def list_events(
    limit: int = 50,
    offset: int = 0,
    from_addr: str | None = None,
    to_addr: str | None = None,
    user: dict = Depends(_get_current_user),
):
    return store.list_events(limit=limit, offset=offset, from_addr=from_addr, to_addr=to_addr)


@app.get("/api/accounts")
async def list_accounts(user: dict = Depends(_get_current_user)):
    return store.list_accounts()


@app.get("/api/senders")
async def list_senders(to_addr: str | None = None, user: dict = Depends(_get_current_user)):
    return store.list_senders(to_addr=to_addr)


@app.get("/api/events/risky")
async def list_risky_events(min_score: int = 1, limit: int = 50, user: dict = Depends(_get_current_user)):
    return store.list_risky_events(min_score=min_score, limit=limit)


@app.get("/api/events/{event_id}")
async def get_event(event_id: str, user: dict = Depends(_get_current_user)):
    event = store.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.get("/api/timeline")
async def get_timeline(days: int = 7, user: dict = Depends(_get_current_user)):
    return store.get_timeline(days=days)


# ============================================================
# Gmail OAuth Web Flow (Per-User)
# ============================================================

# In-memory store for OAuth state
_oauth_states: dict[str, dict] = {}


@app.get("/gmail/auth/start")
async def gmail_auth_start(request: Request, user: dict = Depends(_get_current_user)):
    """Start Gmail OAuth flow. Returns a URL for the user to authorize."""
    if not config.gmail_enabled:
        raise HTTPException(status_code=404, detail="Gmail integration not enabled")

    if not config.gmail_credentials_path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"OAuth credentials not found at {config.gmail_credentials_path}. "
                   "Please upload via admin panel or place on server."
        )

    try:
        # Build redirect URI respecting X-Forwarded-Proto from nginx
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        base = f"{scheme}://{request.url.hostname}"
        if request.url.port and request.url.port not in (80, 443):
            base += f":{request.url.port}"
        redirect_uri = base + "/gmail/auth/callback"

        scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        flow = Flow.from_client_secrets_file(
            str(config.gmail_credentials_path),
            scopes=scopes,
            redirect_uri=redirect_uri,
        )

        auth_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent',
        )

        _oauth_states[state] = {
            "created_at": time.time(),
            "user_id": user["id"],
            "flow_data": {
                "client_config": flow.client_config,
                "scopes": scopes,
                "redirect_uri": redirect_uri,
            },
        }

        # Clean expired states
        now = time.time()
        expired = [s for s, d in _oauth_states.items() if now - d["created_at"] > 600]
        for s in expired:
            del _oauth_states[s]

        return {
            "status": "authorization_required",
            "auth_url": auth_url,
            "state": state,
        }

    except Exception as e:
        logger.error(f"Failed to start OAuth flow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/gmail/auth/callback")
async def gmail_auth_callback(request: Request, state: str, code: str | None = None, error: str | None = None):
    """OAuth callback. Receives the authorization code from Google, stores token per-user."""
    if error:
        return HTMLResponse(content=_oauth_error_html(f"Authorization failed: {error}"), status_code=400)

    if not code:
        return HTMLResponse(content=_oauth_error_html("Missing authorization code"), status_code=400)

    if state not in _oauth_states:
        return HTMLResponse(content=_oauth_error_html("Invalid or expired state. Please try again."), status_code=400)

    try:
        state_data = _oauth_states[state]
        user_id = state_data["user_id"]
        flow_data = state_data["flow_data"]

        # client_config needs the "web" wrapper for from_client_config
        client_config = flow_data["client_config"]
        if "web" not in client_config and "installed" not in client_config:
            client_config = {"web": client_config}
        flow = Flow.from_client_config(
            client_config,
            scopes=flow_data["scopes"],
            redirect_uri=flow_data["redirect_uri"],
        )

        # Don't fail if Google returns additional scopes (e.g. from previous grants)
        import os
        os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
        flow.fetch_token(code=code)
        creds = flow.credentials

        token_data = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': list(creds.scopes) if creds.scopes else [],
        }

        # Figure out the Gmail email address
        from googleapiclient.discovery import build
        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        gmail_email = profile.get("emailAddress", "unknown")

        # Encrypt and store per-user
        encrypted_token = encrypt_token(json.dumps(token_data))
        user_store.store_gmail_account(user_id, gmail_email, encrypted_token)

        # Also save to legacy file path for backward compat
        config.gmail_token_path.write_text(json.dumps(token_data, indent=2))

        # Clear state
        del _oauth_states[state]

        logger.info(f"Gmail OAuth complete: user_id={user_id}, gmail={gmail_email}")

        return HTMLResponse(content=_oauth_success_html(gmail_email))

    except Exception as e:
        logger.error(f"OAuth callback failed: {e}")
        return HTMLResponse(content=_oauth_error_html(str(e)), status_code=500)


def _oauth_success_html(email: str) -> str:
    return f"""<!DOCTYPE html><html><head><title>ClawGuard - Gmail Connected</title>
<style>body{{font-family:system-ui,sans-serif;background:#0a0e17;color:#e0e6f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}}
.c{{text-align:center;padding:40px;background:#131a2b;border-radius:16px;border:1px solid #2a3555;max-width:500px}}
.ok{{color:#00e676;font-size:48px;margin-bottom:20px}}h1{{margin-bottom:16px}}
p{{color:#8899bb;margin-bottom:24px}}.b{{background:#4f8cff;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block}}</style></head>
<body><div class="c"><div class="ok">&#10003;</div><h1>Gmail Connected</h1>
<p>{email} has been authorized. You can close this window and return to the dashboard.</p>
<a href="/dashboard" class="b">Go to Dashboard</a></div></body></html>"""


def _oauth_error_html(error: str) -> str:
    return f"""<!DOCTYPE html><html><head><title>ClawGuard - Error</title>
<style>body{{font-family:system-ui,sans-serif;background:#0a0e17;color:#e0e6f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}}
.c{{text-align:center;padding:40px;background:#131a2b;border-radius:16px;border:1px solid #2a3555;max-width:500px}}
.err{{color:#ff4d6a;font-size:48px;margin-bottom:20px}}h1{{margin-bottom:16px}}
p{{color:#8899bb;margin-bottom:24px}}.b{{background:#4f8cff;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block}}</style></head>
<body><div class="c"><div class="err">&#10007;</div><h1>Authorization Failed</h1>
<p>{error}</p><a href="/dashboard" class="b">Back to Dashboard</a></div></body></html>"""


# ============================================================
# Gmail integration endpoints
# ============================================================

def _get_gmail_client_for_user(user_id: int, gmail_email: str | None = None):
    """Get or create a Gmail client for a specific user account."""
    from .gmail import GmailClient

    # If no specific email, use the first connected account
    accounts = user_store.list_gmail_accounts(user_id)
    if not accounts:
        raise HTTPException(status_code=400, detail="No Gmail account connected. Connect one from the dashboard.")

    if gmail_email:
        account = next((a for a in accounts if a["gmail_email"] == gmail_email), None)
        if not account:
            raise HTTPException(status_code=404, detail=f"Gmail account {gmail_email} not found")
    else:
        account = accounts[0]

    encrypted = user_store.get_gmail_token(user_id, account["gmail_email"])
    if not encrypted:
        raise HTTPException(status_code=400, detail="Gmail token not found")

    token_json = decrypt_token(encrypted)
    token_data = json.loads(token_json)

    creds = Credentials(
        token=token_data.get("token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri=token_data.get("token_uri"),
        client_id=token_data.get("client_id"),
        client_secret=token_data.get("client_secret"),
        scopes=token_data.get("scopes"),
    )

    # Refresh if expired
    if creds.expired and creds.refresh_token:
        from google.auth.transport.requests import Request as GoogleRequest
        creds.refresh(GoogleRequest())
        # Update stored token
        token_data["token"] = creds.token
        new_encrypted = encrypt_token(json.dumps(token_data))
        user_store.store_gmail_account(user_id, account["gmail_email"], new_encrypted)

    from googleapiclient.discovery import build
    service = build("gmail", "v1", credentials=creds)

    client = GmailClient.__new__(GmailClient)
    client._service = service
    client._creds = creds
    client.credentials_path = config.gmail_credentials_path
    client.token_path = config.gmail_token_path

    return client


async def _process_and_store(raw: RawEmailPayload, raw_dict: dict | None = None, user_id: int | None = None) -> SanitizedEmailEvent:
    """Shared pipeline: sanitize, store, forward."""
    sanitized = sanitize_email(raw)
    masked_raw = None
    if raw_dict:
        masked_raw = _mask_raw_payload(raw_dict)
    store.store_event(sanitized, raw_masked=masked_raw, user_id=user_id)

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
    """Receive GCP Pub/Sub push notifications for Gmail."""
    global _last_history_id

    if not config.gmail_enabled:
        raise HTTPException(status_code=404, detail="Gmail integration not enabled")

    body = await request.body()
    try:
        envelope = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    message = envelope.get("message", {})
    data_b64 = message.get("data", "")

    if not data_b64:
        return {"status": "ignored", "reason": "no data"}

    try:
        data = json.loads(base64.b64decode(data_b64))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub data")

    email_address = data.get("emailAddress", "")
    history_id = str(data.get("historyId", ""))
    logger.info(f"Gmail Pub/Sub notification: email={email_address} historyId={history_id}")

    if not history_id:
        return {"status": "ignored", "reason": "no historyId"}

    # For pub/sub, try legacy global client first, then per-user
    try:
        gmail = _get_legacy_gmail_client()
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

        return {"status": "processed", "messages_processed": len(results), "results": results}

    except Exception as e:
        logger.error(f"Failed to process Gmail Pub/Sub notification: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Legacy Gmail client for backward compat (uses file-based token)
_legacy_gmail_client = None


def _get_legacy_gmail_client():
    global _legacy_gmail_client
    if _legacy_gmail_client is None:
        from .gmail import GmailClient
        _legacy_gmail_client = GmailClient(
            credentials_path=config.gmail_credentials_path,
            token_path=config.gmail_token_path,
        )
        _legacy_gmail_client.authenticate()
    return _legacy_gmail_client


@app.post("/gmail/fetch")
async def gmail_fetch_recent(
    max_results: int = 10,
    query: str = "in:inbox",
    gmail_email: str | None = None,
    user: dict = Depends(_get_current_user),
):
    """Fetch recent Gmail messages for the current user."""
    if not config.gmail_enabled:
        raise HTTPException(status_code=404, detail="Gmail integration not enabled")

    try:
        gmail = _get_gmail_client_for_user(user["id"], gmail_email)
        raw_emails = gmail.fetch_recent_messages(max_results=max_results, query=query)

        results = []
        skipped = 0
        for raw in raw_emails:
            to_addr = raw.to_addrs[0] if raw.to_addrs else ""
            received_at = raw.timestamp or ""
            subject = raw.subject or ""
            if store.event_exists(raw.from_address, to_addr, received_at, subject):
                skipped += 1
                continue

            sanitized = await _process_and_store(raw, user_id=user["id"])
            results.append({
                "event_id": sanitized.event_id,
                "from": sanitized.from_addr,
                "subject": sanitized.subject_sanitized[:80],
                "risk_score": sanitized.risk.risk_score,
                "injection_detected": sanitized.risk.injection_detected,
            })

        return {"status": "fetched", "total_fetched": len(results), "skipped_duplicates": skipped, "results": results}

    except HTTPException:
        raise
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"Gmail fetch failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gmail/setup-watch")
async def gmail_setup_watch(user: dict = Depends(_get_current_user)):
    if not config.gmail_enabled:
        raise HTTPException(status_code=404, detail="Gmail integration not enabled")
    if not config.gcp_pubsub_topic:
        raise HTTPException(status_code=400, detail="GCP_PUBSUB_TOPIC not configured")

    try:
        gmail = _get_gmail_client_for_user(user["id"])
        result = gmail.setup_watch(config.gcp_pubsub_topic)
        global _last_history_id
        _last_history_id = str(result.get("historyId", ""))
        return {
            "status": "watch_active",
            "historyId": result.get("historyId"),
            "expiration": result.get("expiration"),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Gmail watch setup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/gmail/accounts")
async def gmail_list_accounts(user: dict = Depends(_get_current_user)):
    """List Gmail accounts connected by the current user."""
    accounts = user_store.list_gmail_accounts(user["id"])
    return accounts


@app.delete("/gmail/accounts/{account_id}")
async def gmail_disconnect_account(account_id: int, user: dict = Depends(_get_current_user)):
    """Disconnect a Gmail account."""
    if not user_store.delete_gmail_account(account_id, user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")
    return {"status": "disconnected"}


@app.get("/gmail/status")
async def gmail_status(user: dict = Depends(_get_current_user)):
    """Check Gmail integration status for current user."""
    accounts = user_store.list_gmail_accounts(user["id"])
    return {
        "enabled": config.gmail_enabled,
        "credentials_exist": config.gmail_credentials_path.exists(),
        "connected_accounts": [a["gmail_email"] for a in accounts],
        "account_count": len(accounts),
        "pubsub_topic": config.gcp_pubsub_topic or None,
    }


# ============================================================
# Cron-friendly endpoint — fetch all Gmail accounts
# ============================================================

@app.post("/gmail/fetch-all")
async def gmail_fetch_all(request: Request):
    """Fetch new emails for ALL connected Gmail accounts.

    Localhost-only — intended to be called by a cron job on the server.
    Example cron (every 5 min):
        */5 * * * * curl -s -X POST http://127.0.0.1:8000/gmail/fetch-all
    """
    # Only allow from localhost — check X-Real-IP/X-Forwarded-For (set by nginx) to detect proxied external requests
    real_ip = request.headers.get("x-real-ip", "") or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    client_ip = real_ip or (request.client.host if request.client else "")
    if client_ip not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="Localhost only")

    if not config.gmail_enabled:
        raise HTTPException(status_code=404, detail="Gmail integration not enabled")

    all_accounts = user_store.get_all_gmail_tokens()
    if not all_accounts:
        return {"status": "ok", "message": "No Gmail accounts connected"}

    results = {}
    for acct in all_accounts:
        user_id = acct["user_id"]
        gmail_email = acct["gmail_email"]
        try:
            gmail = _get_gmail_client_for_user(user_id, gmail_email)
            raw_emails = gmail.fetch_recent_messages(max_results=20, query="in:inbox newer_than:1h")

            new_count = 0
            for raw in raw_emails:
                to_addr = raw.to_addrs[0] if raw.to_addrs else ""
                received_at = raw.timestamp or ""
                subject = raw.subject or ""
                if store.event_exists(raw.from_address, to_addr, received_at, subject):
                    continue
                await _process_and_store(raw, user_id=user_id)
                new_count += 1

            results[gmail_email] = {"new_emails": new_count, "status": "ok"}
            if new_count > 0:
                logger.info(f"Gmail fetch-all: {new_count} new email(s) for {gmail_email}")

        except Exception as e:
            logger.error(f"Gmail fetch-all failed for {gmail_email}: {e}")
            results[gmail_email] = {"new_emails": 0, "status": "error", "error": str(e)}

    total_new = sum(r["new_emails"] for r in results.values())
    return {"status": "ok", "accounts": len(results), "total_new_emails": total_new, "details": results}


# ============================================================
# Page routes — serve frontend HTML
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def landing_page():
    """Serve the landing page."""
    html_path = _STATIC_DIR / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>ClawGuard</h1><p>Frontend not built yet.</p>")


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Serve the login page."""
    html_path = _STATIC_DIR / "login.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Login</h1>")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    """Serve the dashboard SPA (auth checked client-side)."""
    html_path = _STATIC_DIR / "dashboard.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Dashboard</h1>")


@app.get("/demo", response_class=HTMLResponse)
async def demo_page():
    """Serve the public demo page."""
    html_path = _STATIC_DIR / "demo.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Demo</h1>")


@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    """Serve the admin panel (auth checked client-side)."""
    html_path = _STATIC_DIR / "dashboard.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Admin</h1>")
