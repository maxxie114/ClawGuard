"""ClawGuard FastAPI application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from clawguard.models import (
    EmailSummary,
    IngestResponse,
    SanitizedEmailEvent,
    StatsResponse,
)
from clawguard.storage import (
    get_email_count,
    get_recent_emails,
    get_risky_count,
    get_risky_emails,
    init_db,
    search_emails,
    store_event,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="ClawGuard",
    description="Secure inbound sanitization layer for LLM agents",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/events/email", response_model=IngestResponse)
async def ingest_email(event: SanitizedEmailEvent):
    inserted = store_event(event)
    status = "created" if inserted else "duplicate"
    return IngestResponse(status=status, event_id=event.event_id)


@app.get("/emails/recent")
async def list_recent_emails(limit: int = Query(default=10, ge=1, le=100)):
    return get_recent_emails(limit)


@app.get("/emails/risky")
async def list_risky_emails(limit: int = Query(default=10, ge=1, le=100)):
    return get_risky_emails(limit)


@app.get("/emails/search")
async def search(q: str = Query(..., min_length=1), limit: int = Query(default=10, ge=1, le=100)):
    return search_emails(q, limit)


@app.get("/emails/summary", response_model=EmailSummary)
async def summarize_recent_emails():
    recent = get_recent_emails(50)
    total = get_email_count()
    risky = get_risky_count()
    latest = recent[0].received_at if recent else None
    senders = list(dict.fromkeys(e.from_addr for e in recent if e.from_addr))[:5]
    return EmailSummary(
        total=total,
        risky=risky,
        latest_received_at=latest,
        top_senders=senders,
    )


@app.get("/emails/stats", response_model=StatsResponse)
async def email_stats():
    return StatsResponse(
        total_emails=get_email_count(),
        risky_emails=get_risky_count(),
    )
