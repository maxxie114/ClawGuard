"""Pydantic models for ClawGuard skill layer."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class RiskInfo(BaseModel):
    flags: list[str] = Field(default_factory=list)
    injection_detected: bool = False
    truncated: bool = False


class EmailMeta(BaseModel):
    original_sizes: dict[str, int] = Field(default_factory=dict)
    sanitizer_version: str = ""


class SanitizedEmailEvent(BaseModel):
    event_id: str
    provider: str = ""
    received_at: datetime
    from_addr: str = ""
    to_addrs: list[str] = Field(default_factory=list)
    subject_sanitized: str = ""
    body_sanitized: str = ""
    attachments_sanitized: list[dict] = Field(default_factory=list)
    risk: RiskInfo = Field(default_factory=RiskInfo)
    meta: EmailMeta = Field(default_factory=EmailMeta)


class IngestResponse(BaseModel):
    status: str
    event_id: str


class EmailRecord(BaseModel):
    event_id: str
    provider: str
    received_at: str
    from_addr: str
    to_addrs: list[str]
    subject: str
    body: str
    attachments: list[dict]
    risk_flags: list[str]
    injection_detected: bool
    truncated: bool


class EmailSummary(BaseModel):
    total: int
    risky: int
    latest_received_at: Optional[str] = None
    top_senders: list[str] = Field(default_factory=list)


class StatsResponse(BaseModel):
    total_emails: int
    risky_emails: int
