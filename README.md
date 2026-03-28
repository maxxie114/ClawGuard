# ClawGuard

A security-first **Email → Sanitized Event → Agent** pipeline that prevents prompt injection and unsafe content from ever reaching the LLM.

All external content is untrusted. Agents never see raw input.

## Problem

LLM agents are vulnerable to prompt injection, tool call manipulation, hidden HTML/script payloads, secret exfiltration attempts, malicious attachments, and markdown-based instruction hijacking. Most systems pass raw inbound data directly to the agent.

ClawGuard is a **defensive middleware layer** that sits between inbound webhooks and your agent runtime.

## How It Works

```
Inbound Webhook
  → Verification
  → Normalization
  → Deterministic Sanitization
  → Risk Flagging
  → Structured Safe Payload
  → Agent
```

### Guarantees

- No raw HTML reaches the agent
- No scripts or hidden elements
- Prompt injection patterns flagged and redacted
- Attachments filtered and extracted safely
- Content length-limited and normalized
- Risk metadata included with every payload

## Tech Stack

- **Python**
- **FastAPI**
- Deterministic regex-based injection guard
- Pluggable sinks (stdout / DB / webhook)

## Roadmap

### Phase 1 — Email Ingestion ✅ COMPLETE

- Email webhook endpoint
- Shared-secret verification
- Canonical `EmailEvent` schema
- Sanitization pipeline: HTML stripping, Unicode cleanup, injection pattern detection, truncation, attachment allowlist
- Sanitized JSON output to downstream agent
- **Web-based Gmail OAuth** — Connect Gmail directly from UI without SSH

### Phase 2 — GitHub Ingestion (In Progress)

- GitHub webhook ingestion
- Diff truncation and markdown sanitization
- Secret scanning
- Repo-level risk scoring

### Phase 3 — Multi-Account Support ✅ COMPLETE

- Multi-inbox support — Query emails per account (`/api/accounts`, `to_addr` filtering)
- Per-account sender lists and statistics
- CLI support for account filtering (`--account` flag)

## Getting Started

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn clawguard.main:app --reload
```

## License

[MIT](LICENSE)
