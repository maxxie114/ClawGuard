# ClawGuard

A security-first **Email → Sanitized Event → Agent** pipeline that prevents prompt injection and unsafe content from ever reaching the LLM.

All external content is untrusted. Agents never see raw input.

**Live at [claw-guard.tech](https://claw-guard.tech)** — closed beta, contact support@qubemc.com for access.

## Problem

LLM agents are vulnerable to prompt injection, tool call manipulation, hidden HTML/script payloads, secret exfiltration attempts, malicious attachments, and markdown-based instruction hijacking. Most systems pass raw inbound data directly to the agent.

ClawGuard is a **defensive middleware layer** that sits between inbound email and your agent runtime.

## How It Works

```
Gmail Inbox
  → OAuth Connect (per-user, encrypted)
  → Auto-Fetch (cron, every minute)
  → Deterministic Sanitization
  → Risk Scoring & Injection Detection
  → Structured Safe Payload
  → Agent (via API key)
```

### Sanitization Guarantees

- No raw HTML reaches the agent
- No scripts or hidden elements
- Prompt injection patterns flagged and redacted
- API keys, tokens, and passwords redacted
- Attachments filtered by allowlist
- Content length-limited and normalized
- Risk metadata (0–100 score) included with every payload

## Features

- **JWT + API Key Auth** — Closed beta with admin-managed users. API keys (`cg_` prefix) for agent/automation access.
- **Per-User Gmail OAuth** — Each user connects their own Gmail(s). Tokens encrypted at rest with Fernet.
- **Auto-Fetch** — Cron-driven polling fetches new emails every minute with deduplication.
- **Dashboard** — Inbox viewer, API key management, Gmail account management, admin panel.
- **Security Demo** — Public demo at `/demo` with 8 attack vectors, no login required.
- **Agent Skill** — Bundled `clawguard-skill` for OpenClaw/agent integration with query scripts.

## Tech Stack

- **Python / FastAPI** — API server
- **SQLite** — Storage (users, API keys, Gmail tokens, sanitized events)
- **bcrypt + PyJWT** — Auth
- **Fernet (cryptography)** — Gmail token encryption
- **nginx + Let's Encrypt** — HTTPS reverse proxy
- **Deterministic regex pipeline** — Injection detection and sanitization

## Getting Started

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up .env (required)
cat > .env << 'EOF'
CLAWGUARD_ADMIN_EMAIL=admin@example.com
CLAWGUARD_ADMIN_PASSWORD=your-secure-password
CLAWGUARD_JWT_SECRET=your-jwt-secret
CLAWGUARD_ENCRYPTION_KEY=your-fernet-key
EOF

# Run the server
uvicorn clawguard.main:app --host 0.0.0.0 --port 8000
```

## API Endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `POST /auth/login` | None | Login (email + password → JWT) |
| `GET /api/events` | Bearer | List sanitized emails (filterable) |
| `GET /api/events/risky` | Bearer | List risky emails by score |
| `GET /api/events/{id}` | Bearer | Get single email detail |
| `GET /api/accounts` | Bearer | List connected inboxes |
| `GET /api/senders` | Bearer | List senders with counts |
| `GET /api/stats` | None | Inbox statistics |
| `GET /api/timeline` | Bearer | Daily email volume trends |
| `POST /api/keys` | Bearer | Create API key |
| `POST /gmail/fetch` | Bearer | Manual Gmail fetch |
| `GET /demo/sanitize` | None | Public security demo |
| `GET /health` | None | Health check |

## Deployment

```bash
# Deploy to server (pull + restart)
bash deploy.sh
```

Requires: nginx, systemd service, Let's Encrypt SSL, `.env` on server.

## License

[MIT](LICENSE)
