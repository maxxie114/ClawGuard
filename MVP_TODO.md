# ClawGuard MVP — Closed Beta

## Overview
Admin-only management. No self-signup. Beta users added manually by admin.
Homepage on port 80 (nginx), API on port 8000 (uvicorn). No HTTPS yet.
Domain: claw-guard.tech

---

## Phase 1: Backend Auth & User Management
- [ ] 1.1 Add `users` table (id, email, password_hash, display_name, role, created_at)
- [ ] 1.2 Add `api_keys` table (id, user_id, key_hash, name, prefix, created_at, last_used_at, is_revoked)
- [ ] 1.3 Add `user_gmail_accounts` table (id, user_id, gmail_email, token_json_encrypted, connected_at)
- [ ] 1.4 Admin user auto-created on startup from .env (CLAWGUARD_ADMIN_EMAIL, CLAWGUARD_ADMIN_PASSWORD)
- [ ] 1.5 Password hashing with bcrypt
- [ ] 1.6 JWT auth (access token 1h, refresh token 7d) — replaces ephemeral UUID tokens
- [ ] 1.7 Auth endpoints: POST /auth/login, POST /auth/refresh, POST /auth/logout
- [ ] 1.8 Admin endpoints: GET/POST/DELETE /admin/users (add/list/remove beta users)
- [ ] 1.9 User endpoints: GET/POST/DELETE /api/keys (generate, list, revoke API keys)
- [ ] 1.10 API key auth: `Authorization: Bearer cg_xxxxx` resolves to user — works alongside JWT

## Phase 2: Per-User Gmail OAuth
- [ ] 2.1 Upload Google OAuth credentials JSON via admin UI (stored on server, not in git)
- [ ] 2.2 Gmail OAuth flow stores token per-user in `user_gmail_accounts` (encrypted with Fernet)
- [ ] 2.3 Each user connects their own Gmail(s) from their dashboard
- [ ] 2.4 Gmail fetch scoped to user — events linked to user_id
- [ ] 2.5 Admin can see all accounts; regular users see only their own

## Phase 3: Frontend — Landing Page
- [ ] 3.1 Landing page at `/` — hero, features, how it works, CTA to login
- [ ] 3.2 Professional design for claw-guard.tech (not monospace hacker aesthetic)
- [ ] 3.3 Navigation: Home, Demo, Login
- [ ] 3.4 Footer with contact email, copyright

## Phase 4: Frontend — Login & Dashboard
- [ ] 4.1 Login page at `/login` (email + password, no signup link — closed beta)
- [ ] 4.2 Dashboard at `/dashboard` — sidebar nav: Inbox, API Keys, Gmail, Demo
- [ ] 4.3 Inbox view: event list with filters (existing functionality, scoped to user)
- [ ] 4.4 API Keys page: create, list (prefix only), revoke
- [ ] 4.5 Gmail page: connect/disconnect accounts, fetch emails, status
- [ ] 4.6 Admin panel at `/admin` (admin-only): add/remove beta users, set temporary passwords

## Phase 5: Security Demo (Public)
- [ ] 5.1 Public demo page at `/demo` — no login required
- [ ] 5.2 Keep the 8 test injection vectors
- [ ] 5.3 Side-by-side raw vs sanitized with risk score visualization
- [ ] 5.4 Rate limit demo endpoint (10 req/min for anonymous)

## Phase 6: Nginx + Domain Setup
- [ ] 6.1 nginx config: port 80 → proxy to FastAPI:8000
- [ ] 6.2 Server name: claw-guard.tech
- [ ] 6.3 Static assets served via nginx for performance
- [ ] 6.4 Deploy script updated for nginx restart

## What's NOT in MVP (deferred to PRODUCTION_TODO.md)
- Self-signup / email verification (future: WorkOS)
- HTTPS/TLS (next priority after MVP works)
- Password reset flow
- SSO/SAML
- Account deletion / data export
- Per-user webhook secrets
- CSRF tokens (mitigated by JWT in Authorization header for now)
