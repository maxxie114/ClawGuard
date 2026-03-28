# ClawGuard MVP — Closed Beta

## Overview
Admin-only management. No self-signup. Beta users added manually by admin.
HTTPS via Let's Encrypt + nginx on port 443, API on port 8000.
Domain: claw-guard.tech

---

## Phase 1: Backend Auth & User Management
- [x] 1.1 Add `users` table (id, email, password_hash, display_name, role, created_at)
- [x] 1.2 Add `api_keys` table (id, user_id, key_hash, name, prefix, created_at, last_used_at, is_revoked)
- [x] 1.3 Add `user_gmail_accounts` table (id, user_id, gmail_email, token_json_encrypted, connected_at)
- [x] 1.4 Admin user auto-created on startup from .env (CLAWGUARD_ADMIN_EMAIL, CLAWGUARD_ADMIN_PASSWORD)
- [x] 1.5 Password hashing with bcrypt
- [x] 1.6 JWT auth (access token 1h, refresh token 7d) — replaces ephemeral UUID tokens
- [x] 1.7 Auth endpoints: POST /auth/login, POST /auth/refresh, POST /auth/logout
- [x] 1.8 Admin endpoints: GET/POST/DELETE /admin/users (add/list/remove beta users)
- [x] 1.9 User endpoints: GET/POST/DELETE /api/keys (generate, list, revoke API keys)
- [x] 1.10 API key auth: `Authorization: Bearer cg_xxxxx` resolves to user — works alongside JWT

## Phase 2: Per-User Gmail OAuth
- [ ] 2.1 Upload Google OAuth credentials JSON via admin UI (stored on server, not in git)
- [x] 2.2 Gmail OAuth flow stores token per-user in `user_gmail_accounts` (encrypted with Fernet)
- [x] 2.3 Each user connects their own Gmail(s) from their dashboard
- [x] 2.4 Gmail fetch scoped to user — events linked to user_id
- [x] 2.5 Auto-fetch all connected accounts via cron (POST /gmail/fetch-all, secured with CLAWGUARD_CRON_SECRET)
- [ ] 2.6 Admin can see all accounts; regular users see only their own

## Phase 3: Frontend — Landing Page
- [x] 3.1 Landing page at `/` — hero, features, how it works, CTA to login
- [x] 3.2 Professional design for claw-guard.tech (not monospace hacker aesthetic)
- [x] 3.3 Navigation: Home, Demo, Login
- [x] 3.4 Footer with contact email (support@qubemc.com), copyright (QubeMC LLC)

## Phase 4: Frontend — Login & Dashboard
- [x] 4.1 Login page at `/login` (email + password, no signup link — closed beta)
- [x] 4.2 Dashboard at `/dashboard` — sidebar nav: Inbox, API Keys, Gmail, Demo
- [x] 4.3 Inbox view: event list with filters (existing functionality, scoped to user)
- [x] 4.4 API Keys page: create, list (prefix only), revoke
- [x] 4.5 Gmail page: connect/disconnect accounts, fetch emails, status
- [x] 4.6 Admin panel at `/admin` (admin-only): add/remove beta users, set temporary passwords

## Phase 5: Security Demo (Public)
- [x] 5.1 Public demo page at `/demo` — no login required
- [x] 5.2 Keep the 8 test injection vectors
- [x] 5.3 Side-by-side raw vs sanitized with risk score visualization
- [x] 5.4 Rate limit demo endpoint (10 req/min for anonymous)

## Phase 6: Nginx + Domain + HTTPS
- [x] 6.1 nginx config: port 80 → proxy to FastAPI:8000
- [x] 6.2 Server name: claw-guard.tech
- [x] 6.3 HTTPS via Let's Encrypt (certbot auto-renewal)
- [x] 6.4 HTTP → HTTPS redirect
- [x] 6.5 Deploy script updated (preserves certbot SSL config)

## Phase 7: Agent Integration
- [x] 7.1 clawguard-skill updated for new auth (API keys, JWT, HTTPS)
- [x] 7.2 Query script supports API key auth (`cg_` prefix)
- [x] 7.3 Email deduplication (prevents re-storing same email on repeated fetches)

## Bugs & Improvements (TODO — deferred)
- [ ] Stricter login rate limiting (5/min + exponential backoff or temporary account lockout)
- [ ] Use non-guessable admin email (GitHub username + landing page domain make it easy to guess)
- [ ] Upload Google OAuth credentials JSON via admin UI (2.1)
- [ ] Admin sees all Gmail accounts; regular users see only their own (2.6)

## Google OAuth App Status
- Currently in "Testing" mode — only manually added test users can connect Gmail
- Each beta user's Gmail must be added as a test user in GCP Console
- To allow any Gmail user: publish the app and pass Google verification (sensitive scope: gmail.readonly)
- For closed beta, manually adding test users in GCP is sufficient

## What's NOT in MVP (deferred to PRODUCTION_TODO.md)
- Self-signup / email verification (future: WorkOS)
- Password reset flow
- SSO/SAML
- Account deletion / data export
- Per-user webhook secrets
- CSRF tokens (mitigated by JWT in Authorization header for now)
- Google OAuth app verification (required to remove "unverified app" warning and test user limit)
