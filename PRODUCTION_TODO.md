# ClawGuard Frontend & Auth Rebuild — TODO

## Phase A: Database & Backend Auth System
> Multi-user auth with proper security. This replaces the single admin password.

- [ ] A1. Create `users` table (id, email, password_hash, display_name, created_at, email_verified, is_admin)
- [ ] A2. Create `api_keys` table (id, user_id, key_hash, name, prefix, created_at, last_used, revoked)
- [ ] A3. Create `user_gmail_accounts` table (id, user_id, email, token_json_encrypted, connected_at) — per-user Gmail tokens instead of single global file
- [ ] A4. Implement password hashing with bcrypt (never store plaintext)
- [ ] A5. Implement JWT-based auth (access token + refresh token) replacing ephemeral UUID tokens
- [ ] A6. API endpoints: `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`
- [ ] A7. API endpoints: `GET/POST/DELETE /api/keys` — generate, list, revoke API keys per user
- [ ] A8. Per-user data isolation — users only see their own events, Gmail accounts, and API keys
- [ ] A9. Rate limiting on auth endpoints (prevent brute force: 5 attempts/min on login, 3/hour on register)
- [ ] A10. Migrate existing admin password to a default admin user (backward compat for webhook ingestion)

## Phase B: New Frontend — Homepage & Layout
> Professional landing page for a production for-profit service.

- [ ] B1. New multi-page layout: landing page (`/`), dashboard (`/dashboard`), login (`/login`), register (`/register`)
- [ ] B2. Landing page: hero section explaining what ClawGuard does, feature highlights, pricing placeholder, CTA to sign up
- [ ] B3. Responsive navigation bar (logo, features link, demo link, login/signup buttons)
- [ ] B4. Footer with links, copyright, contact placeholder

## Phase C: Auth UI
> Login, registration, and account management screens.

- [ ] C1. Registration page (email, password, confirm password, display name)
- [ ] C2. Login page with error handling and rate limit feedback
- [ ] C3. Password strength validation (min 12 chars, complexity requirements)
- [ ] C4. Authenticated dashboard layout with sidebar nav (Inbox, API Keys, Gmail, Demo, Settings)
- [ ] C5. Account settings page (change password, delete account)

## Phase D: API Key Management UI
> Users generate keys to access their data programmatically.

- [ ] D1. API Keys page: list active keys (show prefix only, e.g. `cg_a8f3...`), creation date, last used
- [ ] D2. Create key flow: name the key, show full key ONCE on creation, confirm user copied it
- [ ] D3. Revoke key with confirmation dialog
- [ ] D4. API key auth works alongside JWT — `Authorization: Bearer cg_...` routes to correct user

## Phase E: Gmail Integration (Per-User)
> Each user connects their own Gmail, tokens stored per-user in DB (encrypted).

- [ ] E1. Refactor Gmail OAuth to be per-user (not global token file)
- [ ] E2. Gmail connection page in dashboard: connect/disconnect, show connected accounts
- [ ] E3. OAuth callback associates token with logged-in user
- [ ] E4. Encrypt Gmail tokens at rest in the database (Fernet symmetric encryption with server key)
- [ ] E5. Per-user email fetching and event storage (events linked to user_id)

## Phase F: Security Demo Feature
> Interactive demo of ClawGuard's defense capabilities — keep and improve the test injection panel.

- [ ] F1. Public demo page (no login required) with the 8 test injection vectors
- [ ] F2. Side-by-side before/after view showing raw vs sanitized output
- [ ] F3. Risk score visualization and flag explanations
- [ ] F4. Rate limit demo endpoint separately (prevent abuse, 10 req/min for anonymous)

## Phase G: Security Hardening
> Production readiness for handling real user email data.

- [ ] G1. CSRF protection on all state-changing endpoints
- [ ] G2. Secure cookie settings (HttpOnly, SameSite=Strict, Secure flag)
- [ ] G3. Input validation on all user-facing forms (server-side, not just client)
- [ ] G4. Add security headers (X-Content-Type-Options, X-Frame-Options, CSP, HSTS)
- [ ] G5. Audit logging — log auth events (login, failed login, key creation, Gmail connect)
- [ ] G6. Ensure all secrets (JWT secret, encryption key) come from env vars, never hardcoded

## Phase H: HTTPS & Infrastructure
> Required before handling real user credentials in production.

- [ ] H1. Set up nginx reverse proxy in front of uvicorn
- [ ] H2. Configure Let's Encrypt TLS certificates (certbot auto-renewal)
- [ ] H3. Redirect all HTTP to HTTPS
- [ ] H4. Add HSTS header once TLS is confirmed working

## Phase I: Session & Account Security
> Protect user sessions and support account recovery.

- [ ] I1. Session invalidation on password change — revoke all JWT tokens when password is updated
- [ ] I2. Forgot password / password reset flow (email-based reset link)
- [ ] I3. OAuth scope consent display — show users exactly what Gmail permissions they're granting before redirect
- [ ] I4. Per-user webhook secrets — each user gets their own webhook secret for multi-tenant ingestion

## Phase J: Account Management & Compliance
> Data rights and account lifecycle.

- [ ] J1. Account deletion — user can delete their account and all associated data
- [ ] J2. Data export — user can download all their stored events as JSON/CSV
- [ ] J3. GDPR/CCPA compliance considerations (privacy policy page, data retention controls)

## Phase Z (Future): WorkOS Integration
> Replace homegrown auth with WorkOS for enterprise-grade identity management.
> Until then, signup is open — any email can register without verification. This is intentional for the current phase.

- [ ] Z1. Integrate WorkOS AuthKit (replaces register/login/password reset flows)
- [ ] Z2. Email verification via WorkOS (no longer allow unverified signups)
- [ ] Z3. SSO/SAML support for enterprise customers
- [ ] Z4. Organization & team management via WorkOS
- [ ] Z5. Remove homegrown password hashing, JWT, and reset flows once WorkOS is live
