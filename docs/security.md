# Akamana Security Notes

> Updated 2026-07-15 to match the implemented system (roles, API tokens, CI, known gaps).

## Security by design controls
- Input validation via `validator` on all API payload DTOs.
- Short-lived JWT bearer tokens (`JWT_EXP_MINUTES`, default 30); optional OIDC (RS256/JWKS).
- Scoped API tokens (`ezk_…`) stored as SHA-256 hashes; scopes capped by the creating
  user's role; sentinel role `token` blocks every role-gated endpoint.
- Role-based authorization checks per handler (`full_admin`, `tls_admin`, `ssh_admin`, `auditor`).
- Password hashing using Argon2; bootstrap admin password policy enforced at startup
  (≥ 15 chars, known defaults rejected, process refuses to start).
- Encryption-at-rest for private keys and credential secrets (`AES-256-GCM`, KEK from
  `KEY_ENCRYPTION_KEY_B64`).
- Encrypted backups (`.ezbak`: Argon2id passphrase or RSA envelope) — see `backup_and_restore.md`.
- Centralized audit trail for sensitive actions + access log for every `/api/` request.
- Default-deny auth middleware for `/api/` paths (small explicit public allow-list).
- Security response headers on every response (HSTS, CSP, X-Frame-Options DENY,
  nosniff, Referrer-Policy, Permissions-Policy).
- `x-forwarded-for` honored only from `TRUSTED_PROXY_IPS`; CORS locked to
  `ALLOWED_ORIGINS` (a `*` value logs a loud warning).
- SIEM webhook integration for security alerts.
- Brute-force and auth-attack detection from access telemetry (`security_monitor`).

## OWASP Top 10 mapping
- A01 Broken Access Control: per-handler role checks + scope-gated API tokens.
- A02 Cryptographic Failures: Argon2, AES-GCM, signed certs, encrypted backups.
- A03 Injection: SQLx prepared statements only; shell-quoted paths in SSH deploys.
- A04 Insecure Design: documented threat assumptions and least privilege.
- A05 Security Misconfiguration: `.env` template with required hardening flags.
- A06 Vulnerable Components: `cargo audit` + SonarQube scan in Gitea Actions CI.
- A07 Identification/Auth Failures: token authentication, optional OIDC, TOTP
  second factor, WebAuthn passkeys, and login lockout (see "Sign-in hardening").
- A08 Integrity Failures: signed certificates and immutable audit entries.
- A09 Logging/Monitoring Failures: audit/access/security logs and SIEM webhook alerts.
- A10 SSRF: no outbound user-provided URL fetching in business endpoints
  (outbound SSH/SFTP targets are admin-configured; network scan is RFC1918-only).

## Sign-in hardening
- **Two-factor (TOTP)** — RFC 6238, SHA-1, 6 digits, 30 s step, ±1 step of drift
  tolerance (`mfa.rs`). The secret is stored AES-256-GCM-encrypted in
  `users.totp_secret_enc` and only becomes active once a code proves the
  authenticator holds it. Enrollment also mints 10 single-use recovery codes,
  stored as SHA-256 hashes in `user_recovery_codes` and burned with a
  conditional `UPDATE` so a code can't be replayed by a concurrent request.
- **`REQUIRE_MFA=true`** — an account with no factor cannot complete a sign-in:
  `/auth/login` returns a short-lived enrollment token (audience `akamana-mfa`,
  10 min) instead of a session, and the session is only issued once TOTP is
  confirmed. That audience is deliberately not `akamana-api`, so a half-finished
  login can never be replayed against a real endpoint.
- **Passkeys (WebAuthn)** — opt-in via `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN`
  (`passkey.rs`, webauthn-rs). Pending ceremony state lives in
  `webauthn_challenges`: single-use rows with a 5-minute TTL, matched on both
  username and purpose so a registration challenge can't be replayed into the
  authentication ceremony. Signature counters are persisted on each use.
- **Login lockout** — every attempt is recorded in `login_attempts`; 8 failures
  for a username *or* a source IP inside 15 minutes returns 429. A successful
  sign-in clears only the username counter, never the IP counter (otherwise one
  valid account would reset the limit between password-spraying rounds).
- **Password reset** — a 32-byte random token, stored only as SHA-256, valid
  60 minutes, single-use (burned with a conditional `UPDATE` before the password
  is written). `/auth/password-reset/request` answers identically whether or not
  the account exists, so it cannot be used to enumerate users.
- **Timing** — an unknown username still pays for one Argon2 hash
  (`spend_password_verification_time`), so "no such user" and "wrong password"
  don't differ measurably.

## Known gaps (tracked in REQUIREMENTS.md §4)
- Outbound SSH/SFTP (`deploy.rs`, `backup_remote.rs`) accepts **any host key**
  (no pinning) — lab-acceptable only.
- No automated test suite.

## Hardening checklist
- Replace all default secrets before first deployment.
- Restrict network access to API and MariaDB.
- Enable TLS termination at reverse proxy.
- Set `ALLOWED_ORIGINS` explicitly (never `*` in production) and `TRUSTED_PROXY_IPS`
  when behind a proxy.
- Configure `siem_webhook_url` in settings to forward alerts.
- Rotate JWT secret and key encryption key periodically; expire and rotate API tokens.
- Enable encrypted scheduled backups and store `KEY_ENCRYPTION_KEY_B64` separately
  from database backups.
- Enforce OS patching and container scanning.
