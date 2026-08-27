# Akamana API Reference

Base URL: `/api/v1`
Authentication: `Authorization: Bearer <token>` for all protected endpoints. The bearer token may be either a **login JWT** (from `POST /auth/login`) or an **API token** (`ezk_…`, minted on the API Tokens page). API tokens are gated by fine-grained scopes (`tls:issue`, `tls:read`, `ssh:issue`, `ssh:sign`, `ssh:read`, `ca:read`) and carry the sentinel role `token`, so they can only reach endpoints that explicitly accept their scope.

Machine-readable spec: `GET /api/v1/openapi.json` (OpenAPI 3.1, public). Committed copy: `docs/openapi.yaml`.

## Public endpoints
- `GET /health`
- `GET /openapi.json` OpenAPI 3.1 spec
- `GET /branding` — app title and which sign-in options this deployment offers
  (`{app_title, auth_mode, passkeys_enabled, password_reset_enabled, require_mfa}`)
- `POST /auth/login` — returns **either** a `TokenResponse` **or** an MFA challenge
  (`{mfa_required: true, mfa_setup_required, mfa_token, expires_in_seconds, methods[], username}`).
  429 once 8 failures accumulate for the username or source IP inside 15 minutes.
- `GET /certificates/root`
- `GET /certificates/root/download/{platform}` (`windows|macos|linux|ios|android`)
- `GET /crl/{root_id}.crl` — signed X.509 CRL (DER), served at the **site root** (not under
  `/api/v1`); this is the CRL Distribution Point URL embedded in issued certificates

## Sign-in steps (public — each carries its own credential)
- `POST /auth/login/mfa` `{mfa_token, code}` — `code` is a 6-digit TOTP code or an
  `XXXXX-XXXXX` recovery code. Returns a `TokenResponse`.
- `POST /auth/login/mfa/enroll/start` `{mfa_token}` — only when `REQUIRE_MFA=true` and the
  account has no factor. Returns `{secret, otpauth_uri, qr_data_url, digits, period_seconds}`.
- `POST /auth/login/mfa/enroll/finish` `{mfa_token, code}` — confirms enrollment and returns
  the session **plus** `recovery_codes[]` (shown once).
- `POST /auth/passkey/login/start` `{username}` → `{challenge_id, options}` (WebAuthn
  `RequestChallengeResponse`; base64url fields must be decoded to `ArrayBuffer`).
- `POST /auth/passkey/login/finish` `{challenge_id, credential}` → `TokenResponse`.
- `POST /auth/password-reset/request` `{identifier}` — username or email. Always answers
  202-style `{status:"accepted", message}`, whether or not the account exists.
- `POST /auth/password-reset/confirm` `{token, new_password}` — token is single-use and
  expires after 60 minutes.

## Second factors (authenticated, human users only)
- `GET /mfa/status` — `{totp_enabled, totp_enrollment_pending, recovery_codes_remaining,
  passkeys_supported, passkeys[], require_mfa, email}`
- `POST /mfa/totp/setup` — mints an unconfirmed secret; returns the otpauth URI and an
  SVG QR code as a `data:` URL
- `POST /mfa/totp/confirm` `{code}` → `{status:"enabled", recovery_codes[]}`
- `POST /mfa/totp/disable` `{password}` — re-authenticates, then clears the secret and codes
- `POST /mfa/recovery-codes` — replaces the whole set, returns the new codes
- `GET /mfa/passkeys` · `POST /mfa/passkeys` `{name}` → `{challenge_id, options}`
- `POST /mfa/passkeys/finish` `{challenge_id, name, credential}`
- `DELETE /mfa/passkeys/{id}`

## User administration (full_admin)
- `PATCH /users/{id}/email` `{email}` — empty string clears it
- `POST /users/{id}/reset-link` — issues a one-time reset link without needing SMTP;
  returns `{username, path, url, expires_at, valid_minutes}` (`url` is null when the
  **Public base URL** setting is empty — prefix `path` with your own origin)

## API tokens
- `GET /tokens` list tokens (full_admin: all; others: own; human users only)
- `POST /tokens` create token `{name, comment?, scopes[], expires_in_days?}` — plaintext returned once
- `GET /tokens/scopes` scopes the current user may grant
- `POST /tokens/{id}/revoke`
- `DELETE /tokens/{id}`

## SSH certificates (CA-signed)
- `GET /ssh/cas` list SSH User/Host CA public keys (scope `ca:read`)
- `GET /ssh/cas/{id}/public` download a CA public key (`text/plain`)
- `POST /ssh/cas/{id}/rotate` rotate a CA (full_admin)
- `POST /ssh/certificates` sign a certificate (scope `ssh:sign`) — source: `generate` | `ssh_key_id` | `public_key`
- `GET /ssh/certificates?limit=&offset=` list issued certificates (scope `ssh:read`)
- `GET /ssh/certificates/{id}` certificate detail (scope `ssh:read`)
- `POST /ssh/certificates/{id}/revoke`
- `DELETE /ssh/certificates/{id}`

## Certificates
- `POST /certificates/root` create organization + root CA (+ optional intermediate)
- `POST /certificates/root/import` import an existing root CA
- `GET /certificates/root/{id}` · `DELETE /certificates/root/{id}`
- `POST /certificates/root/{id}/renew` · `POST /certificates/root/{id}/revoke`
- `POST /certificates/intermediate` create intermediate CA under an existing root
- `GET /certificates/tree` TLS hierarchy (root/intermediate/leaf)
- `GET /certificates/tls?limit=&offset=` list TLS certs (default `limit=200`, max `1000`)
- `POST /certificates/tls/import` import existing TLS certificate (+ optional private key)
- `GET /certificates/ssh?limit=&offset=` list SSH certs (default `limit=200`, max `1000`)
- `GET /crypto/options` configurable TLS/SSH options (ciphers, key lengths)
- `GET /certificates/tls/{id}`
- `GET /certificates/ssh/{id}`
- `DELETE /certificates/tls/{id}`
- `DELETE /certificates/ssh/{id}`
- `POST /keys/tls`
- `POST /keys/tls/renew`
- `POST /keys/ssh`
- `POST /keys/ssh/revoke/{id}`
- `POST /crl/revoke`
- `GET /crl`

## Machines
- `POST /machines`
- `GET /machines?limit=&offset=` list machines (default `limit=200`, max `1000`)

## Users and roles
- `GET /users`
- `POST /users`
- `PATCH /users/{id}/role`
- `POST /users/{id}/password` reset user password (admin)
- `DELETE /users/{id}` delete user (admin)
- `GET /users/me`
- `POST /users/me/password`
- `POST /users/me/picture`
- `DELETE /users/me/picture`

## Settings
- `GET /settings/defaults`
- `PUT /settings/defaults`
- `GET /settings/notifications`
- `PUT /settings/notifications`
- `GET /settings/siem`
- `PUT /settings/siem`
- `GET /settings/machine-monitor`
- `PUT /settings/machine-monitor`

## Backups (full_admin — see `backup_and_restore.md`)
- `GET /backup/export` download a fresh dump (encrypted per settings)
- `POST /backup/import` upload & restore a dump (`.sql` / `.ezbak`)
- `POST /backup/run` run a backup now · `GET /backup/list` local backups
- `POST /backup/restore` restore from a local backup file
- `GET|POST /backup/recipients` · `DELETE /backup/recipients/{id}` envelope recipients
- `GET|PUT /settings/backup` schedule/retention/encryption
- `GET|PUT /settings/backup/remote` · `POST /backup/remote/test` off-box destination

## CRL & root-page publishing (tls_admin/full_admin)
- `GET|PUT /settings/crl/remote` · `POST /crl/remote/test` · `POST /crl/publish`
- `GET|PUT /settings/deploy-html/remote` · `POST /deploy-html/remote/test`
- `GET /deploy-html/preview` · `POST /deploy-html/publish` root-CA install page

## Logs
- `GET /logs/actions?actor=&action=&limit=&offset=`
- `GET /logs/access?actor=&path=&limit=&offset=`
- `GET /logs/security?event_type=&source_ip=&limit=&offset=`

Paged list endpoints (`/certificates/tls`, `/certificates/ssh`, `/machines`, `/logs/*`) return:
```json
{"items": [], "total": 0, "limit": 200, "offset": 0}
```

## Network helper
- `GET /network/resolve?hostname=...`
- `GET /network/resolve?ip=...`

## Error model
```json
{"error": "validation failed: ..."}
```
