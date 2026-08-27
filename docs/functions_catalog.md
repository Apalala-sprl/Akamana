# Akamana Functions Catalog

> Updated 2026-07-15 — covers all 16 modules of `backend/src/`.

## backend/src/main.rs
- `main()`: startup (connect → migrations → bootstrap admin → seed applications →
  ensure root CA → ensure SSH CAs), spawns the five background tasks, HTTP server.
- `security_headers_layer(...)`: HSTS/CSP/XFO/nosniff/referrer/permissions headers.
- `auth_guard(...)`: request-id, trusted-proxy client IP, public allow-list, bearer
  authentication, writes `access_logs` for every `/api/` request.
- `log_access(...)`: stores request metadata (date/time, IP, actor, path, status).

## backend/src/config.rs
- `Config::from_env()`: env-only config (dotenvy); bootstrap-password policy.
- `is_trusted_proxy(...)` / `resolved_client_ip(...)`: `x-forwarded-for` handling.

## backend/src/db.rs
- `connect(...)`: MariaDB connection pool.
- `run_migrations(...)`: runs schema migrations `001_init.sql` … `021_app_cert_format.sql`
  statement-by-statement (naive `;` split — keep migrations idempotent).
- `bootstrap_admin(...)`: creates bootstrap admin.
- `seed_applications(...)`: seeds the application catalog (nginx, Apache, …).

## backend/src/auth.rs
- local password verification (Argon2), JWT creation/decode (HS256), OIDC decode
  (RS256 against cached JWKS via `JwksManager`), role-claim mapping.
- `AuthenticatedUser` extractor (`FromRequestParts`); `has_scope(...)`.
- `authenticate(...)`: resolves login JWTs **and** `ezk_…` API tokens (SHA-256 lookup).
- `load_local_user(...)` / `verify_password(...)`: one round trip for identity,
  credential and second-factor state. `spend_password_verification_time(...)` burns an
  equivalent Argon2 hash for an unknown username so the two cases time alike.
- `create_mfa_token` / `decode_mfa_token`: the short-lived half-login token
  (audience `akamana-mfa`, never `akamana-api`), purpose `mfa` or `mfa-setup`.
- `enforce_login_rate_limit` / `record_login_attempt` / `clear_login_failures`: the
  `login_attempts` lockout (8 failures per username or source IP in 15 minutes).

## backend/src/mfa.rs
- RFC 4648 base32 (`base32_encode` / `base32_decode`, tolerant of spaces/dashes/padding).
- RFC 6238 TOTP over OpenSSL HMAC-SHA1: `generate_totp_secret`, `totp_code_at`,
  `verify_totp` (±1 step of drift, constant-time compare, every step evaluated).
- `otpauth_uri(...)` for the QR payload; `generate_recovery_codes` /
  `normalize_recovery_code`.
- Carries the only unit tests in the tree (RFC 6238 vectors + base32 round trip).

## backend/src/passkey.rs
- `is_enabled()` / `instance()`: builds the webauthn-rs relying party from
  `WEBAUTHN_RP_ID` + `WEBAUTHN_ORIGIN`; returns a `Validation` error with setup
  instructions when the feature is off.
- `ceremony_error(...)`: maps a `WebauthnError` to `AppError::Auth`, keeping the
  library detail in the log (a cancelled prompt is not a 500).

## backend/src/crypto.rs
- root CA lifecycle (`ensure_root_ca`, `create_root_ca`, renewal, import).
- intermediate & leaf TLS issuance with SAN (DNS/IP) and EKU purpose (server/client/both).
- CRL generation (`generate_crl_der`) — served at `/crl/<root_id>.crl`.
- SSH keypair generation; SSH CA bootstrap (`ensure_ssh_cas`) and OpenSSH certificate
  signing (`sign_ssh_certificate`, `ssh-key` crate).
- API-token generation/hashing (`generate_api_token`, `hash_api_token` — SHA-256).
- AES-256-GCM secret encryption at rest (`encrypt_secret` / `decrypt_secret`).

## backend/src/routes/api.rs
All HTTP handlers and the router (~5 700 lines): auth/login, root & intermediate CA,
TLS/SSH key lifecycle, certificate tree, CRL + CRL publishing, machines & monitoring,
network scan/resolve, applications/credentials/host links, deployment + journal,
certbot configs, API tokens, SSH CAs & certificates, users/profile, settings
(defaults/notifications/SIEM/machine-monitor/backup/remotes), logs, backups,
deploy-HTML publishing, addons/integration plans. RBAC helpers: `can_manage_tls`,
`can_manage_ssh`, `can_audit`, `can_manage_machines`, `authorize` (token scopes),
`require_human`. Audit writer: `audit`.

## backend/src/models.rs
Request/response DTOs, `validator`-annotated.

## backend/src/errors.rs
`AppError` / `AppResult` (clippy denies `unwrap`/`expect` — always propagate).

## backend/src/notifier.rs
- `start(...)`: periodic certificate expiration notifier.
- `run_once(...)`: computes expiring TLS/SSH certs, sends alert **emails** (lettre/SMTP)
  and records `notification_events`.

## backend/src/machine_monitor.rs
- `start(...)` / `run_once(...)`: TLS scans of monitored host/port/SNI rows
  (`machine_monitor_ports`), records expiry/subject/issuer/chain/TLS support,
  alert emails with reachability cross-check.

## backend/src/security_monitor.rs
- `start(...)` / `run_once(...)`: detects brute-force/auth-attack patterns from `access_logs`.
- `send_to_siem(...)`: JSON alert payload to SIEM webhook.
- `insert_security_event(...)`: persists alert in `security_events`.

## backend/src/lifecycle.rs
- `start(...)`: hourly auto-renew loop.
- `run_auto_renew(...)`: re-issues leaf certs within `renew_days_before` (preserving
  SAN/EKU/chain), re-points deployment targets, re-deploys auto-deploy targets, and
  re-runs due certbot configs.

## backend/src/deploy.rs
- outbound SSH deployment engine (russh): pre-flight `check`, cert/key/chain push
  (shell-quoted, `umask 077`), reload command, per-step journaling, failure emails.
- `run_certbot(...)`: remote `certbot certonly` over SSH, records expiry.
- ⚠️ accepts any SSH host key (no pinning yet).

## backend/src/backup.rs
- `export_dump(...)` / `import_dump(...)`: `mariadb-dump` / `mariadb` client.
- `run_backup(...)`: skip-if-unchanged signature (log tables excluded), retention,
  local write + optional remote push. `start(...)`: scheduler per `backup_frequency_hours`.
- `list_backups()`: local backup inventory.

## backend/src/backup_crypto.rs
- `.ezbak` container: gzip + AES-256-GCM; Argon2id passphrase mode or RSA envelope
  mode (DEK wrapped per recipient); `is_encrypted(...)` detection.

## backend/src/backup_remote.rs
- off-box destinations: mounted **path** or **SFTP** (russh-sftp), remote retention,
  `test_remote(...)`, `push_to_remote(...)` — shared by backups, CRL publishing and
  deploy-HTML publishing. ⚠️ no SFTP host-key pinning yet.

## backend/src/addons.rs
- loads declarative YAML/JSON addon definitions from `ADDONS_DIR` at request time and
  turns them into integration plans.
