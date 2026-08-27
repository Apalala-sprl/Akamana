# Akamana Database Tables

> Updated 2026-08-08 from migrations `001` … `022`. Column lists show the current
> effective schema (base table + later `ALTER`s). All secrets are stored encrypted
> (`*_enc` columns, AES-256-GCM under `KEY_ENCRYPTION_KEY_B64`).

## Identity & access

### users
- `id CHAR(36)` PK · `username VARCHAR(64)` unique · `password_hash VARCHAR(255)` (Argon2)
- `role VARCHAR(32)`: `full_admin`, `tls_admin`, `ssh_admin`, `auditor`
- `email VARCHAR(255)` nullable (022) — required for self-service password reset
- `totp_secret_enc TEXT` nullable (022) — base32 TOTP secret, AES-256-GCM encrypted
- `totp_enabled BOOLEAN` · `totp_confirmed_at DATETIME` (022) — a secret is written at
  enrollment but only counts once a code has confirmed it
- `created_at`, `updated_at DATETIME`

### user_profiles
- `user_id CHAR(36)` PK/FK users · `picture_data_url MEDIUMTEXT` · `updated_at`

### password_reset_tokens (022)
- `id CHAR(36)` PK · `user_id CHAR(36)` (indexed) · `token_hash CHAR(64)` unique (SHA-256)
- `created_at`, `expires_at` (60 min), `used_at` nullable — single-use
- `created_by VARCHAR(64)` (`self-service` or the admin who issued the link) · `requested_ip`

### user_recovery_codes (022)
- `id CHAR(36)` PK · `user_id CHAR(36)` (indexed) · `code_hash CHAR(64)` (SHA-256 of the
  normalized code) · `created_at` · `used_at` nullable — single-use
- Ten rows are minted per TOTP enrollment; regenerating replaces the whole set.

### webauthn_credentials (022)
- `id CHAR(36)` PK · `user_id CHAR(36)` (indexed) · `name VARCHAR(128)` (user-chosen label)
- `credential_id VARCHAR(512)` (base64url) · `passkey_json TEXT` (serialized webauthn-rs `Passkey`)
- `created_at` · `last_used_at` — the signature counter inside `passkey_json` is updated on use

### webauthn_challenges (022)
- `id CHAR(36)` PK · `username VARCHAR(64)` · `purpose VARCHAR(32)` (`register` | `authenticate`)
- `state_json TEXT` · `created_at` · `expires_at` (5 min)
- Single-use: the row is deleted when consumed, and must match both username and purpose.

### login_attempts (022)
- `id CHAR(36)` PK · `username VARCHAR(64)` · `source_ip VARCHAR(64)` · `success BOOLEAN` · `created_at`
- Indexed on `(username, created_at)` and `(source_ip, created_at)`; 8 failures on either
  key within 15 minutes locks sign-in out with a 429.

### api_tokens (migration 018)
- `id CHAR(36)` PK · `name`, `comment` · `token_prefix VARCHAR(20)` (indexed)
- `token_hash CHAR(64)` unique (SHA-256 of the full `ezk_…` token)
- `scopes VARCHAR(512)` (`tls:issue`, `tls:read`, `ssh:issue`, `ssh:sign`, `ssh:read`, `ca:read`)
- `owner_user_id`, `owner_username`, `created_by`, `created_at`
- `expires_at`, `last_used_at`, `last_used_ip`, `is_revoked`, `revoked_at`

## PKI — TLS

### root_ca
Multi-row since migration 006 (one row per organization root; historical fixed `id=1`
is only the bootstrap default).
- `id INT` PK · `common_name` · `organization` · `description`
- `cert_pem TEXT` · `private_key_enc MEDIUMTEXT` · `not_before`, `not_after`, `created_at`
- revocation (007): `is_revoked`, `revoked_at`, `revoked_reason`
- crypto params (009): `cipher`, `key_length`
- subject DN (014): `country`, `state`, `locality`, `org_unit` — inherited by issued certs

### tls_keys
- `id CHAR(36)` PK · `machine_id CHAR(36)` FK machines (nullable since 008)
- `common_name`, `serial_hex` unique, `cert_pem`, `private_key_enc`
- `valid_from`, `valid_to`, `created_by`, `created_at`
- revocation: `is_revoked`, `revoked_at`, `revoked_reason`
- hierarchy (002/006): `cert_level` (`root`/`intermediate`/`leaf`), `parent_cert_id`, `root_ca_id`
- crypto: `cipher`, `key_length`, `usages_json`
- export control (004): `allow_private_key_export`
- lifecycle (011): `auto_renew`, `renew_days_before`, `last_status`, `last_status_at`
- SAN/EKU (017): `sans_json JSON`, `eku_purpose VARCHAR(16)` (`server`/`client`/`both`)

### crl_entries
- `id CHAR(36)` PK · `tls_key_id` FK · `serial_hex` · `revoked_at` · `reason`
- `created_by`, `created_at` — source of the signed DER CRL served at `/crl/<root_id>.crl`

## PKI — SSH

### ssh_keys
- `id CHAR(36)` PK · `machine_id` FK · `algorithm` · `public_key` · `private_key_enc`
- `fingerprint_sha256` · `valid_from`, `valid_to` · `created_by`, `created_at`
- `is_revoked`, `revoked_at`, `revoked_reason`
- (002): `ssh_username`, `machine_name`, `cipher`, `key_length`
- (004): `allow_private_key_export`

### ssh_cas (019)
- `id CHAR(36)` PK · `ca_type VARCHAR(8)` (`user`/`host`) · `name` · `algorithm`
- `public_key`, `private_key_enc`, `fingerprint_sha256`, `is_active`, `created_by`, `created_at`

### ssh_certificates (019)
- `id CHAR(36)` PK · `ca_id`, `ca_type`, `cert_type VARCHAR(8)`
- `serial BIGINT UNSIGNED` · `key_id` · `principals TEXT` · `critical_options`, `extensions`
- `subject_public_key`, `certificate` (OpenSSH cert), `private_key_enc` (when generated),
  `allow_private_key_export`, `fingerprint_sha256`
- `machine_id`, `ssh_key_id` (optional links) · `valid_from`, `valid_to`
- `created_by`, `created_at`, `is_revoked`, `revoked_at`, `revoked_reason`

## Inventory, monitoring & deployment

### machines
- `id CHAR(36)` PK · `hostname` + `ip_address` (unique pair) · `owner` · `environment`
- `created_at`, `updated_at`
- (011): `alert_email`, `test_url` · (012): `monitor_only` · (013): `os_type`

### machine_monitor_ports (010)
- `id CHAR(36)` PK · `machine_id` FK · `port` · `monitor_enabled`, `check_tls`
- scan results: `last_checked_at`, `last_status`, `last_error`, `cert_not_before`,
  `cert_not_after`, `cert_subject`, `cert_issuer`, `cert_serial_hex`,
  `cert_chain_json`, `cert_diagnostic`
- (015): `sni_host` — unique key `(machine_id, port, sni_host)` (several vhosts per port)
- (016): `tls_support_json` (protocol support probe)

### applications (011)
- `id CHAR(36)` PK · `slug` unique · `name` · default paths (`default_cert_path`,
  `default_key_path`, `default_chain_path`, `default_config_dir`),
  `default_reload_command`, `config_example`, `notes`, `is_builtin`
- (021): `expected_cert_format VARCHAR(16)`

### credentials (011) — full_admin only
- `id CHAR(36)` PK · `name` · `kind` (ssh key / password / API token) · `username`
- `secret_enc`, `ssh_private_key_enc`, `ssh_passphrase_enc` — never returned by the API
- `notes`, `created_by`, `created_at`, `updated_at`

### host_credentials (011)
- link machine ↔ credential: `protocol` (default `ssh`), `port`, `is_default`
- last check: `last_check_status`, `last_check_at`, `last_check_message`

### host_applications (011)
- deployment target: `machine_id` + `application_id` + optional `tls_key_id`
- per-location `cert_path`, `key_path`, `chain_path`, `reload_command`, `credential_id`
- `auto_deploy`, `last_deploy_status`, `last_deploy_at`

### deployment_jobs (011/012)
- `id CHAR(36)` PK · `host_application_id` (nullable) · `tls_key_id` ·
  `certbot_config_id` · `job_type` (`deploy`/certbot) · `trigger_source` (`manual`/auto)
- `status`, `started_at`, `finished_at`, `created_by`, `created_at`

### deployment_journal (011)
- `id CHAR(36)` PK · `job_id` FK · `step` · `status` · `message` · `created_at`

### certbot_configs (012)
- `id CHAR(36)` PK · `machine_id` FK · `credential_id` · `domains` · `email`
- `challenge` (`webroot`/`standalone`/`nginx`/`apache`/`dns`), `webroot_path`,
  `dns_plugin`, `extra_args`, `staging`
- results: `live_cert_path`, `live_key_path`, `last_run_status`, `last_run_at`, `last_not_after`
- `auto_renew`, `renew_days_before`, `created_by`, `created_at`, `updated_at`

## Backups

### backup_recipients (020)
- `id CHAR(36)` PK · `name` · `key_type` · `public_key_pem` · `fingerprint_sha256`
- `is_active`, `created_by`, `created_at` — envelope-mode recipients for `.ezbak`
  encrypted backups (see `backup_and_restore.md`)

## Settings & telemetry

### settings
- `key_name VARCHAR(128)` PK · `value_text TEXT` · `updated_by` · `updated_at`
- holds defaults, owner/environment lists, notification/SIEM/monitor settings and
  the `backup_*` / remote-destination keys

### audit_logs
- `id CHAR(36)` PK · `actor` · `action` · `target_type` · `target_id` · `details_json` · `created_at`

### access_logs
- `id CHAR(36)` PK (= request id) · `actor` · `source_ip` · `method` · `path`
- `status_code` · `details_json` · `created_at` — one row per `/api/` request

### security_events (005)
- `id CHAR(36)` PK · `event_type` (`bruteforce_login`, `auth_attack`, …)
- `severity` (`high`/`medium`/`low`) · `source_ip` · `actor` · `details_json` · `created_at`

### notification_events (003)
- `id CHAR(36)` PK · `cert_type` · `cert_id` · `channel` · `recipient` · `status`
- `payload_json` · `sent_at` — expiry-alert delivery status
