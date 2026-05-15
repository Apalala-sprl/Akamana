# EZKey Functions Catalog

## backend/src/main.rs
- `main()`: startup, migration, root CA bootstrap, HTTP server.
- `auth_guard(...)`: protects API bearer routes and writes `access_logs`.
- `log_access(...)`: stores request metadata (date/time, IP, actor, path, status).

## backend/src/notifier.rs
- `start(...)`: starts periodic certificate expiration notifier.
- `run_once(...)`: computes expiring TLS/SSH certs and sends webhook alerts.

## backend/src/security_monitor.rs
- `start(...)`: starts periodic security monitor.
- `run_once(...)`: detects brute-force/auth attack patterns from `access_logs`.
- `send_to_siem(...)`: sends JSON alert payload to SIEM webhook.
- `insert_security_event(...)`: persists alert in `security_events`.

## backend/src/db.rs
- `connect(...)`: MariaDB connection pool.
- `run_migrations(...)`: runs schema migrations (`001_init.sql` ... `005_siem_security.sql`) statement-by-statement.
- `bootstrap_admin(...)`: creates bootstrap admin.

## backend/src/auth.rs
- local password verification, JWT creation and decode, optional OIDC decode.

## backend/src/crypto.rs
- root CA lifecycle
- organization root CA creation (`create_root_ca`)
- TLS certificate issuance
- SSH keypair generation
- AES-256-GCM secret encryption at rest

## backend/src/routes/api.rs
- Auth: `login`
- Machine inventory: `create_machine`, `list_machines`
- TLS/SSH key lifecycle: generate/renew/revoke/delete/detail/list
- Hierarchy view: `certificate_tree`
- CRL management: `revoke_tls`, `list_crl`
- Users and roles: list/create/update role
- Profile: `get_me`, password change, profile picture upload/delete
- Settings: get/save defaults
- Settings: get/save notifications
- Settings: get/save SIEM
- Logs: action logs and access logs with filters
- Logs: security logs with filters
- DNS/IP assist: `resolve_network_info`
- Root certificate download: `download_root_ca`
- Root/organization management: `create_organization_root`, `create_intermediate_cert`
- Dynamic crypto options provider: `get_crypto_options`
- Audit writer: `audit`
