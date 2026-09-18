# Akamana

Akamana is an internal-lab secure key lifecycle service built with Rust, HTML, JS, CSS, and MariaDB.
It exposes a REST API with bearer token authentication (login JWT or scoped `ezk_…` API tokens) to manage:
- machine inventory (hostname, IP, owner, environment) and TLS endpoint monitoring (host → port → SNI vhost)
- an internal CA (root → intermediate → leaf) with SAN/EKU support, TLS keypairs and certificate issuance
- SSH keypairs, plus an SSH User/Host CA signing OpenSSH certificates
- CRL entries (revoked TLS certificate serials), served as a signed DER CRL and publishable off-box
- certificate deployment to hosts over SSH, auto-renew, and remote certbot
- encrypted database backups (local + off-box path/SFTP) — see `docs/backup_and_restore.md`
- audit trail

## Core stack
- Backend: Rust + Axum + SQLx + OpenSSL
- Database: MariaDB
- Frontend: classless semantic HTML + vanilla JS + minimal CSS
- Deployment: Docker / pod manifest

## Installation

One command. It checks for Docker, downloads the code, asks a few questions
(directory, port, admin account), generates strong secrets, writes the
configuration, starts the containers and waits until the app answers.

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/Apalala-sprl/Akamana/main/install.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Apalala-sprl/Akamana/main/install.ps1 | iex
```

The first run builds the image, which compiles the Rust backend: allow 10 to
20 minutes. When it finishes, the script prints the URL and the admin account.
If you did not type a password, one is generated for you and shown once — it
is also in `config/akamana.env`, which holds every secret and must be backed
up: without `KEY_ENCRYPTION_KEY_B64`, stored private keys cannot be recovered.

Running the same command again on an existing installation updates the code
and restarts; the configuration is kept.

Everything can be answered up front for unattended installs:

```bash
AKAMANA_NONINTERACTIVE=1 AKAMANA_DIR=/srv/akamana AKAMANA_HTTP_PORT=8081 AKAMANA_ADMIN_USER=admin AKAMANA_ADMIN_PASSWORD='at-least-15-characters' AKAMANA_PUBLIC_URL=https://pki.example.com   bash -c "$(curl -fsSL https://raw.githubusercontent.com/Apalala-sprl/Akamana/main/install.sh)"
```

Prefer to do it by hand? Copy `.env.example` to `config/akamana.env`, set the
four required values (`DATABASE_URL`, `JWT_SECRET`, `KEY_ENCRYPTION_KEY_B64`,
`BOOTSTRAP_ADMIN_PASSWORD` — at least 15 characters), put `AKAMANA_HOST_CONFIG_DIR`
and the MariaDB passwords in a `.env` next to `docker-compose.yml`, then
`docker compose up -d --build`.

## Configurable crypto options
- Drop a JSON file at `/opt/akamana/data/crypto_options.json` to manage available ciphers/key lengths without code changes.
- Template: `deploy/crypto_options.json.example`

## Where things live
The installer puts everything under the directory you chose (`~/akamana` by
default): `src/` (the code), `config/akamana.env` (secrets — keep it private
and backed up), `data/` (certificates, addons, backups). Compose reads the
paths and the MariaDB passwords from `src/.env`.

## Security highlights
- Argon2 password hashing
- JWT bearer token authentication
- optional OIDC mode for Keycloak-style central auth
- encrypted private keys at rest (AES-256-GCM)
- strict request validation
- audit logging
- root CA bootstrap and controlled download endpoints

## Backup & disaster recovery
- Scheduled/on-demand encrypted backups: see `docs/backup_and_restore.md`.
- A database backup alone is **not** enough to rebuild an instance: keep
  `KEY_ENCRYPTION_KEY_B64` (and `JWT_SECRET`) safe — encrypted private keys are
  unrecoverable without the key-encryption key.

## Documentation index
- `docs/ARCHITECTURE.md` — consolidated architecture (verified against the code)
- `docs/REQUIREMENTS.md` — requirements specification & gap register
- `docs/FEATURES_AND_API.md` — feature tour + full API surface
- `docs/api_reference.md`
- `docs/backup_and_restore.md`
- `docs/database_tables.md`
- `docs/functions_catalog.md`
- `docs/security.md`
- `docs/root_certificate_deployment.md`
