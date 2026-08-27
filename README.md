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
- CI/CD: Gitea Actions (`.gitea/workflows/sonarqube.yml` — Clippy + SonarQube)

## Quick start
1. Copy `.env.example` to `.env` and set strong secrets.
2. Start with Docker Compose:
   - `docker compose up -d --build`
3. Open:
   - `http://localhost:8080`
4. Login with bootstrap credentials from `.env`.

## Interactive install/update
- Run `./scripts/install_or_update.sh`
- The script asks for:
  - target path
  - runtime (`Docker root`, `Podman root`, `Podman rootless`)
  - exposed HTTP port
  - external MariaDB URL or bundled MariaDB
  - host config/data directories

## Configurable crypto options
- Drop a JSON file at `/opt/akamana/data/crypto_options.json` to manage available ciphers/key lengths without code changes.
- Template: `deploy/crypto_options.json.example`

## Persistent host storage (recommended)
- Config (outside container): `/opt/akamana/config/akamana.env`
- Data (outside container): `/opt/akamana/data`
- Prepare secure directories:
  - `./scripts/prepare_host_storage.sh /opt/akamana akamana akamana`
- Compose variables:
  - `AKAMANA_HOST_CONFIG_DIR=/opt/akamana/config`
  - `AKAMANA_HOST_DATA_DIR=/opt/akamana/data`

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
- `docs/deployment_s10.md`
- `docs/root_certificate_deployment.md`
