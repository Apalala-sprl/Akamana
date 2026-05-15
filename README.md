# EZKey

EZKey is an internal-lab secure key lifecycle service built with Rust, HTML, JS, CSS, and MariaDB.
It exposes a REST API with bearer token authentication to manage:
- machine inventory (hostname, IP, owner, environment)
- TLS keypairs and certificate issuance
- SSH keypairs and rotation lifetime
- CRL entries (revoked TLS certificate serials)
- audit trail

## Core stack
- Backend: Rust + Axum + SQLx + OpenSSL
- Database: MariaDB
- Frontend: classless semantic HTML + vanilla JS + minimal CSS
- Deployment: Docker / pod manifest
- CI/CD: GitLab CI

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
- Drop a JSON file at `/opt/ezkey/data/crypto_options.json` to manage available ciphers/key lengths without code changes.
- Template: `deploy/crypto_options.json.example`

## Persistent host storage (recommended)
- Config (outside container): `/opt/ezkey/config/ezkey.env`
- Data (outside container): `/opt/ezkey/data`
- Prepare secure directories:
  - `./scripts/prepare_host_storage.sh /opt/ezkey ezkey ezkey`
- Compose variables:
  - `EZKEY_HOST_CONFIG_DIR=/opt/ezkey/config`
  - `EZKEY_HOST_DATA_DIR=/opt/ezkey/data`

## Security highlights
- Argon2 password hashing
- JWT bearer token authentication
- optional OIDC mode for Keycloak-style central auth
- encrypted private keys at rest (AES-256-GCM)
- strict request validation
- audit logging
- root CA bootstrap and controlled download endpoints

## Documentation index
- `docs/database_tables.md`
- `docs/functions_catalog.md`
- `docs/api_reference.md`
- `docs/security.md`
- `docs/deployment_s10.md`
- `docs/root_certificate_deployment.md`
