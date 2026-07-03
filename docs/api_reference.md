# EZKey API Reference

Base URL: `/api/v1`
Authentication: `Authorization: Bearer <token>` for all protected endpoints. The bearer token may be either a **login JWT** (from `POST /auth/login`) or an **API token** (`ezk_…`, minted on the API Tokens page). API tokens are gated by fine-grained scopes (`tls:issue`, `tls:read`, `ssh:issue`, `ssh:sign`, `ssh:read`, `ca:read`) and carry the sentinel role `token`, so they can only reach endpoints that explicitly accept their scope.

Machine-readable spec: `GET /api/v1/openapi.json` (OpenAPI 3.1, public). Committed copy: `docs/openapi.yaml`.

## Public endpoints
- `GET /health`
- `GET /openapi.json` OpenAPI 3.1 spec
- `POST /auth/login`
- `GET /certificates/root`
- `GET /certificates/root/download/{platform}` (`windows|macos|linux|ios|android`)

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
