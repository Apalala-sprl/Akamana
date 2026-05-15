# EZKey API Reference

Base URL: `/api/v1`
Authentication: `Authorization: Bearer <token>` for all protected endpoints.

## Public endpoints
- `GET /health`
- `POST /auth/login`
- `GET /certificates/root`
- `GET /certificates/root/download/{platform}` (`windows|macos|linux|ios|android`)

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
