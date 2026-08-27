# Akamana — Requirements Specification

> Reverse-engineered from the implemented system on 2026-07-15 and marked with an
> implementation status, so this file doubles as a **gap register**. No formal
> requirements document existed before; treat this as the baseline to amend when scope
> changes.
>
> Status legend: ✅ implemented · 🟡 partial · ❌ not implemented (declared or implied).

## 1. Purpose & scope

Akamana lets lab operators who are not crypto experts run an internal PKI (TLS root →
intermediate → leaf), an SSH CA, certificate monitoring, and automated deployment /
renewal of certificates to managed hosts — on a private, trusted network.

Out of scope (by design): public CA/ACME server duties (certbot is *consumed*, not
served), HSM integration, multi-tenant isolation, internet exposure.

## 2. Functional requirements

### FR-CA — Certificate authority
| ID | Requirement | Status |
|---|---|---|
| FR-CA-1 | Create organizations with a root CA (configurable validity, cipher — Ed25519/ECDSA P-256/RSA 2048-4096, subject DN) | ✅ |
| FR-CA-2 | Subject DN stored per root and inherited by all issued certs, preserved across renewal | ✅ |
| FR-CA-3 | Intermediate CA creation, renewal, root renew/revoke/import/delete | ✅ |
| FR-CA-4 | Controlled root-cert distribution: public list + per-platform download + publishable HTML install page | ✅ |
| FR-CA-5 | CRL: revocation list persisted, signed DER served at `/crl/<root_id>.crl` (CDP embedded in issued certs), publishable off-box | ✅ |

### FR-TLS — TLS certificate lifecycle
| ID | Requirement | Status |
|---|---|---|
| FR-TLS-1 | Issue leaf certs (CN + **SANs** DNS/IP, EKU purpose server/client/both) under a chosen root/intermediate | ✅ (since migration 017) |
| FR-TLS-2 | Renew, revoke (CRL), import, export public/private (private gated by publish-key flag), delete | ✅ |
| FR-TLS-3 | Auto-renew flagged leafs within `renew_days_before`, then re-deploy auto-deploy targets | ✅ (`lifecycle.rs`, hourly) |
| FR-TLS-4 | Obtain public certs via remote certbot over SSH (webroot/standalone/nginx/apache/dns), with auto-renew | ✅ |
| FR-TLS-5 | Certificate hierarchy view (root → intermediate → leaf) | ✅ |

### FR-SSH — SSH keys & certificates
| ID | Requirement | Status |
|---|---|---|
| FR-SSH-1 | Generate/import/export/revoke SSH keypairs | ✅ |
| FR-SSH-2 | SSH **User CA** and **Host CA** auto-bootstrapped; rotation endpoint | ✅ |
| FR-SSH-3 | Sign OpenSSH certificates (source: generate / existing key / provided public key); list, revoke, delete | ✅ |

### FR-MON — Monitoring & discovery
| ID | Requirement | Status |
|---|---|---|
| FR-MON-1 | Monitor TLS endpoints per host → port → SNI vhost; record expiry/subject/issuer/chain; colour-coded status | ✅ |
| FR-MON-2 | Alert emails (per-host + global default) with reachability cross-check | ✅ |
| FR-MON-3 | Network discovery: RFC1918-only /24 scan, hostname guessing (rDNS → TLS CN/SAN → NetBIOS), bulk add | ✅ |
| FR-MON-4 | TLS-version column, cipher/protocol enumeration, issues-only filter | 🟡 partial (declared gap in FEATURES_AND_API §6) |

### FR-INV / FR-DEP — Inventory & deployment
| ID | Requirement | Status |
|---|---|---|
| FR-INV-1 | Host inventory (name, IP, OS, owner, environment as managed dropdown lists), monitor-only mode | ✅ |
| FR-INV-2 | Application catalog with default paths/reload commands; credentials (SSH key/password, API token) encrypted at rest and never returned | ✅ |
| FR-INV-3 | Host↔credential and host↔application links with per-location cert/key paths | ✅ |
| FR-DEP-1 | Pre-flight check (SSH connect + writability, read-only) | ✅ |
| FR-DEP-2 | Deploy cert/key/chain over SSH (quoted paths, `umask 077`), run reload, journal every step, email on failure | ✅ |
| FR-DEP-3 | Manual deployment guide generator; declarative addons (`ADDONS_DIR`) | ✅ |
| FR-DEP-4 | SSH host-key pinning for outbound connections | ❌ (accepts any key — `deploy.rs`, `backup_remote.rs`; flagged in code comments) |

### FR-AUTH — Authentication, authorization, tokens
| ID | Requirement | Status |
|---|---|---|
| FR-AUTH-1 | Local login (Argon2) issuing short-lived HS256 JWTs | ✅ |
| FR-AUTH-2 | Optional OIDC (RS256/JWKS, role-claim mapping) | ✅ |
| FR-AUTH-3 | Four roles (full_admin, tls_admin, ssh_admin, auditor), per-handler enforcement | ✅ |
| FR-AUTH-4 | Scoped API tokens (`ezk_…`, SHA-256 stored, expiry, revocation; scopes capped by creator's role; human-only CRUD) | ✅ |
| FR-AUTH-5 | MFA enforcement when `REQUIRE_MFA=true` | ✅ TOTP (RFC 6238) + recovery codes; forced enrollment at sign-in when mandatory |
| FR-AUTH-6 | Login rate limiting / account lockout | ✅ `login_attempts` table; 8 failures per username or source IP in 15 min → 429 |
| FR-AUTH-7 | Passwordless sign-in with WebAuthn passkeys | ✅ opt-in via `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` |
| FR-AUTH-8 | Self-service password reset (single-use, expiring, emailed token) | ✅ needs SMTP + an email on the account; admins can issue a link without SMTP |

### FR-BAK — Backup & restore (see `docs/backup_and_restore.md`)
| ID | Requirement | Status |
|---|---|---|
| FR-BAK-1 | Scheduled + on-demand full DB backups, retention, skip-if-unchanged | ✅ |
| FR-BAK-2 | Encrypted `.ezbak` container: Argon2id passphrase or RSA envelope with multiple recipients | ✅ |
| FR-BAK-3 | Off-box push: mounted path or SFTP, with connectivity test | ✅ |
| FR-BAK-4 | Restore from upload or local file | ✅ |

### FR-LOG — Audit & telemetry
| ID | Requirement | Status |
|---|---|---|
| FR-LOG-1 | Access log for every `/api/` request (actor, IP, method, path, status, request-id) | ✅ |
| FR-LOG-2 | Action/audit log for sensitive operations | ✅ |
| FR-LOG-3 | Security events (brute-force, auth attack) + SIEM webhook forwarding | ✅ |

## 3. Non-functional requirements

| ID | Requirement | Status / evidence |
|---|---|---|
| NFR-SEC-1 | Secrets encrypted at rest (AES-256-GCM, KEK from env) | ✅ `crypto.rs` |
| NFR-SEC-2 | Argon2 password hashing; bootstrap password policy (≥15 chars, no known defaults, refuse to start) | ✅ `config.rs` |
| NFR-SEC-3 | Security headers (HSTS, CSP, XFO DENY, nosniff, referrer & permissions policy) on every response | ✅ `main.rs` |
| NFR-SEC-4 | CORS locked to configured origins; `*` allowed but loudly warned | ✅ |
| NFR-SEC-5 | `x-forwarded-for` trusted only from `TRUSTED_PROXY_IPS` | ✅ |
| NFR-SEC-6 | Input validation on all DTOs (`validator`) | ✅ |
| NFR-SEC-7 | SQL injection prevention: prepared statements only (SQLx) | ✅ (runtime-checked; no compile-time query validation) |
| NFR-SEC-8 | Intended for private trusted networks; TLS termination at reverse proxy | ✅ documented assumption |
| NFR-REL-1 | Idempotent migrations re-applied at startup | 🟡 works, but no version table/checksum — fragile (naive `;` split) |
| NFR-REL-2 | Background task failures logged, never crash the process | ✅ |
| NFR-OPS-1 | Single container + DB; env-only config; interactive installer; Docker/Podman rootless | ✅ |
| NFR-OPS-2 | Machine-readable OpenAPI for automation | 🟡 covers the token-facing subset (10 paths) only |
| NFR-QUA-1 | Lint gates: `cargo fmt --check`, `clippy -D warnings`, `unwrap/expect` denied; `cargo audit`; SonarQube in CI | ✅ `.gitea/workflows/sonarqube.yml` |
| NFR-QUA-2 | Automated tests (unit/integration) | ❌ none in-tree |
| NFR-PERF-1 | List endpoints paginated (default 200, max 1000) | ✅ |

## 4. Consolidated gap register (priority-ordered)

1. **No automated tests** (NFR-QUA-2) — highest risk given crypto + 5 700-line handler file.
2. **SSH host-key pinning missing** (FR-DEP-4) — MITM-able deploys/backups off a trusted LAN.
3. **OpenAPI coverage** (NFR-OPS-2) — ~110 routes undocumented in the spec.
4. **Migration runner robustness** (NFR-REL-1) — add a schema_version table + checksums.
5. **Monitoring enhancements** (FR-MON-4) — declared in FEATURES_AND_API §6.
