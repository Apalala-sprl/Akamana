# EZKey Security Notes

## Security by design controls
- Input validation via `validator` on all API payload DTOs.
- Short-lived JWT bearer tokens.
- Role-based authorization checks (`admin`, `operator`, `auditor`).
- Password hashing using Argon2.
- Encryption-at-rest for private keys (`AES-256-GCM`).
- Centralized audit trail for sensitive actions.
- Default-deny auth middleware for `/api/*` paths.
- SIEM webhook integration for security alerts.
- Brute-force and auth-attack detection from access telemetry.

## OWASP Top 10 mapping
- A01 Broken Access Control: role checks + protected routes.
- A02 Cryptographic Failures: Argon2, AES-GCM, signed certs.
- A03 Injection: SQLx prepared statements only.
- A04 Insecure Design: documented threat assumptions and least privilege.
- A05 Security Misconfiguration: `.env` template with required hardening flags.
- A06 Vulnerable Components: GitLab CI includes `cargo audit`.
- A07 Identification/Auth Failures: token authentication + optional OIDC.
- A08 Integrity Failures: signed certificates and immutable audit entries.
- A09 Logging/Monitoring Failures: audit/access/security logs and SIEM webhook alerts.
- A10 SSRF: no outbound user-provided URL fetching in business endpoints.

## Hardening checklist
- Replace all default secrets before first deployment.
- Restrict network access to API and MariaDB.
- Enable TLS termination at reverse proxy.
- Configure `siem_webhook_url` in settings to forward alerts.
- Rotate JWT secret and key encryption key periodically.
- Back up database and root CA material securely.
- Enforce OS patching and container scanning.
