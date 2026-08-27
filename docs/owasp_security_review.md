# Akamana Security Review & OWASP ASVS 5.0 Assessment

**Document Version:** 1.0  
**Date:** 2026-03-23  
**Review Scope:** Rust backend (`backend/src/`) + JavaScript frontend (`web/`)  
**OWASP Reference:** ASVS 5.0.0 + OWASP Top 10 (2021)

---

## 1. Executive Summary

Akamana is an internal-lab PKI/key lifecycle management service with a Rust/Axum backend, MariaDB database, and vanilla JS/CSS SPA frontend. The codebase demonstrates good security fundamentals (Argon2, AES-256-GCM, SQLx prepared statements, JWT) but has several medium-to-high severity findings that must be addressed before production deployment.

**Risk Rating:**
| Severity | Count | Finding |
|----------|-------|---------|
| Critical | 1 | CORS permits any origin |
| High | 4 | Missing security headers, IP spoofing, audit silent failure, private key export default |
| Medium | 4 | OIDC JWKs not cached, role inconsistency, no login rate limiting, SSRF on DNS endpoint |
| Low | 5 | Session management gaps, weak default bootstrap password, DOM clobbering, missing CSP nonce, no token denylist |

---

## 2. Detailed Findings

### 2.1 A01 — Broken Access Control (OWASP Top 10 #1)

#### F-01: CORS Allows Any Origin — **CRITICAL**
- **File:** `backend/src/main.rs:74`
- **ASVS:** V3.4.2 (L1)
- **Finding:** `allow_origin(Any)` permits cross-origin requests from any website.
- **Impact:** Any malicious website can make authenticated API requests on behalf of a logged-in user.
- **Recommendation:** Make CORS configurable via environment variable:
  ```rust
  // Set ALLOWED_ORIGINS=https://trusted.example.com,https://admin.example.com
  let allowed_origins: Vec<axum::http::Origin> = cfg.allowed_origins
      .split(',')
      .map(|s| s.parse::<axum::http::Origin>().ok())
      .flatten()
      .collect();
  let cors = CorsLayer::new()
      .allow_origin(allowed_origins)
      ...
  ```

#### F-02: IP Spoofing via x-forwarded-for — **HIGH**
- **File:** `backend/src/main.rs:93-98`
- **ASVS:** V4.1.3 (L2)
- **Finding:** `x-forwarded-for` header is trusted unconditionally without validating it comes from a trusted proxy.
- **Impact:** An attacker can forge their source IP address (e.g., to bypass brute-force detection, fake admin access from "localhost").
- **Recommendation:**
  - Validate `x-forwarded-for` only when the request comes from a known proxy IP range.
  - Add `TRUSTED_PROXY_CIDRS` config (e.g., `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`).
  - Fall back to the direct connection IP when not from a trusted proxy.

#### F-03: Role Name Inconsistency — **MEDIUM**
- **Files:** `backend/src/routes/api.rs`, `web/index.html`
- **ASVS:** V8.1.1 (L1)
- **Finding:** Code checks for `"admin"` in role checks (e.g., lines 321-325, 417-422), but the frontend only offers `full_admin`, `ssh_admin`, `tls_admin`, `auditor`. The bootstrap admin is created with role `admin` in `db.rs:60`.
- **Impact:** The bootstrap admin with role `admin` may not match all role checks that look for `"admin"`. Inconsistent authorization.
- **Recommendation:** Standardize on one role set. Recommended: keep `full_admin`, `ssh_admin`, `tls_admin`, `auditor` and remove `"admin"` alias, OR add `full_admin` alias for the bootstrap.

#### F-04: No CSRF Protection — **LOW** (mitigated by Bearer tokens)
- **ASVS:** V3.5.1 (L1)
- **Finding:** No CSRF tokens; uses `Authorization: Bearer` header which is not automatically sent in cross-origin HTML form submissions.
- **Mitigation:** Bearer token architecture reduces CSRF risk. However, GET requests that cause side effects (downloads) should not be state-changing.
- **Recommendation:** For state-changing POST/PATCH/DELETE, ensure CORS is restricted (see F-01). Consider adding SameSite=Strict cookies if session-based auth is introduced.

---

### 2.2 A02 — Cryptographic Failures (OWASP Top 10 #2)

#### F-05: Default `publish_private_key = true` — **HIGH**
- **File:** `backend/src/models.rs:71,356-357`
- **ASVS:** V2.4.1 (L1)
- **Finding:** `default_publish_private_key()` returns `true`, meaning private key export is allowed by default when generating new certificates.
- **Impact:** Accidental exposure of private keys. Users may not understand the security implications.
- **Recommendation:** Change default to `false`. Users should explicitly enable private key export. Update the frontend default radio button in `index.html` to `checked` on "No".

#### F-06: Weak Bootstrap Password Default — **MEDIUM**
- **File:** `backend/src/config.rs:61`
- **ASVS:** V6.2.1 (L1)
- **Finding:** `bootstrap_admin_password` defaults to `ChangeMeNow!` which does not meet modern password policy (OWASP recommends 15+ chars, no common patterns).
- **Impact:** If `.env` is not configured before deployment, the service starts with a guessable password.
- **Recommendation:** Fail startup if `BOOTSTRAP_ADMIN_PASSWORD` is not set in the environment. Make it a required (not optional) config field.

#### F-07: No Token Denylist (Logout Doesn't Invalidate JWT) — **LOW**
- **File:** `backend/src/auth.rs`
- **ASVS:** V7.4.1 (L1)
- **Finding:** JWT tokens cannot be invalidated before expiry. A stolen token remains valid until it expires.
- **Recommendation:** Maintain a `revoked_tokens` table with `jti` (JWT ID) claims. Check token JTI against this table on every request. Add `jti` to `AuthClaims`.

#### F-08: No Password Breach Check — **MEDIUM**
- **File:** `backend/src/routes/api.rs:2298-2339`
- **ASVS:** V6.2.12 (L2)
- **Finding:** New user passwords are not checked against known-breached password lists (e.g., HaveIBeenPwned API or a local breach corpus).
- **Recommendation:** Integrate with HaveIBeenPwned Passwords API (`k-anonymity` endpoint) or a local breach database for new user creation and password changes.

---

### 2.3 A03 — Injection (OWASP Top 10 #3)

#### F-09: SQL Injection — **PASSED**
- **Files:** All SQL in `routes/api.rs`, `db.rs`, `auth.rs`
- **ASVS:** V1.2.4 (L1)
- **Finding:** All database queries use SQLx prepared statements with bound parameters. No string concatenation in SQL. ✅
- **Additional:** LIKE queries use `%{}%` patterns via `.bind()`, which is safe.

#### F-10: No Stored XSS — **PASSED**
- **Files:** `web/app.js`
- **ASVS:** V3.2.2 (L1)
- **Finding:** User data is rendered via `textContent` (lines 325, 385-391), not `innerHTML`. No `eval()` usage. ✅

#### F-11: Deployment Command Injection (Partial) — **MEDIUM**
- **File:** `backend/src/routes/api.rs:2017-2168`
- **ASVS:** V1.2.5 (L1)
- **Finding:** `build_tls_deploy_guide` generates shell commands with `shell_escape_single_quotes`. File paths and other user-provided strings are embedded in shell heredocs (`cat <<'EOF' | ...`). While single quotes are escaped, the outer `cat <<'EOF'` delimiter prevents variable expansion inside the content. However, the `cert_path`, `key_path`, and other user-controlled strings are passed as file arguments to `tee` and `chmod` commands.
- **Risk:** If a path contains special characters like `; rm -rf /`, it could be interpreted by the shell when the generated command is pasted and run by an operator.
- **Recommendation:** Validate paths against a strict allowlist (alphanumeric, `-`, `_`, `.`, `/`). Reject paths containing shell metacharacters (`; & | $ ` < > ` \n`).

---

### 2.4 A04 — Insecure Design (OWASP Top 10 #4)

#### F-12: SSRF on Network Resolution Endpoint — **MEDIUM**
- **File:** `backend/src/routes/api.rs:3153-3185`
- **ASVS:** V1.3.6 (L2)
- **Finding:** `/api/v1/network/resolve?hostname=...` performs DNS lookups on user-supplied hostnames. This could be used to probe internal network services, resolve internal IPs, and detect which internal hosts exist.
- **Mitigation:** This is intentional for the certificate workflow, but lacks scope limiting.
- **Recommendation:** Add network scoping — restrict resolution to public IPs only, or require the user to have a role that permits network probes. Log all resolution requests.

#### F-13: Machine Monitor SSRF (TLS Scanning) — **MEDIUM**
- **File:** `backend/src/machine_monitor.rs`
- **ASVS:** V1.3.6 (L2)
- **Finding:** The `scan_tls_port` function connects to arbitrary IPs and ports as specified in the `machine_monitor_ports` table. This is the intended functionality but lacks validation.
- **Recommendation:** Restrict monitored targets to a configured IP range allowlist. Prevent scanning private IP ranges from internet-facing deployments.

---

### 2.5 A05 — Security Misconfiguration (OWASP Top 10 #5)

#### F-14: Missing HTTP Security Headers — **HIGH**
- **File:** `backend/src/main.rs`
- **ASVS:** V3.4.1, V3.4.3, V3.4.4, V3.4.5, V3.4.6 (L1-L2)
- **Finding:** No security headers are set on HTTP responses:
  - Missing `Strict-Transport-Security` (HSTS)
  - Missing `Content-Security-Policy`
  - Missing `X-Content-Type-Options: nosniff`
  - Missing `X-Frame-Options` or CSP `frame-ancestors`
  - Missing `Referrer-Policy`
  - Missing `Permissions-Policy`
- **Recommendation:** Add a tower-http middleware layer for security headers:
  ```rust
  use tower_http::compression::CompressionLayer;
  use tower_http::cors::CorsLayer;
  use tower_http::set_headers::SetResponseHeaderLayer;
  
  app = app
      .layer(SetResponseHeaderLayer::overriding(
          axum::http::header::STRICT_TRANSPORT_SECURITY,
          axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
      ))
      .layer(SetResponseHeaderLayer::overriding(
          axum::http::header::X_CONTENT_TYPE_OPTIONS,
          axum::http::HeaderValue::from_static("nosniff"),
      ))
      .layer(SetResponseHeaderLayer::overriding(
          axum::http::header::X_FRAME_OPTIONS,
          axum::http::HeaderValue::from_static("DENY"),
      ))
      .layer(SetResponseHeaderLayer::overriding(
          axum::http::header::REFERRER_POLICY,
          axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
      ));
  ```

#### F-15: Missing HSTS Preload — **LOW**
- **ASVS:** V3.7.4 (L3)
- **Recommendation:** Submit the domain to the HSTS preload list if TLS is mandatory.

#### F-16: No Content-Type Validation on File Downloads — **LOW**
- **File:** `backend/src/routes/api.rs:3187-3232`
- **ASVS:** V4.1.1 (L1)
- **Finding:** Root CA download endpoint always returns `application/x-pem-file` regardless of platform, even though Windows `.cer` files are binary DER format.
- **Recommendation:** Return correct MIME types per platform.

---

### 2.6 A06 — Vulnerable and Outdated Components (OWASP Top 10 #6)

#### F-17: No Dependency Vulnerability Scanning in CI — **LOW**
- **Finding:** The security.md mentions `cargo audit` in GitLab CI, but this wasn't verified in the repo.
- **Recommendation:** Ensure `.gitlab-ci.yml` includes `cargo audit` and `npm audit` steps. Pin transitive dependencies where possible.

#### F-18: TLS 1.0/1.1 Not Disabled — **LOW**
- **File:** `backend/src/machine_monitor.rs:204`
- **ASVS:** V9.1.1 (L1)
- **Finding:** `SslConnector::builder(SslMethod::tls())` may permit TLS 1.0/1.1 depending on OpenSSL version.
- **Recommendation:** Explicitly set minimum TLS version to 1.2:
  ```rust
  builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
  ```

---

### 2.7 A07 — Identification and Authentication Failures (OWASP Top 10 #7)

#### F-19: No Rate Limiting on Login Endpoint — **MEDIUM**
- **File:** `backend/src/routes/api.rs:236-266`
- **ASVS:** V6.3.1 (L1)
- **Finding:** No rate limiting on `/api/v1/auth/login`. The security_monitor detects brute-force attacks after the fact but doesn't prevent them.
- **Recommendation:** Add per-IP rate limiting using a middleware (e.g., `axum-rate-limit`). Limit to 5 attempts per 15 minutes per IP.

#### F-20: User Enumeration via Timing — **LOW**
- **File:** `backend/src/auth.rs:19-43`
- **ASVS:** V6.3.8 (L3)
- **Finding:** `verify_local_user` returns `Ok(None)` when the user doesn't exist (after DB query), but `Ok(Some(_))` when the user exists and password is wrong. This creates a timing difference that could be used for user enumeration.
- **Recommendation:** Perform a dummy password hash computation even when the user doesn't exist (timing-safe comparison).

#### F-21: No Account Lockout — **LOW**
- **ASVS:** V6.1.1 (L1)
- **Finding:** Failed login attempts are detected by security_monitor but not prevented through account lockout.
- **Recommendation:** Consider temporary account lockout after N failed attempts (e.g., 10 attempts in 15 minutes = 15-minute lockout).

#### F-22: No MFA — **MEDIUM**
- **ASVS:** V6.3.3 (L2)
- **Finding:** No multi-factor authentication support.
- **Recommendation:** For a PKI management system, MFA is strongly recommended. Integrate TOTP (RFC 6238) or hardware keys (FIDO2/WebAuthn).

#### F-23: OIDC Role Claim Not Mapped — **MEDIUM**
- **File:** `backend/src/auth.rs:95-128`
- **ASVS:** V6.8.4 (L2)
- **Finding:** In OIDC mode, the `role` claim from the IdP is used directly without validation or mapping to Akamana roles.
- **Impact:** If the IdP is compromised or misconfigured, an attacker with any role claim could gain elevated access.
- **Recommendation:** Validate the role claim against an allowlist of valid Akamana roles (`full_admin`, `ssh_admin`, `tls_admin`, `auditor`). Add an OIDC_ROLE_CLAIM_CONFIG env var to map IdP groups to Akamana roles.

---

### 2.8 A08 — Software and Data Integrity Failures (OWASP Top 10 #8)

#### F-24: Audit Logging Silently Fails — **HIGH**
- **File:** `backend/src/routes/api.rs:3234-3256`
- **ASVS:** V9.1.1 (L1)
- **Finding:** The `audit()` function uses `Ok(())` with no error handling. In `login()` (line 249-257), if the audit insert fails, the error propagates but in most other places, the `?` operator means audit failures return errors to clients.
- **Impact:** Audit trail integrity is critical for compliance. Silent failures mean security events may go unlogged.
- **Recommendation:**
  ```rust
  async fn audit(...) -> AppResult<()> {
      sqlx::query(...).execute(&state.pool).await?;
      Ok(())
  }
  // In routes: add .or_else(|e| async { tracing::error!("audit failed: {}", e); Ok(()) })
  ```
  Or: make audit failures non-fatal (fire-and-forget with tracing) for non-critical actions, but fatal for security-critical actions.

---

### 2.9 A09 — Security Logging and Monitoring Failures (OWASP Top 10 #9)

#### F-25: No Request Correlation ID — **MEDIUM**
- **Finding:** Audit logs don't include a request ID that correlates with access logs.
- **Recommendation:** Generate a UUID per request in the auth guard, include it in the `log_access` and `audit` records, and return it in response headers (`X-Request-ID`).

#### F-26: SIEM Webhook Doesn't Validate Response — **LOW**
- **File:** `backend/src/security_monitor.rs:126-133`
- **ASVS:** V9.1.1 (L2)
- **Finding:** `send_to_siem` ignores the response from the SIEM webhook.
- **Recommendation:** Log and alert if the SIEM webhook returns non-2xx status.

---

### 2.10 A10 — Server-Side Request Forgery (OWASP Top 10 #10)

#### F-27: SSRF in `/api/v1/network/resolve` — **MEDIUM**
- See F-12.

#### F-28: SSRF in Machine Monitor — **MEDIUM**
- See F-13.

---

## 3. OWASP ASVS Chapter Compliance Summary

| ASVS Chapter | Level | Status | Notes |
|---|---|---|---|
| V1 Encoding/Sanitization | L1 | ⚠️ Partial | SQLi: ✅ XSS: ✅ Shell injection: ⚠️ (see F-11) |
| V2 Validation/Business Logic | L1 | ✅ Pass | Validator crate used, positive validation on DTOs |
| V3 Web Frontend Security | L1 | ❌ Fail | Missing HSTS, CSP, CORS misconfigured (F-01, F-14) |
| V4 API/Web Services | L1 | ⚠️ Partial | No rate limiting (F-19), CORS issue |
| V5 File Handling | L1 | ✅ Pass | No file upload to persistent storage |
| V6 Authentication | L1 | ⚠️ Partial | No MFA, no rate limiting, weak defaults |
| V7 Session Management | L1 | ⚠️ Partial | JWT not revocable (F-07) |
| V8 Authorization | L1 | ⚠️ Partial | Role inconsistency (F-03) |
| V9 Cryptography | L1 | ✅ Pass | Argon2, AES-256-GCM, Ed25519, RSA, CSPRNG |
| V10 Error Handling/Logging | L1 | ❌ Fail | Audit silent failure (F-24), no correlation ID |
| V11 Networking | L1 | ⚠️ Partial | TLS scanning SSRF (F-13, F-28) |

---

## 4. Action Items (Priority Order)

### P0 — Must Fix Before Production
1. **F-01:** Restrict CORS to configured allowed origins
2. **F-14:** Add HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
3. **F-05:** Change `publish_private_key` default to `false`
4. **F-06:** Make bootstrap password a required (not default) config
5. **F-24:** Handle audit logging failures properly (don't silently drop)
6. **F-02:** Validate `x-forwarded-for` against trusted proxy IPs

### P1 — Fix Within 1 Sprint
7. **F-19:** Add rate limiting on login endpoint
8. **F-11:** Validate file paths against shell metacharacter allowlist in deployment guide
9. **F-03:** Standardize role names across backend and frontend
10. **F-23:** Validate and map OIDC role claims to Akamana roles
11. **F-12/28:** Add SSRF protection to network resolution and machine monitor
12. **F-18:** Set minimum TLS 1.2 in machine monitor SSL connector

### P2 — Fix in Next Release
13. **F-07:** Add JWT denylist (revoked tokens table with jti)
14. **F-08:** Integrate password breach checking
15. **F-22:** Add TOTP MFA support
16. **F-20:** Timing-safe user enumeration prevention
17. **F-25:** Add request correlation IDs
18. **F-17:** Verify `cargo audit` is in CI pipeline
19. **F-21:** Consider account lockout after failed logins

---

## 5. Security Controls Already Present ✅

| Control | Implementation |
|---|---|
| Password hashing | Argon2id (`argon2` crate, `auth.rs`, `db.rs`) |
| Encryption at rest | AES-256-GCM for private keys (`crypto.rs`) |
| Parameterized SQL | SQLx with `?` bind params everywhere |
| XSS prevention | `textContent` rendering in JS frontend |
| TLS certificates | Ed25519, ECDSA P-256, RSA (configurable) |
| SSH keys | Ed25519 (`ssh_key` crate) |
| Role-based auth | 4 roles: full_admin, ssh_admin, tls_admin, auditor |
| Audit logging | Action, access, and security event logs |
| Brute-force detection | security_monitor.rs checks failed logins |
| OIDC support | Optional Keycloak/OAuth2 integration |
| Certificate expiry monitoring | machine_monitor.rs with email/webhook alerts |
| JWT authentication | HS256 (local) / RS256 (OIDC) |
| Input validation | `validator` crate on all DTOs |
| OIDC signature verification | JWKS fetched and validated per-token |

---

*Document generated from codebase review against OWASP ASVS 5.0.0 and OWASP Top 10 (2021).*
