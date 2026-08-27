use crate::{
    config::{AuthMode, Config},
    errors::{AppError, AppResult},
    models::AuthClaims,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand_core::OsRng;
use serde::Deserialize;
use sqlx::MySqlPool;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
struct JwksCache {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

pub struct JwksManager {
    cache: Arc<RwLock<Option<JwksCache>>>,
    cache_ttl: StdDuration,
}

impl JwksManager {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(None)),
            cache_ttl: StdDuration::from_secs(3600),
        }
    }
}

impl Default for JwksManager {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static::lazy_static! {
    pub static ref JWKS_MANAGER: JwksManager = JwksManager::new();
}

const VALID_AKAMANA_ROLES: [&str; 4] = ["full_admin", "ssh_admin", "tls_admin", "auditor"];

fn validate_and_normalize_role(role: &str) -> String {
    let normalized = role.to_lowercase();
    if VALID_AKAMANA_ROLES.contains(&normalized.as_str()) {
        return normalized;
    }
    tracing::warn!(
        "OIDC provided unknown role '{}', defaulting to 'auditor'",
        role
    );
    "auditor".to_string()
}

fn map_oidc_groups_to_role(groups: &[String], role_claim: Option<&str>) -> String {
    if let Some(claim) = role_claim {
        for group in groups {
            if group.to_lowercase() == claim.to_lowercase() {
                return validate_and_normalize_role(claim);
            }
        }
    }
    for group in groups {
        let lower = group.to_lowercase();
        if lower.contains("admin") {
            return "full_admin".to_string();
        }
        if lower.contains("tls") {
            return "tls_admin".to_string();
        }
        if lower.contains("ssh") {
            return "ssh_admin".to_string();
        }
    }
    "auditor".to_string()
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub username: String,
    pub role: String,
    /// True when the caller authenticated with an `ezk_` API token rather than
    /// an interactive login/OIDC JWT. Token callers carry the sentinel role
    /// `"token"` (which fails every `can_manage_*` role check) and are gated
    /// solely by `scopes`.
    pub is_token: bool,
    /// Fine-grained scopes granted to an API token (empty for human users).
    pub scopes: Vec<String>,
}

impl AuthenticatedUser {
    /// True if this token was granted `scope`. Always false for human users
    /// (they are gated by role, not scopes).
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Everything the login handler needs about a local account in one round trip:
/// identity, credential and second-factor state.
#[derive(Debug, Clone)]
pub struct LocalUser {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub email: Option<String>,
    pub totp_secret_enc: Option<String>,
    pub totp_enabled: bool,
}

/// Row shape of the `load_local_user` query, in column order.
type LocalUserRow = (
    String,         // id
    String,         // username
    String,         // password_hash
    String,         // role
    Option<String>, // email
    Option<String>, // totp_secret_enc
    bool,           // totp_enabled
);

pub async fn load_local_user(pool: &MySqlPool, username: &str) -> AppResult<Option<LocalUser>> {
    let row: Option<LocalUserRow> = sqlx::query_as(
        "SELECT id, username, password_hash, role, email, totp_secret_enc, totp_enabled \
         FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| LocalUser {
        id: r.0,
        username: r.1,
        password_hash: r.2,
        role: r.3,
        email: r.4,
        totp_secret_enc: r.5,
        totp_enabled: r.6,
    }))
}

/// Verifies a password against an Argon2 hash. A malformed stored hash is a
/// failed verification, not an error, so it can't be told apart from a wrong
/// password by an attacker.
pub fn verify_password(password_hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(password_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Burns roughly the same CPU as [`verify_password`] would have. Called when the
/// username doesn't exist so that "no such user" and "wrong password" don't
/// differ by a measurable Argon2 hash's worth of time.
pub fn spend_password_verification_time(password: &str) {
    let salt = SaltString::generate(&mut OsRng);
    let _ = Argon2::default().hash_password(password.as_bytes(), &salt);
}

/// Audience of the short-lived token issued between the password step and the
/// second-factor step. Deliberately different from `akamana-api` so a half-done
/// login can never be replayed against a real endpoint.
pub const MFA_TOKEN_AUDIENCE: &str = "akamana-mfa";
/// How long the user has to produce a second factor (or finish enrollment).
pub const MFA_TOKEN_MINUTES: i64 = 10;

/// `purpose` is either `mfa` (user already has a factor) or `mfa-setup`
/// (MFA is mandatory and the account has none yet). It lands in the `role`
/// claim, which keeps the token useless for anything but its own step.
pub fn create_mfa_token(cfg: &Config, username: &str, purpose: &str) -> AppResult<(String, i64)> {
    let expires_in = MFA_TOKEN_MINUTES * 60;
    let exp = (Utc::now() + Duration::seconds(expires_in)).timestamp() as usize;
    let claims = AuthClaims {
        sub: username.to_string(),
        role: purpose.to_string(),
        exp,
        iss: "akamana".to_string(),
        aud: MFA_TOKEN_AUDIENCE.to_string(),
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("failed to sign MFA token: {e}")))?;
    Ok((token, expires_in))
}

/// Returns `(username, purpose)` for a valid, unexpired MFA token.
pub fn decode_mfa_token(cfg: &Config, token: &str) -> AppResult<(String, String)> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[MFA_TOKEN_AUDIENCE]);
    validation.set_issuer(&["akamana"]);

    let data = decode::<AuthClaims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Auth)?;

    Ok((data.claims.sub, data.claims.role))
}

/// Window and threshold for the login lockout. Counted per username and per
/// source IP so neither password spraying nor a targeted guess is cheap.
pub const LOGIN_ATTEMPT_WINDOW_MINUTES: i64 = 15;
pub const LOGIN_MAX_FAILURES: i64 = 8;

pub async fn record_login_attempt(
    pool: &MySqlPool,
    username: &str,
    source_ip: &str,
    success: bool,
) {
    // Best-effort: a bookkeeping write must never break a login.
    if let Err(e) = sqlx::query(
        "INSERT INTO login_attempts (id, username, source_ip, success, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(username)
    .bind(source_ip)
    .bind(success)
    .bind(Utc::now().naive_utc())
    .execute(pool)
    .await
    {
        tracing::warn!("login_attempt_insert_failed: username={username} error={e}");
    }
}

/// Errors with 429 once either the account or the source IP has piled up
/// `LOGIN_MAX_FAILURES` failures inside the window.
pub async fn enforce_login_rate_limit(
    pool: &MySqlPool,
    username: &str,
    source_ip: &str,
) -> AppResult<()> {
    let since = (Utc::now() - Duration::minutes(LOGIN_ATTEMPT_WINDOW_MINUTES)).naive_utc();

    let failures: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM login_attempts \
         WHERE success = FALSE AND created_at >= ? AND (username = ? OR source_ip = ?)",
    )
    .bind(since)
    .bind(username)
    .bind(source_ip)
    .fetch_one(pool)
    .await?;

    if failures.0 >= LOGIN_MAX_FAILURES {
        return Err(AppError::TooManyRequests(format!(
            "Too many failed sign-in attempts. Try again in {LOGIN_ATTEMPT_WINDOW_MINUTES} minutes."
        )));
    }
    Ok(())
}

/// Clears the failure counter for an account after a successful sign-in so a
/// user who simply mistyped isn't left near the threshold. Only the username
/// counter is cleared — clearing the IP counter too would let anyone holding
/// one valid account reset the limit between password-spraying rounds.
pub async fn clear_login_failures(pool: &MySqlPool, username: &str) {
    if let Err(e) = sqlx::query("DELETE FROM login_attempts WHERE success = FALSE AND username = ?")
        .bind(username)
        .execute(pool)
        .await
    {
        tracing::warn!("login_attempt_cleanup_failed: username={username} error={e}");
    }
}

pub fn create_local_token(cfg: &Config, username: &str, role: &str) -> AppResult<(String, i64)> {
    let expires_in = cfg.jwt_exp_minutes * 60;
    let exp = (Utc::now() + Duration::seconds(expires_in)).timestamp() as usize;
    let claims = AuthClaims {
        sub: username.to_string(),
        role: role.to_string(),
        exp,
        iss: "akamana".to_string(),
        aud: "akamana-api".to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("failed to sign token: {e}")))?;

    Ok((token, expires_in))
}

fn decode_local_token(cfg: &Config, token: &str) -> AppResult<AuthClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["akamana-api"]);
    validation.set_issuer(&["akamana"]);

    let data = decode::<AuthClaims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Auth)?;

    Ok(data.claims)
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize, Clone, Debug)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
    kty: String,
    #[allow(dead_code)]
    alg: String,
}

async fn fetch_jwks(url: &str) -> AppResult<Vec<Jwk>> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| AppError::Internal(format!("JWKS fetch failed: {e}")))?;
    let jwks: Jwks = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("JWKS parse failed: {e}")))?;
    Ok(jwks.keys)
}

async fn get_jwk_for_kid(cfg: &Config, kid: &str) -> AppResult<Jwk> {
    {
        let cache = JWKS_MANAGER.cache.read().await;
        if let Some(cached) = cache.as_ref() {
            if cached.fetched_at.elapsed() < JWKS_MANAGER.cache_ttl {
                if let Some(key) = cached.keys.iter().find(|k| k.kid == kid && k.kty == "RSA") {
                    return Ok(key.clone());
                }
            }
        }
    }

    let jwks_url = cfg
        .oidc_jwks_url
        .clone()
        .ok_or_else(|| AppError::Internal("OIDC_JWKS_URL missing".to_string()))?;

    let keys = fetch_jwks(&jwks_url).await?;

    {
        let mut cache = JWKS_MANAGER.cache.write().await;
        *cache = Some(JwksCache {
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });
    }

    keys.into_iter()
        .find(|k| k.kid == kid && k.kty == "RSA")
        .ok_or(AppError::Auth)
}

async fn decode_oidc_token(cfg: &Config, token: &str) -> AppResult<AuthClaims> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| AppError::Auth)?;
    let kid = header.kid.clone().ok_or(AppError::Auth)?;

    let jwk = get_jwk_for_kid(cfg, &kid).await?;
    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|_| AppError::Auth)?;

    let mut validation = Validation::new(Algorithm::RS256);
    if let Some(aud) = &cfg.oidc_audience {
        validation.set_audience(&[aud]);
    }
    if let Some(issuer) = &cfg.oidc_issuer {
        validation.set_issuer(&[issuer]);
    }

    let token_data =
        decode::<serde_json::Value>(token, &key, &validation).map_err(|_| AppError::Auth)?;

    let raw_claims = token_data.claims;

    let sub = raw_claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Auth)?
        .to_string();

    let role =
        if let Some(role_val) = raw_claims.get(cfg.oidc_role_claim.as_deref().unwrap_or("role")) {
            let role_str = role_val.as_str().unwrap_or("auditor");
            validate_and_normalize_role(role_str)
        } else if let Some(groups) = raw_claims.get("groups").and_then(|v| v.as_array()) {
            let groups: Vec<String> = groups
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            map_oidc_groups_to_role(&groups, cfg.oidc_role_claim.as_deref())
        } else {
            tracing::warn!("OIDC token has no role or groups claim, defaulting to auditor");
            "auditor".to_string()
        };

    let exp = raw_claims.get("exp").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    let iss = raw_claims
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or("akamana")
        .to_string();

    Ok(AuthClaims {
        sub,
        role,
        exp,
        iss,
        aud: "akamana-api".to_string(),
    })
}

pub async fn decode_token(cfg: &Config, token: &str) -> AppResult<AuthClaims> {
    match cfg.auth_mode {
        AuthMode::Local => decode_local_token(cfg, token),
        AuthMode::Oidc => decode_oidc_token(cfg, token).await,
    }
}

/// Resolves a bearer token to an `AuthenticatedUser`. Accepts both `ezk_` API
/// tokens (validated against the `api_tokens` table) and interactive
/// login/OIDC JWTs. `track_usage` updates the token's last-used metadata and is
/// enabled only on the single `auth_guard` pass so we don't write twice per
/// request.
pub async fn authenticate(
    state: &crate::AppState,
    token: &str,
    source_ip: &str,
    track_usage: bool,
) -> AppResult<AuthenticatedUser> {
    if token.starts_with("ezk_") {
        return authenticate_api_token(state, token, source_ip, track_usage).await;
    }
    let claims = decode_token(&state.cfg, token).await?;
    Ok(AuthenticatedUser {
        username: claims.sub,
        role: claims.role,
        is_token: false,
        scopes: Vec::new(),
    })
}

async fn authenticate_api_token(
    state: &crate::AppState,
    token: &str,
    source_ip: &str,
    track_usage: bool,
) -> AppResult<AuthenticatedUser> {
    let hash = crate::crypto::hash_api_token(token);
    let row: Option<(String, String, String, bool, Option<chrono::NaiveDateTime>)> =
        sqlx::query_as(
            "SELECT id, owner_username, scopes, is_revoked, expires_at FROM api_tokens WHERE token_hash = ?",
        )
        .bind(&hash)
        .fetch_optional(&state.pool)
        .await?;

    let Some((id, owner_username, scopes, is_revoked, expires_at)) = row else {
        return Err(AppError::Auth);
    };
    if is_revoked {
        return Err(AppError::Auth);
    }
    let now = Utc::now().naive_utc();
    if let Some(exp) = expires_at {
        if exp < now {
            return Err(AppError::Auth);
        }
    }

    if track_usage {
        // Best-effort: never fail authentication because a usage-stamp write failed.
        if let Err(e) =
            sqlx::query("UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?")
                .bind(now)
                .bind(source_ip)
                .bind(&id)
                .execute(&state.pool)
                .await
        {
            tracing::warn!("api_token_last_used_update_failed: id={} error={}", id, e);
        }
    }

    let scopes: Vec<String> = scopes.split_whitespace().map(|s| s.to_string()).collect();

    Ok(AuthenticatedUser {
        username: owner_username,
        role: "token".to_string(),
        is_token: true,
        scopes,
    })
}

#[async_trait]
impl FromRequestParts<crate::AppState> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_value = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Auth)?;

        let token = auth_value.strip_prefix("Bearer ").ok_or(AppError::Auth)?;
        authenticate(state, token, "", false).await
    }
}
