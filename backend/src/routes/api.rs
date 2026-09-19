use crate::{
    addons::load_addons,
    auth::{
        clear_login_failures, create_local_token, create_mfa_token, decode_mfa_token,
        enforce_login_rate_limit, load_local_user, record_login_attempt,
        spend_password_verification_time, verify_password, AuthenticatedUser, LocalUser,
    },
    crypto::{
        analyze_ssh_certificate, analyze_ssh_key, build_pkcs12, cert_pem_to_der, create_root_ca,
        decrypt_secret, encrypt_secret, generate_api_token, generate_ssh_ca_material,
        generate_ssh_material, generate_tls_material, sha256_hex, sign_ssh_certificate,
        CreateRootCaParams, GenerateTlsMaterialParams, SshCertParams, SubjectDn,
    },
    errors::{AppError, AppResult},
    machine_monitor, mfa,
    models::{
        AddBackupRecipientRequest, AddMonitoredDomainRequest, AnalyzeSshCertificateRequest,
        AnalyzeSshKeyRequest, ApplicationRecord, BackupRemoteSettingsRequest,
        BackupSettingsRequest, CertbotConfigRecord, ChangePasswordRequest, CreateApiTokenRequest,
        CreateCertbotConfigRequest, CreateCredentialRequest, CreateHostApplicationRequest,
        CreateHostCredentialRequest, CreateIntermediateRequest, CreateMachineMonitorPortRequest,
        CreateMachineRequest, CreateOrganizationRequest, CreateUserRequest, CredentialRow,
        CredentialSummary, CrlEntryRecord, DisableMfaRequest, GenerateSshKeyRequest,
        GenerateSshKeyResponse, GenerateTlsKeyRequest, GenerateTlsKeyResponse,
        HostApplicationRecord, HostCredentialRecord, ImportRootCaRequest,
        ImportSshCertificateRequest, ImportSshKeyRequest, ImportTlsCertificateRequest,
        IntegrationPlanRequest, IssueSshCertificateRequest, LoginOutcome, LoginRequest,
        MachineRecord, MfaChallengeResponse, MfaLoginRequest, MfaTokenRequest, NetworkScanRequest,
        PasskeyLoginFinishRequest, PasskeyLoginStartRequest, PasskeyRegisterFinishRequest,
        PasskeyRegisterStartRequest, PasswordResetConfirmRequest, PasswordResetRequest,
        PublishKeyRequest, RenewTlsRequest, ResetUserPasswordRequest, RestoreBackupRequest,
        RevokeTlsRequest, SaveDefaultsRequest, SaveMachineMonitorSettingsRequest,
        SaveNotificationSettingsRequest, SaveProfilePictureRequest, SaveSiemSettingsRequest,
        SetAutoRenewRequest, TlsDeployGuideRequest, TokenResponse, TotpCodeRequest,
        UpdateCredentialRequest, UpdateHostApplicationRequest, UpdateMachineMonitorPortRequest,
        UpdateMachineRequest, UpdateUserEmailRequest, UpdateUserRoleRequest,
        UpsertApplicationRequest,
    },
    passkey, AppState, ClientIp,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{Path, Query, State},
    routing::{get, patch, post},
    Json, Router,
};
use base64::Engine as _;
use chrono::Utc;
use openssl::{
    nid::Nid,
    pkey::{Id, PKey},
    x509::X509,
};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, net::IpAddr};
use uuid::Uuid;
use validator::Validate;
// Imported by name rather than via `webauthn_rs::prelude::*`: the prelude also
// exports `Uuid` and `Url`, which would collide with this module's imports.
use webauthn_rs::prelude::{
    CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/crl/:file", get(serve_crl))
        .route("/api/v1/openapi.json", get(openapi_spec))
        .route("/api/v1/branding", get(branding))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/login/mfa", post(login_mfa))
        .route(
            "/api/v1/auth/login/mfa/enroll/start",
            post(login_mfa_enroll_start),
        )
        .route(
            "/api/v1/auth/login/mfa/enroll/finish",
            post(login_mfa_enroll_finish),
        )
        .route(
            "/api/v1/auth/passkey/login/start",
            post(passkey_login_start),
        )
        .route(
            "/api/v1/auth/passkey/login/finish",
            post(passkey_login_finish),
        )
        .route(
            "/api/v1/auth/password-reset/request",
            post(password_reset_request),
        )
        .route(
            "/api/v1/auth/password-reset/confirm",
            post(password_reset_confirm),
        )
        .route("/api/v1/mfa/status", get(mfa_status))
        .route("/api/v1/mfa/totp/setup", post(totp_setup))
        .route("/api/v1/mfa/totp/confirm", post(totp_confirm))
        .route("/api/v1/mfa/totp/disable", post(totp_disable))
        .route(
            "/api/v1/mfa/recovery-codes",
            post(regenerate_recovery_codes),
        )
        .route(
            "/api/v1/mfa/passkeys",
            get(list_passkeys).post(passkey_register_start),
        )
        .route("/api/v1/mfa/passkeys/finish", post(passkey_register_finish))
        .route(
            "/api/v1/mfa/passkeys/:id",
            axum::routing::delete(delete_passkey),
        )
        .route(
            "/api/v1/certificates/root/download/:platform",
            get(download_root_ca),
        )
        .route(
            "/api/v1/certificates/root",
            get(list_root_certs).post(create_organization_root),
        )
        .route(
            "/api/v1/certificates/root/:id",
            get(get_root_cert).delete(delete_root_cert),
        )
        .route("/api/v1/certificates/root/:id/renew", post(renew_root_cert))
        .route(
            "/api/v1/certificates/root/:id/revoke",
            post(revoke_root_cert),
        )
        .route(
            "/api/v1/certificates/intermediate",
            post(create_intermediate_cert),
        )
        .route("/api/v1/certificates/root/import", post(import_root_ca))
        .route("/api/v1/certificates/tls", get(list_tls_certs))
        .route("/api/v1/certificates/ssh", get(list_ssh_certs))
        .route("/api/v1/ssh/keys/analyze", post(analyze_ssh_key_endpoint))
        .route(
            "/api/v1/ssh/certificates/analyze",
            post(analyze_ssh_certificate_endpoint),
        )
        .route(
            "/api/v1/ssh/certificates/import",
            post(import_ssh_certificate),
        )
        .route("/api/v1/certificates/tree", get(certificate_tree))
        .route("/api/v1/crypto/options", get(get_crypto_options))
        .route(
            "/api/v1/certificates/tls/:id",
            get(get_tls_cert).delete(delete_tls_cert),
        )
        .route(
            "/api/v1/certificates/tls/:id/publish-key",
            patch(set_tls_publish_key),
        )
        .route(
            "/api/v1/certificates/ssh/:id",
            get(get_ssh_cert).delete(delete_ssh_cert),
        )
        .route(
            "/api/v1/certificates/ssh/:id/publish-key",
            patch(set_ssh_publish_key),
        )
        .route("/api/v1/keys/tls/renew", post(renew_tls_key))
        .route(
            "/api/v1/certificates/tls/import",
            post(import_tls_certificate),
        )
        .route("/api/v1/certificates/ssh/import", post(import_ssh_key))
        .route("/api/v1/keys/ssh/revoke/:id", post(revoke_ssh_key))
        .route("/api/v1/certificates/tls/:id/export", get(export_tls_cert))
        .route(
            "/api/v1/certificates/tls/:id/export/public",
            get(export_tls_public),
        )
        .route(
            "/api/v1/certificates/tls/:id/export/private",
            get(export_tls_private),
        )
        .route("/api/v1/deploy/tls/:id/guide", post(build_tls_deploy_guide))
        .route(
            "/api/v1/certificates/ssh/:id/export/public",
            get(export_ssh_public),
        )
        .route(
            "/api/v1/certificates/ssh/:id/export/private",
            get(export_ssh_private),
        )
        .route("/api/v1/machines", post(create_machine).get(list_machines))
        .route(
            "/api/v1/machines/:id",
            patch(update_machine).delete(delete_machine),
        )
        .route(
            "/api/v1/certificates/tls/:id/auto-renew",
            patch(set_tls_auto_renew),
        )
        .route("/api/v1/machines/monitor", get(list_machine_monitor_rows))
        .route(
            "/api/v1/machines/monitor/ports",
            post(add_machine_monitor_port),
        )
        .route(
            "/api/v1/machines/monitor/domains",
            post(add_monitored_domain),
        )
        .route(
            "/api/v1/machines/monitor/ports/:id/scan",
            post(scan_machine_monitor_port),
        )
        .route(
            "/api/v1/machines/monitor/ports/:id",
            patch(update_machine_monitor_port).delete(delete_machine_monitor_port),
        )
        .route(
            "/api/v1/machines/monitor/scan",
            post(scan_all_machine_monitor_ports),
        )
        .route("/api/v1/keys/tls", post(generate_tls_key))
        .route("/api/v1/keys/ssh", post(generate_ssh_key))
        .route("/api/v1/crl/revoke", post(revoke_tls))
        .route("/api/v1/crl", get(list_crl))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/:id/role", patch(update_user_role))
        .route("/api/v1/users/:id/email", patch(update_user_email))
        .route("/api/v1/users/:id/password", post(reset_user_password))
        .route("/api/v1/users/:id/reset-link", post(create_user_reset_link))
        .route("/api/v1/users/:id", axum::routing::delete(delete_user))
        .route("/api/v1/users/me", get(get_me))
        .route("/api/v1/users/me/password", post(change_my_password))
        .route(
            "/api/v1/users/me/picture",
            post(upload_my_picture).delete(delete_my_picture),
        )
        .route(
            "/api/v1/tokens",
            get(list_api_tokens).post(create_api_token),
        )
        .route("/api/v1/tokens/scopes", get(list_grantable_scopes))
        .route("/api/v1/tokens/:id/revoke", post(revoke_api_token))
        .route(
            "/api/v1/tokens/:id",
            axum::routing::delete(delete_api_token),
        )
        .route("/api/v1/ssh/cas", get(list_ssh_cas))
        .route("/api/v1/ssh/cas/:id/public", get(export_ssh_ca_public))
        .route("/api/v1/ssh/cas/:id/rotate", post(rotate_ssh_ca))
        .route(
            "/api/v1/ssh/certificates",
            get(list_ssh_certificates).post(issue_ssh_certificate),
        )
        .route(
            "/api/v1/ssh/certificates/:id",
            get(get_ssh_certificate).delete(delete_ssh_certificate),
        )
        .route(
            "/api/v1/ssh/certificates/:id/revoke",
            post(revoke_ssh_certificate),
        )
        .route(
            "/api/v1/settings/defaults",
            get(get_defaults).put(save_defaults),
        )
        .route(
            "/api/v1/settings/notifications",
            get(get_notification_settings).put(save_notification_settings),
        )
        .route(
            "/api/v1/settings/siem",
            get(get_siem_settings).put(save_siem_settings),
        )
        .route(
            "/api/v1/settings/machine-monitor",
            get(get_machine_monitor_settings).put(save_machine_monitor_settings),
        )
        .route(
            "/api/v1/applications",
            get(list_applications).post(create_application),
        )
        .route(
            "/api/v1/applications/:id",
            patch(update_application).delete(delete_application),
        )
        .route(
            "/api/v1/applications/:id/duplicate",
            post(duplicate_application),
        )
        .route(
            "/api/v1/credentials",
            get(list_credentials).post(create_credential),
        )
        .route(
            "/api/v1/credentials/:id",
            patch(update_credential).delete(delete_credential),
        )
        .route(
            "/api/v1/host-credentials",
            get(list_host_credentials).post(create_host_credential),
        )
        .route(
            "/api/v1/host-credentials/:id",
            axum::routing::delete(delete_host_credential),
        )
        .route(
            "/api/v1/host-applications",
            get(list_host_applications).post(create_host_application),
        )
        .route(
            "/api/v1/host-applications/:id",
            patch(update_host_application).delete(delete_host_application),
        )
        .route(
            "/api/v1/host-applications/:id/deploy",
            post(deploy_host_application),
        )
        .route(
            "/api/v1/host-applications/:id/check",
            post(check_host_application),
        )
        .route(
            "/api/v1/host-applications/:id/deployments",
            get(list_host_application_deployments),
        )
        .route(
            "/api/v1/deployments/:job_id/journal",
            get(get_deployment_journal),
        )
        .route(
            "/api/v1/certbot/configs",
            get(list_certbot_configs).post(create_certbot_config),
        )
        .route(
            "/api/v1/certbot/configs/:id",
            axum::routing::delete(delete_certbot_config),
        )
        .route("/api/v1/certbot/configs/:id/run", post(run_certbot_config))
        .route("/api/v1/integrations/addons", get(list_addons))
        .route("/api/v1/integrations/plan", post(build_integration_plan))
        .route("/api/v1/logs/actions", get(list_action_logs))
        .route("/api/v1/logs/access", get(list_access_logs))
        .route("/api/v1/logs/security", get(list_security_logs))
        .route("/api/v1/audit", get(list_action_logs))
        .route("/api/v1/network/resolve", get(resolve_network_info))
        .route("/api/v1/network/match", get(match_hostname))
        .route("/api/v1/network/scan", post(scan_network))
        .route("/api/v1/backup/export", get(backup_export))
        .route("/api/v1/backup/import", post(backup_import))
        .route("/api/v1/backup/run", post(backup_run))
        .route("/api/v1/backup/list", get(backup_list))
        .route(
            "/api/v1/settings/backup",
            get(get_backup_settings).put(save_backup_settings),
        )
        .route(
            "/api/v1/settings/backup/remote",
            get(get_backup_remote_settings).put(save_backup_remote_settings),
        )
        .route("/api/v1/backup/remote/test", post(test_backup_remote))
        .route(
            "/api/v1/settings/crl/remote",
            get(get_crl_remote_settings).put(save_crl_remote_settings),
        )
        .route("/api/v1/crl/remote/test", post(test_crl_remote))
        .route("/api/v1/crl/publish", post(publish_crl_now))
        .route(
            "/api/v1/settings/deploy-html/remote",
            get(get_deploy_html_remote_settings).put(save_deploy_html_remote_settings),
        )
        .route(
            "/api/v1/deploy-html/remote/test",
            post(test_deploy_html_remote),
        )
        .route("/api/v1/deploy-html/preview", get(preview_deploy_html))
        .route("/api/v1/deploy-html/publish", post(publish_deploy_html))
        .route("/api/v1/backup/restore", post(backup_restore))
        .route(
            "/api/v1/backup/recipients",
            get(list_backup_recipients).post(add_backup_recipient),
        )
        .route(
            "/api/v1/backup/recipients/:id",
            axum::routing::delete(delete_backup_recipient),
        )
}

pub async fn health() -> Json<serde_json::Value> {
    // La version vient de Cargo.toml et de nulle part ailleurs. Elle était
    // écrite en dur ici, dans deploy/pod.yaml, dans la page web et dans
    // openapi.json — quatre valeurs, dont trois avaient déjà divergé.
    Json(json!({
        "status": "ok",
        "service": "akamana",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Serves the signed X.509 CRL (DER) for a root CA at `/crl/<root_id>.crl`.
/// Public (non-`/api/` path, so it skips the token check) — this is the URL
/// embedded in issued certs' CRL Distribution Point.
pub async fn serve_crl(
    axum::extract::Path(file): axum::extract::Path<String>,
    State(state): State<AppState>,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let root_id: i32 = file
        .strip_suffix(".crl")
        .and_then(|s| s.parse().ok())
        .ok_or(AppError::NotFound)?;
    let der = crate::crypto::generate_crl_der(&state.pool, &state.cfg, root_id).await?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/pkix-crl")],
        der,
    )
        .into_response())
}

/// Serves the machine-readable OpenAPI spec. Public (allow-listed in
/// `auth_guard`) so scripts can discover the API without a token.
pub async fn openapi_spec() -> axum::response::Response {
    use axum::response::IntoResponse;
    const SPEC: &str = include_str!("../../openapi.json");
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        SPEC,
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct PaginationParams {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct RootCertDetailRow {
    id: i32,
    common_name: String,
    organization: String,
    description: Option<String>,
    cert_pem: String,
    not_before: chrono::NaiveDateTime,
    not_after: chrono::NaiveDateTime,
    is_revoked: bool,
    revoked_at: Option<chrono::NaiveDateTime>,
    revoked_reason: Option<String>,
    cipher: String,
    key_length: i32,
}

fn parse_pagination(params: PaginationParams) -> (i64, i64) {
    let limit = params.limit.unwrap_or(200).clamp(1, 1000);
    let offset = params.offset.unwrap_or(0).max(0);
    (limit, offset)
}

fn parse_pagination_from_map(params: &HashMap<String, String>) -> (i64, i64) {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(200)
        .clamp(1, 1000);
    let offset = params
        .get("offset")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    (limit, offset)
}

fn organization_filename_prefix(organization: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;

    for ch in organization.trim().chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_sep = false;
        } else if !prev_sep {
            out.push('-');
            prev_sep = true;
        }
    }

    let normalized = out.trim_matches('-');
    if normalized.is_empty() {
        "organization".to_string()
    } else {
        normalized.to_string()
    }
}

// ---------------------------------------------------------------------------
// Sign-in
//
// A local sign-in is up to two steps. `/auth/login` checks the password; if the
// account has a second factor (or MFA is mandatory and it has none yet) it
// answers with a `MfaChallengeResponse` carrying a short-lived `mfa_token`
// instead of a session, and the client finishes at `/auth/login/mfa` (verify)
// or `/auth/login/mfa/enroll/*` (forced enrollment). Passkeys skip the password
// entirely via `/auth/passkey/login/*`.
//
// Every branch that ends in "no session" returns `AppError::Auth`, so a client
// can never tell a wrong username from a wrong password from a wrong code.
// ---------------------------------------------------------------------------

/// Public, unauthenticated description of this deployment: what the product is
/// called and which sign-in options the login screen should offer.
async fn branding(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "app_title": state.cfg.app_title,
        "auth_mode": match state.cfg.auth_mode {
            crate::config::AuthMode::Local => "local",
            crate::config::AuthMode::Oidc => "oidc",
        },
        "passkeys_enabled": passkey::is_enabled(),
        "password_reset_enabled": crate::notifier::smtp_configured(),
        "require_mfa": state.cfg.require_mfa,
    }))
}

fn session_for(state: &AppState, user: &LocalUser) -> AppResult<TokenResponse> {
    let (token, expires) = create_local_token(&state.cfg, &user.username, &user.role)?;
    Ok(TokenResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in_seconds: expires,
        username: user.username.clone(),
        role: user.role.clone(),
    })
}

async fn unused_recovery_code_count(state: &AppState, user_id: &str) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(row.0)
}

/// Replaces every recovery code for a user and returns the new plaintext set —
/// the only time the operator ever sees them.
async fn issue_recovery_codes(state: &AppState, user_id: &str) -> AppResult<Vec<String>> {
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(&state.pool)
        .await?;

    let codes = mfa::generate_recovery_codes(mfa::RECOVERY_CODE_COUNT);
    let now = Utc::now().naive_utc();
    for code in &codes {
        sqlx::query(
            "INSERT INTO user_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(sha256_hex(&mfa::normalize_recovery_code(code)))
        .bind(now)
        .execute(&state.pool)
        .await?;
    }
    Ok(codes)
}

/// Marks a recovery code used, atomically. The conditional `UPDATE` is what
/// makes a code single-use even if two requests race.
async fn consume_recovery_code(state: &AppState, user_id: &str, code: &str) -> AppResult<bool> {
    let normalized = mfa::normalize_recovery_code(code);
    if normalized.len() < 8 {
        return Ok(false);
    }
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM user_recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .bind(sha256_hex(&normalized))
    .fetch_optional(&state.pool)
    .await?;

    let Some((id,)) = row else {
        return Ok(false);
    };
    let result =
        sqlx::query("UPDATE user_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL")
            .bind(Utc::now().naive_utc())
            .bind(&id)
            .execute(&state.pool)
            .await?;
    Ok(result.rows_affected() == 1)
}

fn now_unix() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

pub async fn login(
    State(state): State<AppState>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<LoginOutcome>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    let ip = client_ip.0;
    enforce_login_rate_limit(&state.pool, &payload.username, &ip).await?;

    let candidate = load_local_user(&state.pool, &payload.username).await?;
    let password_ok = match &candidate {
        Some(user) => verify_password(&user.password_hash, &payload.password),
        None => {
            spend_password_verification_time(&payload.password);
            false
        }
    };

    let Some(user) = candidate.filter(|_| password_ok) else {
        record_login_attempt(&state.pool, &payload.username, &ip, false).await;
        let _ = audit(
            &state,
            &payload.username,
            "auth.login.failed",
            "user",
            &payload.username,
            json!({"reason": "bad_credentials", "source_ip": ip}),
        )
        .await;
        return Err(AppError::Auth);
    };

    // Second factor enrolled: hand back a challenge, not a session.
    if user.totp_enabled && user.totp_secret_enc.is_some() {
        let (mfa_token, expires) = create_mfa_token(&state.cfg, &user.username, "mfa")?;
        let mut methods = vec!["totp".to_string()];
        if unused_recovery_code_count(&state, &user.id).await? > 0 {
            methods.push("recovery".to_string());
        }
        return Ok(Json(LoginOutcome::Mfa(MfaChallengeResponse {
            mfa_required: true,
            mfa_setup_required: false,
            mfa_token,
            expires_in_seconds: expires,
            methods,
            username: user.username,
        })));
    }

    // MFA is mandatory but this account has nothing enrolled: force enrollment
    // before the session is issued.
    if state.cfg.require_mfa {
        let (mfa_token, expires) = create_mfa_token(&state.cfg, &user.username, "mfa-setup")?;
        return Ok(Json(LoginOutcome::Mfa(MfaChallengeResponse {
            mfa_required: true,
            mfa_setup_required: true,
            mfa_token,
            expires_in_seconds: expires,
            methods: vec!["totp".to_string()],
            username: user.username,
        })));
    }

    let session = session_for(&state, &user)?;
    record_login_attempt(&state.pool, &user.username, &ip, true).await;
    clear_login_failures(&state.pool, &user.username).await;
    audit(
        &state,
        &user.username,
        "auth.login",
        "user",
        &user.username,
        json!({"success": true, "mfa": false}),
    )
    .await?;
    Ok(Json(LoginOutcome::Token(session)))
}

/// Second step of a password sign-in: a TOTP code or a recovery code.
async fn login_mfa(
    State(state): State<AppState>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Json(payload): Json<MfaLoginRequest>,
) -> AppResult<Json<TokenResponse>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    let (username, purpose) = decode_mfa_token(&state.cfg, &payload.mfa_token)?;
    if purpose != "mfa" {
        return Err(AppError::Auth);
    }

    let ip = client_ip.0;
    enforce_login_rate_limit(&state.pool, &username, &ip).await?;

    let user = load_local_user(&state.pool, &username)
        .await?
        .ok_or(AppError::Auth)?;
    let secret_enc = user.totp_secret_enc.clone().ok_or(AppError::Auth)?;
    if !user.totp_enabled {
        return Err(AppError::Auth);
    }

    let secret = decrypt_secret(&state.cfg, &secret_enc)?;
    let mut method = "totp";
    let mut accepted = mfa::verify_totp(&secret, &payload.code, now_unix());
    if !accepted {
        accepted = consume_recovery_code(&state, &user.id, &payload.code).await?;
        if accepted {
            method = "recovery_code";
        }
    }

    if !accepted {
        record_login_attempt(&state.pool, &username, &ip, false).await;
        let _ = audit(
            &state,
            &username,
            "auth.login.failed",
            "user",
            &username,
            json!({"reason": "bad_second_factor", "source_ip": ip}),
        )
        .await;
        return Err(AppError::Auth);
    }

    let session = session_for(&state, &user)?;
    record_login_attempt(&state.pool, &username, &ip, true).await;
    clear_login_failures(&state.pool, &username).await;
    audit(
        &state,
        &username,
        "auth.login",
        "user",
        &username,
        json!({"success": true, "mfa": true, "method": method}),
    )
    .await?;
    Ok(Json(session))
}

/// Forced-enrollment path (`REQUIRE_MFA=true`, account has no factor): mint a
/// secret against the half-authenticated MFA token.
async fn login_mfa_enroll_start(
    State(state): State<AppState>,
    Json(payload): Json<MfaTokenRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    let (username, purpose) = decode_mfa_token(&state.cfg, &payload.mfa_token)?;
    if purpose != "mfa-setup" {
        return Err(AppError::Auth);
    }
    let user = load_local_user(&state.pool, &username)
        .await?
        .ok_or(AppError::Auth)?;
    Ok(Json(begin_totp_enrollment(&state, &user).await?))
}

/// Confirms the forced enrollment and, only then, issues the session.
async fn login_mfa_enroll_finish(
    State(state): State<AppState>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Json(payload): Json<MfaLoginRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    let (username, purpose) = decode_mfa_token(&state.cfg, &payload.mfa_token)?;
    if purpose != "mfa-setup" {
        return Err(AppError::Auth);
    }

    let ip = client_ip.0;
    enforce_login_rate_limit(&state.pool, &username, &ip).await?;

    let user = load_local_user(&state.pool, &username)
        .await?
        .ok_or(AppError::Auth)?;
    let codes = confirm_totp_enrollment(&state, &user, &payload.code).await?;

    let session = session_for(&state, &user)?;
    record_login_attempt(&state.pool, &username, &ip, true).await;
    clear_login_failures(&state.pool, &username).await;
    audit(
        &state,
        &username,
        "auth.login",
        "user",
        &username,
        json!({"success": true, "mfa": true, "method": "totp_enrollment"}),
    )
    .await?;

    Ok(Json(json!({
        "access_token": session.access_token,
        "token_type": session.token_type,
        "expires_in_seconds": session.expires_in_seconds,
        "username": session.username,
        "role": session.role,
        "recovery_codes": codes,
    })))
}

// ---------------------------------------------------------------------------
// TOTP enrollment
// ---------------------------------------------------------------------------

/// Renders an `otpauth://` URI as an SVG QR code, inlined as a `data:` URL so
/// it can be dropped straight into an `<img>` without loosening the CSP.
fn qr_data_url(payload: &str) -> AppResult<String> {
    let code = qrcode::QrCode::new(payload.as_bytes())
        .map_err(|e| AppError::Internal(format!("QR encoding failed: {e}")))?;
    let svg = code
        .render()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#101828"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg.as_bytes())
    ))
}

/// Stores a fresh (still unconfirmed) TOTP secret and returns everything the
/// enrollment screen needs. The secret only becomes usable once a code proves
/// the authenticator really has it.
async fn begin_totp_enrollment(state: &AppState, user: &LocalUser) -> AppResult<serde_json::Value> {
    if user.totp_enabled {
        return Err(AppError::Validation(
            "Two-factor authentication is already enabled for this account. Turn it off before enrolling again.".to_string(),
        ));
    }

    let secret = mfa::generate_totp_secret();
    let encrypted = encrypt_secret(&state.cfg, &secret)?;
    sqlx::query(
        "UPDATE users SET totp_secret_enc = ?, totp_enabled = FALSE, totp_confirmed_at = NULL, updated_at = ? WHERE id = ?",
    )
    .bind(&encrypted)
    .bind(Utc::now().naive_utc())
    .bind(&user.id)
    .execute(&state.pool)
    .await?;

    let uri = mfa::otpauth_uri(&state.cfg.app_title, &user.username, &secret);
    Ok(json!({
        "secret": secret,
        "otpauth_uri": uri,
        "qr_data_url": qr_data_url(&uri)?,
        "digits": mfa::TOTP_DIGITS,
        "period_seconds": mfa::TOTP_STEP_SECONDS,
    }))
}

/// Verifies the first code, flips the account to MFA-enabled and mints the
/// recovery codes. Returns the plaintext codes for one-time display.
async fn confirm_totp_enrollment(
    state: &AppState,
    user: &LocalUser,
    code: &str,
) -> AppResult<Vec<String>> {
    let secret_enc = user.totp_secret_enc.clone().ok_or_else(|| {
        AppError::Validation(
            "No enrollment is in progress. Start setting up two-factor authentication first."
                .to_string(),
        )
    })?;
    let secret = decrypt_secret(&state.cfg, &secret_enc)?;
    if !mfa::verify_totp(&secret, code, now_unix()) {
        return Err(AppError::Validation(
            "That code didn't match. Check your authenticator app's clock and try the current code."
                .to_string(),
        ));
    }

    let now = Utc::now().naive_utc();
    sqlx::query(
        "UPDATE users SET totp_enabled = TRUE, totp_confirmed_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(now)
    .bind(now)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;

    let codes = issue_recovery_codes(state, &user.id).await?;
    audit(
        state,
        &user.username,
        "user.mfa.totp.enabled",
        "user",
        &user.id,
        json!({}),
    )
    .await?;
    Ok(codes)
}

async fn current_user(state: &AppState, auth_user: &AuthenticatedUser) -> AppResult<LocalUser> {
    load_local_user(&state.pool, &auth_user.username)
        .await?
        .ok_or(AppError::NotFound)
}

async fn mfa_status(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    let user = current_user(&state, &auth_user).await?;

    let passkeys = sqlx::query_as::<_, (String, String, chrono::NaiveDateTime, Option<chrono::NaiveDateTime>)>(
        "SELECT id, name, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(json!({
        "username": user.username,
        "email": user.email,
        "totp_enabled": user.totp_enabled,
        "totp_enrollment_pending": !user.totp_enabled && user.totp_secret_enc.is_some(),
        "recovery_codes_remaining": unused_recovery_code_count(&state, &user.id).await?,
        "passkeys_supported": passkey::is_enabled(),
        "passkeys": passkeys.into_iter().map(|p| json!({
            "id": p.0,
            "name": p.1,
            "created_at": p.2,
            "last_used_at": p.3,
        })).collect::<Vec<_>>(),
        "require_mfa": state.cfg.require_mfa,
    })))
}

async fn totp_setup(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    let user = current_user(&state, &auth_user).await?;
    Ok(Json(begin_totp_enrollment(&state, &user).await?))
}

async fn totp_confirm(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<TotpCodeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    let user = current_user(&state, &auth_user).await?;
    if user.totp_enabled {
        return Err(AppError::Validation(
            "Two-factor authentication is already enabled for this account.".to_string(),
        ));
    }
    let codes = confirm_totp_enrollment(&state, &user, &payload.code).await?;
    Ok(Json(json!({"status": "enabled", "recovery_codes": codes})))
}

async fn totp_disable(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<DisableMfaRequest>,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    let user = current_user(&state, &auth_user).await?;
    if !verify_password(&user.password_hash, &payload.password) {
        return Err(AppError::Validation(
            "That password is not correct.".to_string(),
        ));
    }

    sqlx::query(
        "UPDATE users SET totp_secret_enc = NULL, totp_enabled = FALSE, totp_confirmed_at = NULL, updated_at = ? WHERE id = ?",
    )
    .bind(Utc::now().naive_utc())
    .bind(&user.id)
    .execute(&state.pool)
    .await?;
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = ?")
        .bind(&user.id)
        .execute(&state.pool)
        .await?;

    audit(
        &state,
        &auth_user.username,
        "user.mfa.totp.disabled",
        "user",
        &user.id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status": "disabled"})))
}

async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    let user = current_user(&state, &auth_user).await?;
    if !user.totp_enabled {
        return Err(AppError::Validation(
            "Recovery codes only apply once two-factor authentication is enabled.".to_string(),
        ));
    }
    let codes = issue_recovery_codes(&state, &user.id).await?;
    audit(
        &state,
        &auth_user.username,
        "user.mfa.recovery_codes.regenerated",
        "user",
        &user.id,
        json!({"count": codes.len()}),
    )
    .await?;
    Ok(Json(json!({"recovery_codes": codes})))
}

// ---------------------------------------------------------------------------
// Passkeys (WebAuthn)
//
// Both ceremonies are two calls with server-side state in between. That state
// lives in `webauthn_challenges`: single-use rows with a few minutes' TTL,
// consumed by `take_webauthn_challenge`.
// ---------------------------------------------------------------------------

const WEBAUTHN_CHALLENGE_MINUTES: i64 = 5;

async fn store_webauthn_challenge<T: Serialize>(
    state: &AppState,
    username: &str,
    purpose: &str,
    value: &T,
) -> AppResult<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let state_json = serde_json::to_string(value)
        .map_err(|e| AppError::Internal(format!("WebAuthn state serialization failed: {e}")))?;

    // Opportunistic cleanup: these rows are worthless once expired.
    sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at < ?")
        .bind(now.naive_utc())
        .execute(&state.pool)
        .await?;

    sqlx::query(
        "INSERT INTO webauthn_challenges (id, username, purpose, state_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(username)
    .bind(purpose)
    .bind(state_json)
    .bind(now.naive_utc())
    .bind((now + chrono::Duration::minutes(WEBAUTHN_CHALLENGE_MINUTES)).naive_utc())
    .execute(&state.pool)
    .await?;
    Ok(id)
}

/// Fetches and deletes a challenge in one shot. The row must match the
/// username and purpose it was created for, so a registration challenge can't
/// be replayed into the authentication ceremony.
async fn take_webauthn_challenge<T: DeserializeOwned>(
    state: &AppState,
    id: &str,
    username: &str,
    purpose: &str,
) -> AppResult<T> {
    let row: Option<(String, chrono::NaiveDateTime)> = sqlx::query_as(
        "SELECT state_json, expires_at FROM webauthn_challenges WHERE id = ? AND username = ? AND purpose = ?",
    )
    .bind(id)
    .bind(username)
    .bind(purpose)
    .fetch_optional(&state.pool)
    .await?;

    sqlx::query("DELETE FROM webauthn_challenges WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await?;

    let Some((state_json, expires_at)) = row else {
        return Err(AppError::Auth);
    };
    if expires_at < Utc::now().naive_utc() {
        return Err(AppError::Auth);
    }
    serde_json::from_str(&state_json)
        .map_err(|e| AppError::Internal(format!("WebAuthn state deserialization failed: {e}")))
}

/// Returns `(row id, passkey)` for every credential registered to a user.
/// A credential whose stored JSON no longer parses is skipped rather than
/// failing the whole sign-in.
async fn load_user_passkeys(state: &AppState, user_id: &str) -> AppResult<Vec<(String, Passkey)>> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT id, passkey_json FROM webauthn_credentials WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(
            |(id, json_text)| match serde_json::from_str::<Passkey>(&json_text) {
                Ok(passkey) => Some((id, passkey)),
                Err(e) => {
                    tracing::warn!("skipping unreadable passkey row id={id}: {e}");
                    None
                }
            },
        )
        .collect())
}

fn credential_id_b64(cred_id: &CredentialID) -> String {
    let bytes: &[u8] = cred_id.as_ref();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

async fn passkey_register_start(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<PasskeyRegisterStartRequest>,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    let webauthn = passkey::instance()?;
    let user = current_user(&state, &auth_user).await?;
    let user_uuid = Uuid::parse_str(&user.id)
        .map_err(|e| AppError::Internal(format!("user id is not a UUID: {e}")))?;

    let existing = load_user_passkeys(&state, &user.id).await?;
    let exclude: Vec<CredentialID> = existing
        .iter()
        .map(|(_, pk)| pk.cred_id().clone())
        .collect();

    let (challenge, registration) = webauthn
        .start_passkey_registration(user_uuid, &user.username, &user.username, Some(exclude))
        .map_err(|e| passkey::ceremony_error("register_start", e))?;

    let challenge_id =
        store_webauthn_challenge(&state, &user.username, "register", &registration).await?;

    Ok(Json(json!({
        "challenge_id": challenge_id,
        "options": challenge,
        "name": payload.name,
    })))
}

async fn passkey_register_finish(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<PasskeyRegisterFinishRequest>,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    let webauthn = passkey::instance()?;
    let user = current_user(&state, &auth_user).await?;

    let credential: RegisterPublicKeyCredential = serde_json::from_value(payload.credential)
        .map_err(|e| AppError::Validation(format!("Malformed passkey registration: {e}")))?;
    let registration: PasskeyRegistration =
        take_webauthn_challenge(&state, &payload.challenge_id, &user.username, "register").await?;

    let registered = webauthn
        .finish_passkey_registration(&credential, &registration)
        .map_err(|e| passkey::ceremony_error("register_finish", e))?;

    let id = Uuid::new_v4().to_string();
    let passkey_json = serde_json::to_string(&registered)
        .map_err(|e| AppError::Internal(format!("passkey serialization failed: {e}")))?;

    sqlx::query(
        "INSERT INTO webauthn_credentials (id, user_id, name, credential_id, passkey_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(&payload.name)
    .bind(credential_id_b64(registered.cred_id()))
    .bind(passkey_json)
    .bind(Utc::now().naive_utc())
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "user.mfa.passkey.registered",
        "user",
        &user.id,
        json!({"name": payload.name}),
    )
    .await?;
    Ok(Json(json!({"status": "registered", "id": id})))
}

async fn list_passkeys(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<Vec<serde_json::Value>>> {
    require_human(&auth_user)?;
    let user = current_user(&state, &auth_user).await?;
    let rows = sqlx::query_as::<_, (String, String, chrono::NaiveDateTime, Option<chrono::NaiveDateTime>)>(
        "SELECT id, name, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| json!({"id": r.0, "name": r.1, "created_at": r.2, "last_used_at": r.3}))
            .collect(),
    ))
}

async fn delete_passkey(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    let user = current_user(&state, &auth_user).await?;
    let result = sqlx::query("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(&user.id)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        &state,
        &auth_user.username,
        "user.mfa.passkey.removed",
        "user",
        &user.id,
        json!({"passkey_id": id}),
    )
    .await?;
    Ok(Json(json!({"status": "deleted"})))
}

async fn passkey_login_start(
    State(state): State<AppState>,
    Json(payload): Json<PasskeyLoginStartRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    let webauthn = passkey::instance()?;

    let user = load_local_user(&state.pool, &payload.username)
        .await?
        .ok_or(AppError::Auth)?;
    let passkeys: Vec<Passkey> = load_user_passkeys(&state, &user.id)
        .await?
        .into_iter()
        .map(|(_, pk)| pk)
        .collect();
    if passkeys.is_empty() {
        return Err(AppError::Auth);
    }

    let (challenge, authentication) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| passkey::ceremony_error("auth_start", e))?;
    let challenge_id =
        store_webauthn_challenge(&state, &user.username, "authenticate", &authentication).await?;

    Ok(Json(json!({
        "challenge_id": challenge_id,
        "options": challenge,
    })))
}

async fn passkey_login_finish(
    State(state): State<AppState>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Json(payload): Json<PasskeyLoginFinishRequest>,
) -> AppResult<Json<TokenResponse>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    let webauthn = passkey::instance()?;

    // The challenge row is the only thing tying this call to a user, so read the
    // username off it rather than trusting anything in the request body.
    let owner: Option<(String,)> = sqlx::query_as(
        "SELECT username FROM webauthn_challenges WHERE id = ? AND purpose = 'authenticate'",
    )
    .bind(&payload.challenge_id)
    .fetch_optional(&state.pool)
    .await?;
    let username = owner.map(|r| r.0).ok_or(AppError::Auth)?;

    let ip = client_ip.0;
    enforce_login_rate_limit(&state.pool, &username, &ip).await?;

    let user = load_local_user(&state.pool, &username)
        .await?
        .ok_or(AppError::Auth)?;

    let credential: PublicKeyCredential = serde_json::from_value(payload.credential)
        .map_err(|e| AppError::Validation(format!("Malformed passkey assertion: {e}")))?;
    let authentication: PasskeyAuthentication =
        take_webauthn_challenge(&state, &payload.challenge_id, &username, "authenticate").await?;

    let result = match webauthn.finish_passkey_authentication(&credential, &authentication) {
        Ok(result) => result,
        Err(e) => {
            record_login_attempt(&state.pool, &username, &ip, false).await;
            return Err(passkey::ceremony_error("auth_finish", e));
        }
    };

    // Persist the bumped signature counter so cloned-authenticator detection
    // keeps working across sign-ins.
    let matched_id = credential_id_b64(result.cred_id());
    for (row_id, mut stored) in load_user_passkeys(&state, &user.id).await? {
        if credential_id_b64(stored.cred_id()) != matched_id {
            continue;
        }
        if stored.update_credential(&result).is_some() {
            if let Ok(updated_json) = serde_json::to_string(&stored) {
                sqlx::query(
                    "UPDATE webauthn_credentials SET passkey_json = ?, last_used_at = ? WHERE id = ?",
                )
                .bind(updated_json)
                .bind(Utc::now().naive_utc())
                .bind(&row_id)
                .execute(&state.pool)
                .await?;
                break;
            }
        }
        sqlx::query("UPDATE webauthn_credentials SET last_used_at = ? WHERE id = ?")
            .bind(Utc::now().naive_utc())
            .bind(&row_id)
            .execute(&state.pool)
            .await?;
        break;
    }

    let session = session_for(&state, &user)?;
    record_login_attempt(&state.pool, &username, &ip, true).await;
    clear_login_failures(&state.pool, &username).await;
    audit(
        &state,
        &username,
        "auth.login",
        "user",
        &username,
        json!({"success": true, "method": "passkey"}),
    )
    .await?;
    Ok(Json(session))
}

// ---------------------------------------------------------------------------
// Password reset
//
// A reset token is a 32-byte random string; only its SHA-256 is stored, and it
// is single-use and short-lived. The request endpoint answers identically
// whether or not the account exists, so it can't be used to enumerate users.
// ---------------------------------------------------------------------------

const RESET_TOKEN_VALID_MINUTES: i64 = 60;

/// Mints a reset token for `user_id` and invalidates any outstanding ones.
/// Returns `(token, expires_at)`.
async fn mint_reset_token(
    state: &AppState,
    user_id: &str,
    created_by: &str,
    source_ip: &str,
) -> AppResult<(String, chrono::NaiveDateTime)> {
    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL")
        .bind(user_id)
        .execute(&state.pool)
        .await?;

    let mut raw = [0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);

    let now = Utc::now();
    let expires_at = (now + chrono::Duration::minutes(RESET_TOKEN_VALID_MINUTES)).naive_utc();
    sqlx::query(
        "INSERT INTO password_reset_tokens (id, user_id, token_hash, created_at, expires_at, created_by, requested_ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(sha256_hex(&token))
    .bind(now.naive_utc())
    .bind(expires_at)
    .bind(created_by)
    .bind(source_ip)
    .execute(&state.pool)
    .await?;

    Ok((token, expires_at))
}

fn reset_url(base: &str, token: &str) -> String {
    format!("{}/#reset={}", base.trim_end_matches('/'), token)
}

async fn password_reset_request(
    State(state): State<AppState>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Json(payload): Json<PasswordResetRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    let identifier = payload.identifier.trim().to_string();
    let found: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, username, email FROM users WHERE username = ? OR (email IS NOT NULL AND email <> '' AND email = ?) LIMIT 1",
    )
    .bind(&identifier)
    .bind(&identifier)
    .fetch_optional(&state.pool)
    .await?;

    // Everything below is best-effort and silent: the response must not depend
    // on whether the account exists or the mail went out.
    if let Some((user_id, username, Some(email))) = found {
        if !email.trim().is_empty() {
            match mint_reset_token(&state, &user_id, "self-service", &client_ip.0).await {
                Ok((token, expires_at)) => {
                    let base = read_setting_value(&state, "public_base_url")
                        .await
                        .unwrap_or_default();
                    let where_to_go = if base.trim().is_empty() {
                        format!(
                            "Open {} in your browser and append  #reset={token}  to the address.",
                            state.cfg.app_title
                        )
                    } else {
                        reset_url(base.trim(), &token)
                    };
                    let body = format!(
                        "Hello {username},\n\n\
                         Someone asked to reset the password for your {title} account.\n\n\
                         {where_to_go}\n\n\
                         The link works once and expires at {expires_at} UTC.\n\
                         If this wasn't you, you can ignore this message — your password has not changed.\n",
                        title = state.cfg.app_title,
                    );
                    if let Err(e) = crate::notifier::send_text_email(
                        email.trim(),
                        &format!("{} password reset", state.cfg.app_title),
                        &body,
                    )
                    .await
                    {
                        tracing::warn!("password_reset_email_failed: user={username} error={e}");
                    }
                    let _ = audit(
                        &state,
                        &username,
                        "auth.password_reset.requested",
                        "user",
                        &user_id,
                        json!({"source_ip": client_ip.0}),
                    )
                    .await;
                }
                Err(e) => tracing::warn!("password_reset_token_failed: user={username} error={e}"),
            }
        }
    }

    Ok(Json(json!({
        "status": "accepted",
        "message": "If that account exists and has an email address on file, a reset link is on its way.",
    })))
}

async fn password_reset_confirm(
    State(state): State<AppState>,
    Json(payload): Json<PasswordResetConfirmRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    let invalid = || {
        AppError::Validation("This reset link is no longer valid. Ask for a new one.".to_string())
    };

    let row: Option<(
        String,
        String,
        chrono::NaiveDateTime,
        Option<chrono::NaiveDateTime>,
    )> = sqlx::query_as(
        "SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = ?",
    )
    .bind(sha256_hex(&payload.token))
    .fetch_optional(&state.pool)
    .await?;

    let Some((token_id, user_id, expires_at, used_at)) = row else {
        return Err(invalid());
    };
    if used_at.is_some() || expires_at < Utc::now().naive_utc() {
        return Err(invalid());
    }

    // Burn the token first, conditionally, so two concurrent submissions can't
    // both go through.
    let burned = sqlx::query(
        "UPDATE password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL",
    )
    .bind(Utc::now().naive_utc())
    .bind(&token_id)
    .execute(&state.pool)
    .await?;
    if burned.rows_affected() != 1 {
        return Err(invalid());
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("unable to hash password: {e}")))?
        .to_string();

    let username: Option<(String,)> = sqlx::query_as("SELECT username FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await?;
    let username = username.map(|r| r.0).ok_or_else(invalid)?;

    sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(hash)
        .bind(Utc::now().naive_utc())
        .bind(&user_id)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL")
        .bind(&user_id)
        .execute(&state.pool)
        .await?;
    clear_login_failures(&state.pool, &username).await;

    audit(
        &state,
        &username,
        "auth.password_reset.completed",
        "user",
        &user_id,
        json!({}),
    )
    .await?;

    Ok(Json(json!({
        "status": "updated",
        "message": "Your password has been changed. You can sign in now.",
    })))
}

/// Admin escape hatch for deployments with no SMTP relay: generate a reset link
/// and hand it to the user over whatever channel you trust.
async fn create_user_reset_link(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }

    let target: Option<(String,)> = sqlx::query_as("SELECT username FROM users WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
    let username = target.map(|r| r.0).ok_or(AppError::NotFound)?;

    let (token, expires_at) =
        mint_reset_token(&state, &id, &auth_user.username, &client_ip.0).await?;
    let base = read_setting_value(&state, "public_base_url")
        .await
        .unwrap_or_default();

    audit(
        &state,
        &auth_user.username,
        "user.password_reset.link_issued",
        "user",
        &id,
        json!({"username": username}),
    )
    .await?;

    Ok(Json(json!({
        "username": username,
        // Relative form so the UI can fall back to the address it is served on.
        "path": format!("/#reset={token}"),
        "url": if base.trim().is_empty() { serde_json::Value::Null } else { json!(reset_url(base.trim(), &token)) },
        "expires_at": expires_at,
        "valid_minutes": RESET_TOKEN_VALID_MINUTES,
    })))
}

async fn update_user_email(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<UpdateUserEmailRequest>,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    let email = normalize_optional_email(&payload.email)?;
    sqlx::query("UPDATE users SET email = ?, updated_at = ? WHERE id = ?")
        .bind(&email)
        .bind(Utc::now().naive_utc())
        .bind(&id)
        .execute(&state.pool)
        .await?;

    audit(
        &state,
        &auth_user.username,
        "user.email.update",
        "user",
        &id,
        json!({"email": email.clone()}),
    )
    .await?;
    Ok(Json(json!({"status": "updated", "email": email})))
}

/// Trims and sanity-checks an address. Deliberately permissive — internal-lab
/// deployments use hosts like `ops@lab` — it only rejects shapes that could
/// never be delivered.
fn normalize_optional_email(raw: &str) -> AppResult<Option<String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parts: Vec<&str> = trimmed.split('@').collect();
    let looks_like_address = parts.len() == 2
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && !trimmed.contains(char::is_whitespace);
    if !looks_like_address {
        return Err(AppError::Validation(
            "That doesn't look like an email address.".to_string(),
        ));
    }
    Ok(Some(trimmed.to_string()))
}

async fn list_root_certs(State(state): State<AppState>) -> AppResult<Json<Vec<serde_json::Value>>> {
    let rows = sqlx::query_as::<
        _,
        (
            i32,
            String,
            String,
            Option<String>,
            chrono::NaiveDateTime,
            chrono::NaiveDateTime,
            chrono::NaiveDateTime,
            bool,
            Option<chrono::NaiveDateTime>,
            Option<String>,
            String,
            i32,
        ),
    >(
        "SELECT id, common_name, organization, description, not_before, not_after, created_at, is_revoked, revoked_at, revoked_reason, cipher, key_length FROM root_ca ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                json!({
                    "id": r.0,
                    "common_name": r.1,
                    "organization": r.2,
                    "description": r.3,
                    "not_before": r.4,
                    "not_after": r.5,
                    "created_at": r.6,
                    "is_revoked": r.7,
                    "revoked_at": r.8,
                    "revoked_reason": r.9,
                    "cipher": r.10,
                    "key_length": r.11,
                })
            })
            .collect(),
    ))
}

async fn create_organization_root(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateOrganizationRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin" | "tls_admin") {
        return Err(AppError::Forbidden);
    }

    let root_id = create_root_ca(
        &state.pool,
        &state.cfg,
        CreateRootCaParams {
            organization: &payload.organization,
            common_name: &payload.root_common_name,
            description: payload.description.as_deref(),
            valid_years: payload.root_valid_years,
            cipher: payload.root_cipher.as_deref(),
            key_length: payload.root_key_length,
            dn: SubjectDn {
                country: payload.country.clone().filter(|s| !s.trim().is_empty()),
                state: payload.state.clone().filter(|s| !s.trim().is_empty()),
                locality: payload.locality.clone().filter(|s| !s.trim().is_empty()),
                organization: Some(payload.organization.clone()),
                org_unit: payload.org_unit.clone().filter(|s| !s.trim().is_empty()),
            },
        },
    )
    .await?;

    let mut intermediate_id: Option<String> = None;
    if payload.create_intermediate {
        let common_name = payload
            .intermediate_common_name
            .clone()
            .unwrap_or_else(|| format!("{} Intermediate CA", payload.organization));
        let valid_days = payload.intermediate_valid_days.unwrap_or(1825);
        let intermediate_cipher = payload
            .intermediate_cipher
            .clone()
            .unwrap_or_else(|| "ed25519".to_string());
        let intermediate_key_length = payload.intermediate_key_length.unwrap_or(256);
        let material = generate_tls_material(
            &state.pool,
            &state.cfg,
            GenerateTlsMaterialParams {
                root_id,
                common_name: &common_name,
                valid_days,
                is_ca: true,
                cipher: Some(&intermediate_cipher),
                key_length: Some(intermediate_key_length),
                sans: &[],
                purpose: "server",
            },
        )
        .await?;
        let cert_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO tls_keys (id, machine_id, root_ca_id, parent_cert_id, common_name, serial_hex, cert_pem, private_key_enc, valid_from, valid_to, created_by, created_at, is_revoked, cert_level, cipher, key_length, usages_json, allow_private_key_export) VALUES (?, NULL, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, false, 'intermediate', ?, ?, ?, false)",
        )
        .bind(&cert_id)
        .bind(root_id)
        .bind(&common_name)
        .bind(&material.serial_hex)
        .bind(&material.cert_pem)
        .bind(encrypt_secret(&state.cfg, &material.private_key_pem)?)
        .bind(material.valid_from.naive_utc())
        .bind(material.valid_to.naive_utc())
        .bind(&auth_user.username)
        .bind(Utc::now().naive_utc())
        .bind(&intermediate_cipher)
        .bind(intermediate_key_length)
        .bind(json!(["keyCertSign", "cRLSign", "digitalSignature"]).to_string())
        .execute(&state.pool)
        .await?;
        intermediate_id = Some(cert_id);
    }

    audit(
        &state,
        &auth_user.username,
        "organization.create",
        "root_ca",
        &root_id.to_string(),
        json!({
            "organization": payload.organization,
            "root_common_name": payload.root_common_name,
            "create_intermediate": payload.create_intermediate,
            "intermediate_id": intermediate_id,
        }),
    )
    .await?;

    Ok(Json(json!({
        "root_id": root_id,
        "intermediate_id": intermediate_id,
    })))
}

async fn create_intermediate_cert(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateIntermediateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin" | "tls_admin") {
        return Err(AppError::Forbidden);
    }

    let org_row: Option<(String,)> =
        sqlx::query_as("SELECT organization FROM root_ca WHERE id = ?")
            .bind(payload.root_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((_organization,)) = org_row else {
        return Err(AppError::NotFound);
    };
    let cipher = payload
        .cipher
        .clone()
        .unwrap_or_else(|| "ed25519".to_string());
    let key_length = payload.key_length.unwrap_or(256);
    let material = generate_tls_material(
        &state.pool,
        &state.cfg,
        GenerateTlsMaterialParams {
            root_id: payload.root_id,
            common_name: &payload.common_name,
            valid_days: payload.valid_days,
            is_ca: true,
            cipher: Some(&cipher),
            key_length: Some(key_length),
            sans: &[],
            purpose: "server",
        },
    )
    .await?;
    let cert_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO tls_keys (id, machine_id, root_ca_id, parent_cert_id, common_name, serial_hex, cert_pem, private_key_enc, valid_from, valid_to, created_by, created_at, is_revoked, cert_level, cipher, key_length, usages_json, allow_private_key_export) VALUES (?, NULL, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, false, 'intermediate', ?, ?, ?, false)",
    )
    .bind(&cert_id)
    .bind(payload.root_id)
    .bind(&payload.common_name)
    .bind(&material.serial_hex)
    .bind(&material.cert_pem)
    .bind(encrypt_secret(&state.cfg, &material.private_key_pem)?)
    .bind(material.valid_from.naive_utc())
    .bind(material.valid_to.naive_utc())
    .bind(&auth_user.username)
    .bind(Utc::now().naive_utc())
    .bind(&cipher)
    .bind(key_length)
    .bind(json!(["keyCertSign", "cRLSign", "digitalSignature"]).to_string())
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "tls.intermediate.create",
        "tls_key",
        &cert_id,
        json!({"root_id": payload.root_id, "common_name": payload.common_name}),
    )
    .await?;

    Ok(Json(json!({"id": cert_id, "root_id": payload.root_id})))
}

async fn get_root_cert(
    Path(id): Path<i32>,
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let row: RootCertDetailRow = sqlx::query_as(
        "SELECT id, common_name, organization, description, cert_pem, not_before, not_after, is_revoked, revoked_at, revoked_reason, cipher, key_length FROM root_ca WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(json!({
        "id": row.id,
        "common_name": row.common_name,
        "organization": row.organization,
        "description": row.description,
        "cert_pem": row.cert_pem,
        "not_before": row.not_before,
        "not_after": row.not_after,
        "is_revoked": row.is_revoked,
        "revoked_at": row.revoked_at,
        "revoked_reason": row.revoked_reason,
        "cipher": row.cipher,
        "key_length": row.key_length,
    })))
}

#[derive(sqlx::FromRow)]
struct RootRenewRow {
    organization: String,
    common_name: String,
    description: Option<String>,
    not_before: chrono::NaiveDateTime,
    not_after: chrono::NaiveDateTime,
    cipher: String,
    key_length: i32,
    country: Option<String>,
    state: Option<String>,
    locality: Option<String>,
    org_unit: Option<String>,
}

async fn renew_root_cert(
    Path(id): Path<i32>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !matches!(auth_user.role.as_str(), "full_admin" | "tls_admin") {
        return Err(AppError::Forbidden);
    }
    let row = sqlx::query_as::<_, RootRenewRow>(
        "SELECT organization, common_name, description, not_before, not_after, cipher, key_length, country, state, locality, org_unit FROM root_ca WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    let days = (row.not_after - row.not_before).num_days().max(365);
    let years = (days / 365).max(1);
    let new_id = create_root_ca(
        &state.pool,
        &state.cfg,
        CreateRootCaParams {
            organization: &row.organization,
            common_name: &row.common_name,
            description: row.description.as_deref(),
            valid_years: years,
            cipher: Some(&row.cipher),
            key_length: Some(row.key_length),
            dn: SubjectDn {
                country: row.country.clone(),
                state: row.state.clone(),
                locality: row.locality.clone(),
                organization: Some(row.organization.clone()),
                org_unit: row.org_unit.clone(),
            },
        },
    )
    .await?;
    audit(
        &state,
        &auth_user.username,
        "root.renew",
        "root_ca",
        &id.to_string(),
        json!({"new_root_id": new_id}),
    )
    .await?;
    Ok(Json(
        json!({"status":"renewed","previous_root_id":id,"new_root_id":new_id}),
    ))
}

async fn revoke_root_cert(
    Path(id): Path<i32>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !matches!(auth_user.role.as_str(), "full_admin" | "tls_admin") {
        return Err(AppError::Forbidden);
    }
    sqlx::query("UPDATE root_ca SET is_revoked = true, revoked_at = ?, revoked_reason = 'manual revocation' WHERE id = ?")
        .bind(Utc::now().naive_utc())
        .bind(id)
        .execute(&state.pool)
        .await?;
    audit(
        &state,
        &auth_user.username,
        "root.revoke",
        "root_ca",
        &id.to_string(),
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status":"revoked","root_id":id})))
}

async fn delete_root_cert(
    Path(id): Path<i32>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !matches!(auth_user.role.as_str(), "full_admin" | "tls_admin") {
        return Err(AppError::Forbidden);
    }

    let root_row: Option<(i32, String, String)> =
        sqlx::query_as("SELECT id, organization, common_name FROM root_ca WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((_root_id, organization, common_name)) = root_row else {
        return Err(AppError::NotFound);
    };

    let mut tx = state.pool.begin().await?;

    // Avec la CA disparaît sa CRL entière : plus rien pour la signer.
    let deleted_crl = sqlx::query("DELETE FROM crl_entries WHERE root_ca_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    let deleted_tls = sqlx::query("DELETE FROM tls_keys WHERE root_ca_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    let deleted_root = sqlx::query("DELETE FROM root_ca WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    tx.commit().await?;

    if deleted_root == 0 {
        return Err(AppError::NotFound);
    }

    audit(
        &state,
        &auth_user.username,
        "organization.delete",
        "root_ca",
        &id.to_string(),
        json!({
            "organization": organization,
            "common_name": common_name,
            "deleted_tls_certificates": deleted_tls,
            "deleted_crl_entries": deleted_crl,
        }),
    )
    .await?;

    Ok(Json(json!({
        "status": "deleted",
        "root_id": id,
        "organization": organization,
        "common_name": common_name,
        "deleted_tls_certificates": deleted_tls,
        "deleted_crl_entries": deleted_crl,
    })))
}

async fn get_crypto_options() -> AppResult<Json<serde_json::Value>> {
    let default = json!({
        "tls": {
            "ciphers": [
                {"id":"ed25519","label":"Ed25519","recommended":true},
                {"id":"ecdsa_p256","label":"ECDSA P-256","recommended":true},
                {"id":"rsa","label":"RSA"}
            ],
            "key_lengths": [256, 2048, 3072, 4096],
            "cert_levels": [
                {"id":"leaf","label":"Leaf certificate"},
                {"id":"intermediate","label":"Intermediate CA"}
            ]
        },
        "ssh": {
            "ciphers": [
                {"id":"ed25519","label":"Ed25519","recommended":true},
                {"id":"rsa","label":"RSA"}
            ],
            "key_lengths": [256, 2048, 3072, 4096]
        }
    });
    let path = std::env::var("AKAMANA_CRYPTO_OPTIONS_PATH")
        .unwrap_or_else(|_| "/data/crypto_options.json".to_string());
    let from_file = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .unwrap_or(default);
    Ok(Json(from_file))
}

fn can_manage_tls(role: &str) -> bool {
    matches!(role, "full_admin" | "tls_admin")
}

fn can_manage_ssh(role: &str) -> bool {
    matches!(role, "full_admin" | "ssh_admin")
}

fn can_audit(role: &str) -> bool {
    matches!(role, "full_admin" | "auditor")
}

fn can_manage_machines(role: &str) -> bool {
    can_manage_tls(role) || can_manage_ssh(role) || role == "full_admin"
}

/// Every scope an API token may carry. Used to validate token-creation requests.
const ALL_SCOPES: &[&str] = &[
    "tls:issue",
    "tls:read",
    "ssh:issue",
    "ssh:sign",
    "ssh:read",
    "ca:read",
];

/// The scopes a user of `role` is allowed to mint into a token. A token can
/// never exceed its owner's own authority.
fn grantable_scopes_for_role(role: &str) -> Vec<&'static str> {
    match role {
        "full_admin" => ALL_SCOPES.to_vec(),
        "tls_admin" => vec!["tls:issue", "tls:read", "ca:read"],
        "ssh_admin" => vec!["ssh:issue", "ssh:sign", "ssh:read", "ca:read"],
        "auditor" => vec!["tls:read", "ssh:read", "ca:read"],
        _ => vec![],
    }
}

/// Unified authorization for endpoints reachable by both humans and API tokens.
/// Token callers are gated purely by `scope`; human callers by the pre-computed
/// `role_ok` role check. Because token callers carry the sentinel role
/// `"token"`, they never satisfy a `can_manage_*` check and thus cannot reach
/// any endpoint that does not explicitly grant a scope here.
fn authorize(auth: &AuthenticatedUser, scope: &str, role_ok: bool) -> AppResult<()> {
    if auth.is_token {
        if auth.has_scope(scope) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    } else if role_ok {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Rejects API-token callers outright — for endpoints that only interactive
/// users may reach (user management, token management, settings, deletes).
fn require_human(auth: &AuthenticatedUser) -> AppResult<()> {
    if auth.is_token {
        Err(AppError::Forbidden)
    } else {
        Ok(())
    }
}

async fn create_machine(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateMachineRequest>,
) -> AppResult<Json<MachineRecord>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let now = Utc::now().naive_utc();
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO machines (id, hostname, ip_address, owner, environment, os_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.hostname)
    .bind(&payload.ip_address)
    .bind(&payload.owner)
    .bind(&payload.environment)
    .bind(&payload.os_type)
    .bind(now)
    .bind(now)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "machine.create",
        "machine",
        &id,
        json!({"hostname": payload.hostname, "ip": payload.ip_address}),
    )
    .await?;

    let row = sqlx::query_as::<_, MachineRecord>(
        "SELECT id, hostname, ip_address, owner, environment, os_type, alert_email, test_url, monitor_only, created_at, updated_at FROM machines WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(row))
}

async fn list_machines(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let (limit, offset) = parse_pagination(params);
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM machines")
        .fetch_one(&state.pool)
        .await?;
    let rows = sqlx::query_as::<_, MachineRecord>(
        "SELECT id, hostname, ip_address, owner, environment, os_type, alert_email, test_url, monitor_only, created_at, updated_at FROM machines ORDER BY hostname ASC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        json!({"items": rows, "total": total, "limit": limit, "offset": offset}),
    ))
}

#[derive(sqlx::FromRow)]
struct MachineMonitorPortRow {
    id: String,
    machine_id: String,
    hostname: String,
    ip_address: String,
    owner: String,
    environment: String,
    port: i32,
    sni_host: String,
    monitor_enabled: bool,
    last_checked_at: Option<chrono::NaiveDateTime>,
    last_status: Option<String>,
    last_error: Option<String>,
    cert_not_before: Option<chrono::NaiveDateTime>,
    cert_not_after: Option<chrono::NaiveDateTime>,
    cert_subject: Option<String>,
    cert_issuer: Option<String>,
    cert_serial_hex: Option<String>,
    cert_chain_json: Option<String>,
    tls_support_json: Option<String>,
    cert_diagnostic: Option<String>,
}

async fn list_machine_monitor_rows(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let rows = sqlx::query_as::<_, MachineMonitorPortRow>(
        "SELECT mp.id, mp.machine_id, m.hostname, m.ip_address, m.owner, m.environment, mp.port, mp.sni_host, mp.monitor_enabled, mp.last_checked_at, mp.last_status, mp.last_error, mp.cert_not_before, mp.cert_not_after, mp.cert_subject, mp.cert_issuer, mp.cert_serial_hex, CAST(mp.cert_chain_json AS CHAR) AS cert_chain_json, CAST(mp.tls_support_json AS CHAR) AS tls_support_json, mp.cert_diagnostic \
         FROM machine_monitor_ports mp \
         JOIN machines m ON m.id = mp.machine_id \
         ORDER BY m.hostname ASC, mp.port ASC, mp.sni_host ASC",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut cert_map: HashMap<String, i64> = HashMap::new();
    for (machine_id, count) in sqlx::query_as::<_, (String, i64)>(
        "SELECT machine_id, COUNT(*) FROM tls_keys WHERE machine_id IS NOT NULL GROUP BY machine_id",
    )
    .fetch_all(&state.pool)
    .await?
    {
        cert_map.insert(machine_id, count);
    }
    for (machine_id, count) in sqlx::query_as::<_, (String, i64)>(
        "SELECT machine_id, COUNT(*) FROM ssh_keys WHERE machine_id IS NOT NULL GROUP BY machine_id",
    )
    .fetch_all(&state.pool)
    .await?
    {
        *cert_map.entry(machine_id).or_insert(0) += count;
    }

    let items = rows
        .into_iter()
        .map(|r| {
            let chain = r
                .cert_chain_json
                .as_deref()
                .and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok())
                .unwrap_or_else(|| json!([]));
            let days_to_expiry = r
                .cert_not_after
                .map(|d| (d - Utc::now().naive_utc()).num_days());
            let tls_support = r
                .tls_support_json
                .as_deref()
                .and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok())
                .unwrap_or_else(|| json!([]));
            json!({
                "id": r.id,
                "machine_id": r.machine_id,
                "hostname": r.hostname,
                "ip_address": r.ip_address,
                "owner": r.owner,
                "environment": r.environment,
                "machine_certificate_count": cert_map.get(&r.machine_id).copied().unwrap_or(0),
                "port": r.port,
                "sni_host": r.sni_host,
                "monitor_enabled": r.monitor_enabled,
                "last_checked_at": r.last_checked_at,
                "status": r.last_status.unwrap_or_else(|| "unknown".to_string()),
                "last_error": r.last_error,
                "cert_not_before": r.cert_not_before,
                "cert_not_after": r.cert_not_after,
                "days_to_expiry": days_to_expiry,
                "cert_subject": r.cert_subject,
                "cert_issuer": r.cert_issuer,
                "cert_serial_hex": r.cert_serial_hex,
                "cert_chain": chain,
                "tls_support": tls_support,
                "diagnostic": r.cert_diagnostic.unwrap_or_else(|| "No scan yet.".to_string()),
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({ "items": items })))
}

async fn add_machine_monitor_port(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateMachineMonitorPortRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    let sni_host = payload.sni_host.clone().unwrap_or_default();
    sqlx::query(
        "INSERT INTO machine_monitor_ports (id, machine_id, port, sni_host, monitor_enabled, check_tls, created_at, updated_at) VALUES (?, ?, ?, ?, ?, true, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.machine_id)
    .bind(payload.port)
    .bind(&sni_host)
    .bind(payload.monitor_enabled.unwrap_or(true))
    .bind(now)
    .bind(now)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Validation(format!("unable to add monitor port: {e}")))?;

    audit(
        &state,
        &auth_user.username,
        "machine.monitor_port.create",
        "machine_monitor_port",
        &id,
        json!({"machine_id": payload.machine_id, "port": payload.port}),
    )
    .await?;

    Ok(Json(json!({"id": id, "status": "created"})))
}

/// Reduces user input to a bare host name.
///
/// Operators paste whatever they have at hand — `https://pki.example.com/admin`,
/// `pki.example.com:8443`, a trailing dot from a DNS tool. Rejecting those would
/// be pedantic when the intent is unambiguous.
fn normalize_domain(raw: &str) -> AppResult<String> {
    let mut host = raw.trim().to_ascii_lowercase();
    if let Some(pos) = host.find("://") {
        host = host[pos + 3..].to_string();
    }
    host = host
        .split('/')
        .next()
        .unwrap_or_default()
        .split('@')
        .next_back()
        .unwrap_or_default()
        .to_string();
    // Strip a port, but leave bracketed IPv6 literals alone.
    if !host.starts_with('[') {
        if let Some(pos) = host.rfind(':') {
            if host[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
                host = host[..pos].to_string();
            }
        }
    }
    let host = host.trim_end_matches('.').to_string();

    if host.is_empty() || host.len() > 255 {
        return Err(AppError::Validation("invalid domain name".to_string()));
    }
    if !host.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']'
    }) {
        return Err(AppError::Validation(format!(
            "invalid characters in domain name: {host}"
        )));
    }
    Ok(host)
}

/// Returns whichever of the candidate ports accepts a TCP connection.
///
/// A blocking connect in `spawn_blocking` rather than an async one: the check
/// is two short-lived sockets, and this keeps the code free of any assumption
/// about which tokio features happen to be enabled.
async fn probe_ports(host: String, candidates: Vec<i32>) -> Vec<i32> {
    tokio::task::spawn_blocking(move || {
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;
        candidates
            .into_iter()
            .filter(|port| {
                let target = format!("{host}:{port}");
                target
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut addrs| {
                        addrs.find(|addr| {
                            TcpStream::connect_timeout(addr, Duration::from_secs(4)).is_ok()
                        })
                    })
                    .is_some()
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

/// Registers a domain for monitoring, resolving its host on the way.
///
/// The point is to let an operator type a name and be done: the server finds
/// the address, reuses the machine that already answers on it (a domain is
/// usually one more virtual host on a server we already watch) or registers a
/// new one, picks a port that actually responds, and runs the same scan the
/// per-host "add a virtual host" button triggers.
/// Describes a key the operator is about to import.
///
/// Deliberately stores nothing: the point is to let someone paste a key, see
/// what it actually is, and decide — rather than discover after the fact that
/// they imported a 1024-bit RSA key, a passphrase-locked file the deployer
/// cannot open, or a private key belonging to a different public key.
/// Charge les AC SSH de cette instance sous la forme attendue par l'analyse :
/// (id, nom, empreinte SHA256).
async fn known_ssh_cas(state: &AppState) -> Result<Vec<(String, String, String)>, AppError> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT id, name, fingerprint_sha256 FROM ssh_cas")
            .fetch_all(&state.pool)
            .await?;
    Ok(rows)
}

/// Lit un certificat SSH et rend son verdict sans rien stocker.
async fn analyze_ssh_certificate_endpoint(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<AnalyzeSshCertificateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let cas = known_ssh_cas(&state).await?;
    let analysis =
        analyze_ssh_certificate(&payload.certificate, payload.private_key.as_deref(), &cas)?;
    Ok(Json(serde_json::to_value(analysis).map_err(|e| {
        AppError::Internal(format!("unable to serialise analysis: {e}"))
    })?))
}

/// Enregistre un certificat SSH émis ailleurs.
///
/// L'analyse tourne d'abord et l'import est refusé si elle relève une erreur :
/// une signature qui ne vérifie pas, un certificat expiré ou une clé privée qui
/// ne va pas avec lui n'ont rien à faire dans l'inventaire, et les y laisser
/// entrer donnerait une fausse assurance à qui le consulte.
///
/// Le certificat est identifié par l'empreinte de sa clé sujet et son numéro de
/// série ; réimporter le même renvoie la ligne existante plutôt qu'un doublon.
async fn import_ssh_certificate(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<ImportSshCertificateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let cas = known_ssh_cas(&state).await?;
    let analysis =
        analyze_ssh_certificate(&payload.certificate, payload.private_key.as_deref(), &cas)?;
    if !analysis.errors.is_empty() {
        return Err(AppError::Validation(format!(
            "certificate refused: {}",
            analysis.errors.join(" ")
        )));
    }

    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM ssh_certificates WHERE fingerprint_sha256 = ? AND serial = ?",
    )
    .bind(&analysis.subject_fingerprint_sha256)
    .bind(analysis.serial)
    .fetch_optional(&state.pool)
    .await?;
    if let Some((id,)) = existing {
        return Ok(Json(json!({ "id": id, "status": "already_imported" })));
    }

    let private_key_enc = match payload.private_key.as_deref().map(str::trim) {
        Some(k) if !k.is_empty() => Some(encrypt_secret(&state.cfg, k)?),
        _ => None,
    };
    let valid_from = analysis
        .valid_from
        .map(|d| d.naive_utc())
        .unwrap_or_else(|| Utc::now().naive_utc());
    // La colonne valid_to n'est pas nullable ; un certificat sans expiration est
    // enregistré très loin dans le futur, et l'avertissement de l'analyse dit
    // déjà ce qu'il faut en penser.
    let valid_to = analysis
        .valid_to
        .map(|d| d.naive_utc())
        .unwrap_or_else(|| (Utc::now() + chrono::Duration::days(36500)).naive_utc());

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    sqlx::query(
        "INSERT INTO ssh_certificates (id, ca_id, ca_type, cert_type, serial, key_id, principals, \
         critical_options, extensions, subject_public_key, certificate, private_key_enc, \
         allow_private_key_export, fingerprint_sha256, ca_fingerprint_sha256, is_imported, \
         machine_id, valid_from, valid_to, created_by, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&analysis.known_ca_id)
    .bind(&analysis.cert_type)
    .bind(&analysis.cert_type)
    .bind(analysis.serial)
    .bind(&analysis.key_id)
    .bind(analysis.principals.join(","))
    .bind(serde_json::to_string(&analysis.critical_options).unwrap_or_default())
    .bind(serde_json::to_string(&analysis.extensions).unwrap_or_default())
    .bind(&analysis.subject_fingerprint_sha256)
    .bind(payload.certificate.trim())
    .bind(&private_key_enc)
    .bind(payload.allow_private_key_export.unwrap_or(false))
    .bind(&analysis.subject_fingerprint_sha256)
    .bind(&analysis.ca_fingerprint_sha256)
    .bind(&payload.machine_id)
    .bind(valid_from)
    .bind(valid_to)
    .bind(&auth_user.username)
    .bind(now)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "ssh_certificate.import",
        "ssh_certificate",
        &id,
        json!({
            "key_id": analysis.key_id,
            "serial": analysis.serial,
            "ca_known": analysis.known_ca_id.is_some(),
        }),
    )
    .await?;

    Ok(Json(json!({
        "id": id,
        "status": "imported",
        "warnings": analysis.warnings,
    })))
}

async fn analyze_ssh_key_endpoint(
    State(_state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<AnalyzeSshKeyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let analysis = analyze_ssh_key(
        payload.public_key.as_deref(),
        payload.private_key.as_deref(),
    )?;
    Ok(Json(serde_json::to_value(analysis).map_err(|e| {
        AppError::Internal(format!("unable to serialise analysis: {e}"))
    })?))
}

async fn add_monitored_domain(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<AddMonitoredDomainRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let domain = normalize_domain(&payload.domain)?;

    let lookup_name = domain.clone();
    let addresses = tokio::task::spawn_blocking(move || dns_lookup::lookup_host(&lookup_name))
        .await
        .map_err(|e| AppError::Internal(format!("dns lookup task failed: {e}")))?
        .map_err(|e| AppError::Validation(format!("{domain} does not resolve: {e}")))?;

    // Prefer IPv4: the inventory stores a single address, and the rest of the
    // deployment tooling (SSH, certbot) is reached over v4 here.
    let ip = addresses
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| addresses.first())
        .ok_or_else(|| AppError::Validation(format!("{domain} resolves to no address")))?
        .to_string();

    let existing: Option<(String, String)> =
        sqlx::query_as("SELECT id, hostname FROM machines WHERE ip_address = ? LIMIT 1")
            .bind(&ip)
            .fetch_optional(&state.pool)
            .await?;

    let (machine_id, machine_hostname, machine_created) = match existing {
        Some((id, hostname)) => (id, hostname, false),
        None => {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now().naive_utc();
            sqlx::query(
                "INSERT INTO machines (id, hostname, ip_address, owner, environment, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(&domain)
            .bind(&ip)
            .bind(payload.owner.clone().unwrap_or_default())
            .bind(payload.environment.clone().unwrap_or_default())
            .bind(now)
            .bind(now)
            .execute(&state.pool)
            .await
            .map_err(|e| AppError::Validation(format!("unable to create host: {e}")))?;

            audit(
                &state,
                &auth_user.username,
                "machine.create",
                "machine",
                &id,
                json!({"hostname": domain, "ip": ip, "via": "monitored_domain"}),
            )
            .await?;

            (id, domain.clone(), true)
        }
    };

    // Probe before registering: monitoring a port nothing listens on produces a
    // permanently red row and teaches the operator to ignore the dashboard.
    let probed = probe_ports(ip.clone(), vec![443, 80]).await;
    let port = match payload.port {
        Some(p) => p,
        None => {
            if probed.contains(&443) {
                443
            } else if probed.contains(&80) {
                80
            } else {
                return Err(AppError::Validation(format!(
                    "{domain} ({ip}) answers on neither 443 nor 80; pass an explicit port to monitor it anyway"
                )));
            }
        }
    };

    // The (machine, port, sni_host) triple is unique: adding the same domain
    // twice should be idempotent rather than an error the operator must read.
    let existing_port: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM machine_monitor_ports WHERE machine_id = ? AND port = ? AND sni_host = ?",
    )
    .bind(&machine_id)
    .bind(port)
    .bind(&domain)
    .fetch_optional(&state.pool)
    .await?;

    let (port_id, port_created) = match existing_port {
        Some((id,)) => (id, false),
        None => {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now().naive_utc();
            sqlx::query(
                "INSERT INTO machine_monitor_ports (id, machine_id, port, sni_host, monitor_enabled, check_tls, created_at, updated_at) VALUES (?, ?, ?, ?, true, ?, ?, ?)",
            )
            .bind(&id)
            .bind(&machine_id)
            .bind(port)
            .bind(&domain)
            .bind(port != 80)
            .bind(now)
            .bind(now)
            .execute(&state.pool)
            .await
            .map_err(|e| AppError::Validation(format!("unable to add monitored domain: {e}")))?;
            (id, true)
        }
    };

    audit(
        &state,
        &auth_user.username,
        "machine.monitor_domain.create",
        "machine_monitor_port",
        &port_id,
        json!({"domain": domain, "ip": ip, "port": port, "machine_id": machine_id}),
    )
    .await?;

    // A failed scan is not a failed registration: the row exists and the error
    // belongs on it, which is exactly what the per-host flow does.
    let scan = machine_monitor::scan_and_store(&state, &port_id, true)
        .await
        .unwrap_or_else(|e| json!({"status": "error", "error": e.to_string()}));

    Ok(Json(json!({
        "status": "ok",
        "domain": domain,
        "ip_address": ip,
        "machine_id": machine_id,
        "machine_hostname": machine_hostname,
        "machine_created": machine_created,
        "monitor_port_id": port_id,
        "monitor_port_created": port_created,
        "port": port,
        "responds_https": probed.contains(&443),
        "responds_http": probed.contains(&80),
        "scan": scan,
    })))
}

async fn update_machine_monitor_port(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<UpdateMachineMonitorPortRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    if payload.port.is_none() && payload.monitor_enabled.is_none() {
        return Err(AppError::Validation(
            "at least one field (port, monitor_enabled) must be provided".to_string(),
        ));
    }

    let existing: Option<(String, i32)> =
        sqlx::query_as("SELECT machine_id, port FROM machine_monitor_ports WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((machine_id, old_port)) = existing else {
        return Err(AppError::NotFound);
    };

    let new_port = payload.port.unwrap_or(old_port);
    let new_enabled = if let Some(v) = payload.monitor_enabled {
        v
    } else {
        let (current_enabled,): (bool,) =
            sqlx::query_as("SELECT monitor_enabled FROM machine_monitor_ports WHERE id = ?")
                .bind(&id)
                .fetch_one(&state.pool)
                .await?;
        current_enabled
    };

    if new_port != old_port {
        let dupe: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM machine_monitor_ports WHERE machine_id = ? AND port = ? AND id <> ?",
        )
        .bind(&machine_id)
        .bind(new_port)
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
        if dupe.is_some() {
            return Err(AppError::Validation(
                "this machine already has a monitor row for that port".to_string(),
            ));
        }
    }

    sqlx::query(
        "UPDATE machine_monitor_ports SET port = ?, monitor_enabled = ?, updated_at = ? WHERE id = ?",
    )
    .bind(new_port)
    .bind(new_enabled)
    .bind(Utc::now().naive_utc())
    .bind(&id)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "machine.monitor_port.update",
        "machine_monitor_port",
        &id,
        json!({"old_port": old_port, "new_port": new_port, "monitor_enabled": new_enabled}),
    )
    .await?;

    Ok(Json(
        json!({"status": "updated", "id": id, "port": new_port, "monitor_enabled": new_enabled}),
    ))
}

async fn delete_machine_monitor_port(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let result = sqlx::query("DELETE FROM machine_monitor_ports WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    audit(
        &state,
        &auth_user.username,
        "machine.monitor_port.delete",
        "machine_monitor_port",
        &id,
        json!({}),
    )
    .await?;

    Ok(Json(json!({"status": "deleted"})))
}

async fn scan_machine_monitor_port(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) && !can_audit(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let out = machine_monitor::scan_and_store(&state, &id, true)
        .await
        .map_err(|e| AppError::Internal(format!("scan failed: {e}")))?;

    audit(
        &state,
        &auth_user.username,
        "machine.monitor_port.scan",
        "machine_monitor_port",
        &id,
        json!({}),
    )
    .await?;

    Ok(Json(out))
}

async fn scan_all_machine_monitor_ports(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    machine_monitor::run_all_checks(&state)
        .await
        .map_err(|e| AppError::Internal(format!("bulk scan failed: {e}")))?;
    Ok(Json(json!({"status": "ok"})))
}

pub(crate) async fn generate_tls_key(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<GenerateTlsKeyRequest>,
) -> AppResult<Json<GenerateTlsKeyResponse>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    authorize(&auth_user, "tls:issue", can_manage_tls(&auth_user.role))?;
    let root_id = payload.root_id.unwrap_or(1);
    let cert_level = payload
        .cert_level
        .clone()
        .unwrap_or_else(|| "leaf".to_string());
    let is_ca = cert_level == "intermediate";
    let tls_cipher = payload
        .cipher
        .clone()
        .unwrap_or_else(|| "ed25519".to_string());
    let tls_key_length = payload.key_length.unwrap_or(256);
    let sans: Vec<String> = payload.sans.clone().unwrap_or_default();
    let purpose = payload
        .purpose
        .clone()
        .unwrap_or_else(|| "server".to_string());

    let material = generate_tls_material(
        &state.pool,
        &state.cfg,
        GenerateTlsMaterialParams {
            root_id,
            common_name: &payload.common_name,
            valid_days: payload.valid_days,
            is_ca,
            cipher: Some(&tls_cipher),
            key_length: Some(tls_key_length),
            sans: &sans,
            purpose: &purpose,
        },
    )
    .await?;
    let id = Uuid::new_v4().to_string();
    let usages = if is_ca {
        json!(["keyCertSign", "cRLSign", "digitalSignature"])
    } else {
        json!(["digitalSignature", "keyEncipherment"])
    };
    // Un certificat peut appartenir à plusieurs machines — une ferme derrière
    // un répartiteur, un nom en round-robin. La liste fait foi ; la colonne
    // machine_id de tls_keys garde la première pour tout ce qui ne lit encore
    // qu'une seule machine. Une CA n'est rattachée à rien.
    let machine_ids: Vec<String> = if is_ca {
        Vec::new()
    } else {
        // Ordre conservé, doublons écartés : la première est celle que la
        // colonne machine_id retiendra.
        let mut ids: Vec<String> = Vec::new();
        let candidats = payload
            .machine_id
            .iter()
            .cloned()
            .chain(payload.machine_ids.clone().unwrap_or_default());
        for m in candidats {
            let m = m.trim().to_string();
            if !m.is_empty() && !ids.contains(&m) {
                ids.push(m);
            }
        }
        for m in &ids {
            if m.len() != 36 {
                return Err(AppError::Validation(format!(
                    "machine_ids: `{m}` is not a machine id"
                )));
            }
            let known: Option<(String,)> = sqlx::query_as("SELECT id FROM machines WHERE id = ?")
                .bind(m)
                .fetch_optional(&state.pool)
                .await?;
            if known.is_none() {
                return Err(AppError::Validation(format!(
                    "machine_ids: no host with id `{m}`"
                )));
            }
        }
        ids
    };
    let machine_id_to_store: Option<&str> = machine_ids.first().map(String::as_str);

    sqlx::query(
        "INSERT INTO tls_keys (id, machine_id, root_ca_id, parent_cert_id, common_name, serial_hex, cert_pem, private_key_enc, valid_from, valid_to, created_by, created_at, is_revoked, cert_level, cipher, key_length, usages_json, sans_json, eku_purpose, allow_private_key_export) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(machine_id_to_store)
    .bind(root_id)
    .bind(payload.parent_cert_id.as_deref())
    .bind(&payload.common_name)
    .bind(&material.serial_hex)
    .bind(&material.cert_pem)
    .bind(encrypt_secret(&state.cfg, &material.private_key_pem)?)
    .bind(material.valid_from.naive_utc())
    .bind(material.valid_to.naive_utc())
    .bind(&auth_user.username)
    .bind(Utc::now().naive_utc())
    .bind(cert_level.clone())
    .bind(&tls_cipher)
    .bind(tls_key_length)
    .bind(usages.to_string())
    .bind(serde_json::to_string(&sans).unwrap_or_else(|_| "[]".to_string()))
    .bind(if is_ca { None } else { Some(purpose.clone()) })
    .bind(payload.publish_private_key)
    .execute(&state.pool)
    .await?;

    let now = Utc::now().naive_utc();
    for m in &machine_ids {
        sqlx::query(
            "INSERT IGNORE INTO tls_key_machines (tls_key_id, machine_id, created_at) VALUES (?, ?, ?)",
        )
        .bind(&id)
        .bind(m)
        .bind(now)
        .execute(&state.pool)
        .await?;
    }

    audit(
        &state,
        &auth_user.username,
        "tls.generate",
        "tls_key",
        &id,
        json!({"machine_ids": machine_ids, "common_name": payload.common_name, "serial_hex": material.serial_hex, "root_id": root_id, "cert_level": cert_level}),
    )
    .await?;

    Ok(Json(GenerateTlsKeyResponse {
        key_id: id,
        serial_hex: material.serial_hex,
        cert_pem: material.cert_pem,
        private_key_pem: material.private_key_pem,
        valid_from: material.valid_from,
        valid_to: material.valid_to,
    }))
}

/// Maps a certificate's public-key type to Akamana's cipher label + key bits.
fn detect_cert_cipher_and_bits(cert: &X509) -> (String, i32) {
    match cert.public_key() {
        Ok(pkey) => {
            let bits = pkey.bits() as i32;
            let cipher = match pkey.id() {
                Id::RSA => "rsa",
                Id::EC => "ecdsa_p256",
                _ => "ed25519",
            };
            (cipher.to_string(), if bits > 0 { bits } else { 256 })
        }
        Err(_) => ("ed25519".to_string(), 256),
    }
}

async fn import_root_ca(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<ImportRootCaRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin" | "tls_admin") {
        return Err(AppError::Forbidden);
    }

    let cert = X509::from_pem(payload.cert_pem.as_bytes())
        .map_err(|e| AppError::Validation(format!("invalid certificate PEM: {e}")))?;

    let subject = cert.subject_name();
    let field = |nid: Nid| {
        subject
            .entries_by_nid(nid)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
    };
    let common_name = field(Nid::COMMONNAME).unwrap_or_else(|| payload.organization.clone());

    let valid_from = chrono::NaiveDateTime::parse_from_str(
        &cert.not_before().to_string(),
        "%b %e %H:%M:%S %Y GMT",
    )
    .map_err(|e| AppError::Validation(format!("not_before parse failed: {e}")))?;
    let valid_to = chrono::NaiveDateTime::parse_from_str(
        &cert.not_after().to_string(),
        "%b %e %H:%M:%S %Y GMT",
    )
    .map_err(|e| AppError::Validation(format!("not_after parse failed: {e}")))?;

    let (cipher, key_length) = detect_cert_cipher_and_bits(&cert);

    // If a private key is supplied, verify it matches the certificate, then store
    // it so Akamana can issue under this root. Otherwise store an empty secret —
    // the root becomes a trust anchor only (publish/distribute, cannot sign).
    let has_private_key = payload
        .private_key_pem
        .as_ref()
        .is_some_and(|k| !k.trim().is_empty());
    let key_enc = if let Some(key_pem) = payload
        .private_key_pem
        .as_ref()
        .filter(|k| !k.trim().is_empty())
    {
        let key = PKey::private_key_from_pem(key_pem.as_bytes())
            .map_err(|e| AppError::Validation(format!("invalid private key PEM: {e}")))?;
        let cert_key = cert
            .public_key()
            .map_err(|e| AppError::Validation(format!("cannot read certificate key: {e}")))?;
        if !key.public_eq(&cert_key) {
            return Err(AppError::Validation(
                "the private key does not match the certificate".to_string(),
            ));
        }
        encrypt_secret(&state.cfg, key_pem)?
    } else {
        encrypt_secret(&state.cfg, "")?
    };

    let next_id: Option<(i32,)> = sqlx::query_as("SELECT COALESCE(MAX(id), 0) + 1 FROM root_ca")
        .fetch_optional(&state.pool)
        .await?;
    let root_id = next_id.map(|r| r.0).unwrap_or(1);

    sqlx::query(
        "INSERT INTO root_ca (id, common_name, organization, description, cert_pem, private_key_enc, not_before, not_after, created_at, cipher, key_length, country, state, locality, org_unit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(root_id)
    .bind(&common_name)
    .bind(&payload.organization)
    .bind(payload.description.as_deref().unwrap_or(""))
    .bind(&payload.cert_pem)
    .bind(key_enc)
    .bind(valid_from)
    .bind(valid_to)
    .bind(Utc::now().naive_utc())
    .bind(&cipher)
    .bind(key_length)
    .bind(field(Nid::COUNTRYNAME))
    .bind(field(Nid::STATEORPROVINCENAME))
    .bind(field(Nid::LOCALITYNAME))
    .bind(field(Nid::ORGANIZATIONALUNITNAME))
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "root_ca.import",
        "root_ca",
        &root_id.to_string(),
        json!({
            "organization": payload.organization,
            "common_name": common_name,
            "has_private_key": has_private_key,
        }),
    )
    .await?;

    Ok(Json(json!({
        "root_id": root_id,
        "common_name": common_name,
        "has_private_key": has_private_key,
        "can_issue": has_private_key,
    })))
}

async fn import_tls_certificate(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<ImportTlsCertificateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let cert = X509::from_pem(payload.cert_pem.as_bytes())
        .map_err(|e| AppError::Validation(format!("invalid certificate PEM: {e}")))?;
    let serial_hex = cert
        .serial_number()
        .to_bn()
        .map_err(|e| AppError::Validation(format!("serial parse failed: {e}")))?
        .to_hex_str()
        .map_err(|e| AppError::Validation(format!("serial conversion failed: {e}")))?
        .to_string();
    let common_name = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Imported certificate".to_string());
    let valid_from_txt = cert.not_before().to_string();
    let valid_to_txt = cert.not_after().to_string();
    let valid_from =
        chrono::NaiveDateTime::parse_from_str(&valid_from_txt, "%b %e %H:%M:%S %Y GMT")
            .map_err(|e| AppError::Validation(format!("not_before parse failed: {e}")))?;
    let valid_to = chrono::NaiveDateTime::parse_from_str(&valid_to_txt, "%b %e %H:%M:%S %Y GMT")
        .map_err(|e| AppError::Validation(format!("not_after parse failed: {e}")))?;

    let cert_level = payload
        .cert_level
        .clone()
        .unwrap_or_else(|| "leaf".to_string());
    let root_id = payload.root_id.unwrap_or(1);
    let id = Uuid::new_v4().to_string();
    let key_enc = if let Some(k) = payload
        .private_key_pem
        .as_ref()
        .filter(|v| !v.trim().is_empty())
    {
        encrypt_secret(&state.cfg, k)?
    } else {
        encrypt_secret(&state.cfg, "")?
    };
    let usages = if cert_level == "intermediate" {
        json!(["keyCertSign", "cRLSign", "digitalSignature"])
    } else {
        json!(["digitalSignature", "keyEncipherment"])
    };
    let machine_id_to_store = if cert_level == "intermediate" {
        None
    } else {
        payload.machine_id.as_deref()
    };

    sqlx::query(
        "INSERT INTO tls_keys (id, machine_id, root_ca_id, parent_cert_id, common_name, serial_hex, cert_pem, private_key_enc, valid_from, valid_to, created_by, created_at, is_revoked, cert_level, cipher, key_length, usages_json, allow_private_key_export) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(machine_id_to_store)
    .bind(root_id)
    .bind(payload.parent_cert_id.as_deref())
    .bind(common_name)
    .bind(serial_hex)
    .bind(&payload.cert_pem)
    .bind(key_enc)
    .bind(valid_from)
    .bind(valid_to)
    .bind(&auth_user.username)
    .bind(Utc::now().naive_utc())
    .bind(cert_level)
    .bind(&payload.cipher)
    .bind(payload.key_length)
    .bind(usages.to_string())
    .bind(payload.publish_private_key)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "tls.import",
        "tls_key",
        &id,
        json!({"machine_id": payload.machine_id}),
    )
    .await?;
    Ok(Json(json!({"status":"imported","id":id})))
}

async fn import_ssh_key(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<ImportSshKeyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_ssh(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let machine_name = if let Some(name) = payload.machine_name.clone() {
        Some(name)
    } else if let Some(mid) = payload.machine_id.as_deref() {
        sqlx::query_as::<_, (String,)>("SELECT hostname FROM machines WHERE id = ?")
            .bind(mid)
            .fetch_optional(&state.pool)
            .await?
            .map(|r| r.0)
    } else {
        None
    };

    let id = Uuid::new_v4().to_string();
    let fingerprint = payload
        .public_key
        .split_whitespace()
        .nth(1)
        .map(|s| format!("imported:{s}"))
        .unwrap_or_else(|| "imported:unknown".to_string());
    let key_enc = if let Some(k) = payload
        .private_key
        .as_ref()
        .filter(|v| !v.trim().is_empty())
    {
        encrypt_secret(&state.cfg, k)?
    } else {
        encrypt_secret(&state.cfg, "")?
    };
    let now = Utc::now();
    let valid_to = now + chrono::Duration::days(365);

    sqlx::query(
        "INSERT INTO ssh_keys (id, machine_id, algorithm, public_key, private_key_enc, fingerprint_sha256, valid_from, valid_to, created_by, created_at, is_revoked, ssh_username, machine_name, cipher, key_length, allow_private_key_export) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(payload.machine_id.as_deref())
    .bind(&payload.cipher)
    .bind(&payload.public_key)
    .bind(key_enc)
    .bind(fingerprint)
    .bind(now.naive_utc())
    .bind(valid_to.naive_utc())
    .bind(&auth_user.username)
    .bind(now.naive_utc())
    .bind(&payload.ssh_username)
    .bind(machine_name)
    .bind(&payload.cipher)
    .bind(payload.key_length)
    .bind(payload.publish_private_key)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "ssh.import",
        "ssh_key",
        &id,
        json!({"machine_id": payload.machine_id, "ssh_username": payload.ssh_username}),
    )
    .await?;
    Ok(Json(json!({"status":"imported","id":id})))
}

async fn renew_tls_key(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<RenewTlsRequest>,
) -> AppResult<Json<GenerateTlsKeyResponse>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let old = sqlx::query_as::<_, TlsRenewRow>(
        "SELECT machine_id, common_name, root_ca_id, parent_cert_id, cipher, key_length, CAST(sans_json AS CHAR) AS sans_json, eku_purpose FROM tls_keys WHERE id = ?",
    )
    .bind(&payload.tls_key_id)
    .fetch_one(&state.pool)
    .await?;

    let sans: Option<Vec<String>> = old
        .sans_json
        .as_deref()
        .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok());
    // Le renouvellement garde tous les hôtes du certificat, pas seulement
    // celui de la colonne machine_id.
    let machine_ids: Vec<String> =
        sqlx::query_scalar("SELECT machine_id FROM tls_key_machines WHERE tls_key_id = ?")
            .bind(&payload.tls_key_id)
            .fetch_all(&state.pool)
            .await?;
    let req = GenerateTlsKeyRequest {
        machine_id: old.machine_id,
        machine_ids: Some(machine_ids),
        root_id: Some(old.root_ca_id),
        cert_level: Some("leaf".to_string()),
        parent_cert_id: old.parent_cert_id,
        common_name: old.common_name,
        valid_days: payload.valid_days,
        cipher: Some(old.cipher),
        key_length: Some(old.key_length),
        sans,
        purpose: old.eku_purpose,
        publish_private_key: false,
    };
    generate_tls_key(State(state), auth_user, Json(req)).await
}

#[derive(sqlx::FromRow)]
struct TlsRenewRow {
    machine_id: Option<String>,
    common_name: String,
    root_ca_id: i32,
    parent_cert_id: Option<String>,
    cipher: String,
    key_length: i32,
    sans_json: Option<String>,
    eku_purpose: Option<String>,
}

async fn generate_ssh_key(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<GenerateSshKeyRequest>,
) -> AppResult<Json<GenerateSshKeyResponse>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    authorize(&auth_user, "ssh:issue", can_manage_ssh(&auth_user.role))?;

    let material = generate_ssh_material(&payload.comment, payload.valid_days)?;
    let id = Uuid::new_v4().to_string();
    let machine_name = if let Some(mid) = payload.machine_id.as_deref() {
        sqlx::query_as::<_, (String,)>("SELECT hostname FROM machines WHERE id = ?")
            .bind(mid)
            .fetch_optional(&state.pool)
            .await?
            .map(|r| r.0)
    } else {
        None
    };
    let ssh_cipher = payload
        .cipher
        .clone()
        .unwrap_or_else(|| "ed25519".to_string());
    let ssh_key_length = payload.key_length.unwrap_or(256);

    sqlx::query(
        "INSERT INTO ssh_keys (id, machine_id, algorithm, public_key, private_key_enc, fingerprint_sha256, valid_from, valid_to, created_by, created_at, is_revoked, ssh_username, machine_name, cipher, key_length, allow_private_key_export) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.machine_id)
    .bind(&material.algorithm)
    .bind(&material.public_key)
    .bind(encrypt_secret(&state.cfg, &material.private_key)?)
    .bind(&material.fingerprint_sha256)
    .bind(material.valid_from.naive_utc())
    .bind(material.valid_to.naive_utc())
    .bind(&auth_user.username)
    .bind(Utc::now().naive_utc())
    .bind(&payload.comment)
    .bind(machine_name)
    .bind(&ssh_cipher)
    .bind(ssh_key_length)
    .bind(payload.publish_private_key)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "ssh.generate",
        "ssh_key",
        &id,
        json!({"machine_id": payload.machine_id, "fingerprint": material.fingerprint_sha256}),
    )
    .await?;

    Ok(Json(GenerateSshKeyResponse {
        key_id: id,
        algorithm: material.algorithm,
        public_key: material.public_key,
        private_key: material.private_key,
        fingerprint_sha256: material.fingerprint_sha256,
        valid_from: material.valid_from,
        valid_to: material.valid_to,
    }))
}

async fn revoke_tls(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<RevokeTlsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let found: Option<(String, i32, chrono::NaiveDateTime)> = sqlx::query_as(
        "SELECT serial_hex, root_ca_id, valid_to FROM tls_keys WHERE id = ?",
    )
    .bind(&payload.tls_key_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((serial_hex, root_ca_id, not_after)) = found else {
        return Err(AppError::NotFound);
    };

    let now = Utc::now().naive_utc();
    sqlx::query(
        "UPDATE tls_keys SET is_revoked = true, revoked_at = ?, revoked_reason = ? WHERE id = ?",
    )
    .bind(now)
    .bind(&payload.reason)
    .bind(&payload.tls_key_id)
    .execute(&state.pool)
    .await?;

    let crl_id = Uuid::new_v4().to_string();
    // La CA et l'expiration sont copiées ici : l'entrée doit survivre à la
    // suppression du certificat (voir migration 026).
    sqlx::query("INSERT INTO crl_entries (id, tls_key_id, serial_hex, revoked_at, reason, created_by, created_at, root_ca_id, not_after) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&crl_id)
        .bind(&payload.tls_key_id)
        .bind(serial_hex)
        .bind(now)
        .bind(&payload.reason)
        .bind(&auth_user.username)
        .bind(now)
        .bind(root_ca_id)
        .bind(not_after)
        .execute(&state.pool)
        .await?;

    audit(
        &state,
        &auth_user.username,
        "tls.revoke",
        "tls_key",
        &payload.tls_key_id,
        json!({"reason": payload.reason}),
    )
    .await?;

    // Refresh the published CRL(s) so the revocation propagates to the remote
    // distribution point. Best-effort — never fail the revocation on a push error.
    if let Err(e) = publish_crls(&state).await {
        tracing::warn!("CRL publish after revocation failed: {e}");
    }

    Ok(Json(
        json!({"status": "revoked", "tls_key_id": payload.tls_key_id}),
    ))
}

async fn revoke_ssh_key(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_ssh(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    sqlx::query(
        "UPDATE ssh_keys SET is_revoked = true, revoked_at = ?, revoked_reason = 'manual revocation' WHERE id = ?",
    )
    .bind(Utc::now().naive_utc())
    .bind(&id)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "ssh.revoke",
        "ssh_key",
        &id,
        json!({}),
    )
    .await?;

    Ok(Json(json!({"status": "revoked", "ssh_key_id": id})))
}

async fn delete_tls_cert(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    // L'entrée CRL éventuelle reste : le numéro de série est révoqué jusqu'à
    // l'expiration, que l'opérateur ait ou non fait le ménage.
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM tls_key_machines WHERE tls_key_id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    let deleted = sqlx::query("DELETE FROM tls_keys WHERE id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        &state,
        &auth_user.username,
        "tls.delete",
        "tls_key",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status": "deleted", "id": id})))
}

async fn delete_ssh_cert(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_ssh(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    sqlx::query("DELETE FROM ssh_keys WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    audit(
        &state,
        &auth_user.username,
        "ssh.delete",
        "ssh_key",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status": "deleted", "id": id})))
}

async fn set_tls_publish_key(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<PublishKeyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    sqlx::query("UPDATE tls_keys SET allow_private_key_export = ? WHERE id = ?")
        .bind(payload.allow_private_key_export)
        .bind(&id)
        .execute(&state.pool)
        .await?;
    audit(
        &state,
        &auth_user.username,
        "tls.publish_key.update",
        "tls_key",
        &id,
        json!({"allow_private_key_export": payload.allow_private_key_export}),
    )
    .await?;
    Ok(Json(json!({"status": "updated"})))
}

async fn set_ssh_publish_key(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<PublishKeyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_ssh(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    sqlx::query("UPDATE ssh_keys SET allow_private_key_export = ? WHERE id = ?")
        .bind(payload.allow_private_key_export)
        .bind(&id)
        .execute(&state.pool)
        .await?;
    audit(
        &state,
        &auth_user.username,
        "ssh.publish_key.update",
        "ssh_key",
        &id,
        json!({"allow_private_key_export": payload.allow_private_key_export}),
    )
    .await?;
    Ok(Json(json!({"status": "updated"})))
}

async fn list_tls_certs(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let (limit, offset) = parse_pagination(params);
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tls_keys")
        .fetch_one(&state.pool)
        .await?;
    let rows = sqlx::query_as::<_, (
        String,
        String,
        String,
        i32,
        Option<String>,
        String,
        chrono::NaiveDateTime,
        chrono::NaiveDateTime,
        bool,
        Option<String>,
        String,
        i32,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
    )>(
        "SELECT t.id, t.common_name, t.serial_hex, t.root_ca_id, t.parent_cert_id, t.cert_level, t.valid_from, t.valid_to, t.is_revoked, t.revoked_reason, t.cipher, t.key_length, t.usages_json, m.hostname, m.ip_address, t.allow_private_key_export FROM tls_keys t LEFT JOIN machines m ON t.machine_id = m.id ORDER BY t.created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    // Tous les hôtes de chaque certificat, en une requête à part : sqlx ne
    // dérive FromRow que jusqu'à seize colonnes, et la ligne ci-dessus les a
    // toutes. Une agrégation par certificat, puis une table de correspondance.
    let noms: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT tkm.tls_key_id, GROUP_CONCAT(CONCAT(m2.hostname, ' (', m2.ip_address, ')') ORDER BY m2.hostname SEPARATOR ', ') FROM tls_key_machines tkm JOIN machines m2 ON m2.id = tkm.machine_id GROUP BY tkm.tls_key_id",
    )
    .fetch_all(&state.pool)
    .await?;
    let machine_names: HashMap<String, String> = noms
        .into_iter()
        .filter_map(|(id, n)| n.map(|n| (id, n)))
        .collect();

    let body: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.0,
                "common_name": r.1,
                "serial_hex": r.2,
                "root_ca_id": r.3,
                "parent_cert_id": r.4,
                "cert_level": r.5,
                "valid_from": r.6,
                "valid_to": r.7,
                "is_revoked": r.8,
                "revoked_reason": r.9,
                "cipher": r.10,
                "key_length": r.11,
                "usages": r.12.and_then(|u| serde_json::from_str::<serde_json::Value>(&u).ok()).unwrap_or_else(|| json!([])),
                "machine_name": r.13,
                "ip_address": r.14,
                "allow_private_key_export": r.15,
                "machine_names": machine_names.get(&r.0),
            })
        })
        .collect();

    Ok(Json(
        json!({"items": body, "total": total, "limit": limit, "offset": offset}),
    ))
}

async fn list_ssh_certs(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let (limit, offset) = parse_pagination(params);
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ssh_keys")
        .fetch_one(&state.pool)
        .await?;
    let rows = sqlx::query_as::<_, (
        String,
        String,
        String,
        chrono::NaiveDateTime,
        chrono::NaiveDateTime,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        i32,
        bool,
    )>(
        "SELECT id, algorithm, fingerprint_sha256, valid_from, valid_to, is_revoked, ssh_username, machine_name, revoked_reason, cipher, key_length, allow_private_key_export FROM ssh_keys ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    let body: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.0,
                "algorithm": r.1,
                "fingerprint": r.2,
                "valid_from": r.3,
                "valid_to": r.4,
                "is_revoked": r.5,
                "ssh_username": r.6,
                "machine_name": r.7,
                "revoked_reason": r.8,
                "cipher": r.9,
                "key_length": r.10,
                "allow_private_key_export": r.11,
            })
        })
        .collect();

    Ok(Json(
        json!({"items": body, "total": total, "limit": limit, "offset": offset}),
    ))
}

async fn get_tls_cert(
    Path(id): Path<String>,
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let row: (String, String, String, String, String, bool) = sqlx::query_as(
        "SELECT id, common_name, cert_pem, private_key_enc, serial_hex, allow_private_key_export FROM tls_keys WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(json!({
        "id": row.0,
        "common_name": row.1,
        "cert_pem": row.2,
        "private_key_pem": if row.5 { decrypt_secret(&state.cfg, &row.3)? } else { "not published".to_string() },
        "serial_hex": row.4,
        "allow_private_key_export": row.5,
    })))
}

async fn get_ssh_cert(
    Path(id): Path<String>,
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let row: (String, String, String, String, bool) = sqlx::query_as(
        "SELECT id, algorithm, public_key, private_key_enc, allow_private_key_export FROM ssh_keys WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(json!({
        "id": row.0,
        "algorithm": row.1,
        "public_key": row.2,
        "private_key": if row.4 { decrypt_secret(&state.cfg, &row.3)? } else { "not published".to_string() },
        "allow_private_key_export": row.4,
    })))
}

async fn export_tls_public(
    Path(id): Path<String>,
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<(axum::http::HeaderMap, String)> {
    let row: (String, String) =
        sqlx::query_as("SELECT common_name, cert_pem FROM tls_keys WHERE id = ?")
            .bind(&id)
            .fetch_one(&state.pool)
            .await?;
    let filename = format!("{}-public.pem", row.0.replace(' ', "_"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-pem-file"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename))
            .map_err(|e| AppError::Internal(format!("content disposition error: {e}")))?,
    );
    Ok((headers, row.1))
}

async fn export_tls_private(
    Path(id): Path<String>,
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<(axum::http::HeaderMap, String)> {
    let row: (String, String, bool) = sqlx::query_as(
        "SELECT common_name, private_key_enc, allow_private_key_export FROM tls_keys WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;
    if !row.2 {
        return Err(AppError::Forbidden);
    }
    let filename = format!("{}-private.pem", row.0.replace(' ', "_"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-pem-file"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename))
            .map_err(|e| AppError::Internal(format!("content disposition error: {e}")))?,
    );
    Ok((headers, decrypt_secret(&state.cfg, &row.1)?))
}

/// Exports a TLS certificate in a chosen format: `pem` (default), `der`, or
/// `pkcs12`/`pfx`. PKCS#12 bundles the private key (requires export to be
/// allowed) and accepts an optional `password` query parameter.
async fn export_tls_cert(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    _auth: AuthenticatedUser,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let row: (String, String, String, bool) = sqlx::query_as(
        "SELECT common_name, cert_pem, private_key_enc, allow_private_key_export FROM tls_keys WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;
    let (cn, cert_pem, key_enc, allow_export) = row;
    let base = cn.replace(' ', "_");

    let (bytes, content_type, filename) =
        match params.get("format").map(|s| s.as_str()).unwrap_or("pem") {
            "der" | "cer" => (
                cert_pem_to_der(&cert_pem)?,
                "application/pkix-cert",
                format!("{base}.der"),
            ),
            "pkcs12" | "pfx" | "p12" => {
                if !allow_export {
                    return Err(AppError::Forbidden);
                }
                let key_pem = decrypt_secret(&state.cfg, &key_enc)?;
                if key_pem.trim().is_empty() {
                    return Err(AppError::Validation(
                        "no private key is stored for this certificate".to_string(),
                    ));
                }
                let password = params.get("password").cloned().unwrap_or_default();
                (
                    build_pkcs12(&cert_pem, &key_pem, &password, &cn)?,
                    "application/x-pkcs12",
                    format!("{base}.pfx"),
                )
            }
            _ => (
                cert_pem.into_bytes(),
                "application/x-pem-file",
                format!("{base}.pem"),
            ),
        };

    Ok((
        [
            (axum::http::header::CONTENT_TYPE, content_type.to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        bytes,
    )
        .into_response())
}

fn shell_escape_single_quotes(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
}

fn nginx_websocket_tls_snippet(
    cert_path: &str,
    key_path: &str,
    location: &str,
    upstream: &str,
) -> String {
    format!(
        "server {{
    listen 443 ssl http2;
    server_name _;

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};

    location {location} {{
        proxy_pass {upstream};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600;
    }}
}}",
        cert_path = cert_path,
        key_path = key_path,
        location = location,
        upstream = upstream
    )
}

fn tls_target_steps(target: &str) -> Vec<String> {
    match target {
        "nginx" => vec![
            "Set `ssl_certificate` to the full chain file and `ssl_certificate_key` to the private key.".to_string(),
            "Run `nginx -t` before reload.".to_string(),
        ],
        "nginx_docker_container" => vec![
            "Copy certificate/key files into the Nginx Docker container.".to_string(),
            "Install a secure WebSocket (wss) Nginx server block with Upgrade headers."
                .to_string(),
            "Validate with `docker exec <container> nginx -t` and reload Nginx.".to_string(),
        ],
        "nginx_podman_container" => vec![
            "Copy certificate/key files into the Nginx Podman container.".to_string(),
            "Install a secure WebSocket (wss) Nginx server block with Upgrade headers."
                .to_string(),
            "Validate with `podman exec <container> nginx -t` and reload Nginx.".to_string(),
        ],
        "apache" => vec![
            "Set `SSLCertificateFile` to the leaf cert file.".to_string(),
            "Set `SSLCertificateKeyFile` to the private key file.".to_string(),
            "Set `SSLCertificateChainFile` or use a full chain file if your setup requires it.".to_string(),
        ],
        "iis" => vec![
            "Create a PFX bundle from cert + private key and import it in Local Machine certificate store.".to_string(),
            "Bind HTTPS in IIS Manager to the imported certificate.".to_string(),
        ],
        "haproxy" => vec![
            "HAProxy usually expects one PEM bundle with cert chain + private key.".to_string(),
            "Reference bundle in `bind ... ssl crt /path/to/bundle.pem`.".to_string(),
        ],
        "kubernetes" => vec![
            "Create a TLS secret from cert and private key, then reference it in Ingress.".to_string(),
            "Ensure the cert presented includes intermediate chain when needed.".to_string(),
        ],
        _ => vec![
            "Check whether your application expects file upload, file paths, or pasted PEM text."
                .to_string(),
            "Use leaf certificate plus intermediate chain for client trust compatibility."
                .to_string(),
        ],
    }
}

async fn build_tls_deploy_guide(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<TlsDeployGuideRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let row: (String, String, String, bool, Option<String>, String) = sqlx::query_as(
        "SELECT common_name, cert_pem, private_key_enc, allow_private_key_export, parent_cert_id, cert_level FROM tls_keys WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;
    let cert_common_name = row.0;
    let leaf_cert_pem = row.1;
    let private_key_enc = row.2;
    let allow_private_export = row.3;
    let parent_cert_id = row.4;
    let cert_level = row.5;

    let parent_cert_pem: Option<String> = if let Some(parent_id) = parent_cert_id.clone() {
        sqlx::query_as("SELECT cert_pem FROM tls_keys WHERE id = ?")
            .bind(parent_id)
            .fetch_optional(&state.pool)
            .await?
            .map(|r: (String,)| r.0)
    } else {
        None
    };

    let private_key_pem = if allow_private_export {
        Some(decrypt_secret(&state.cfg, &private_key_enc)?)
    } else {
        None
    };
    let full_chain_pem = if let Some(parent) = parent_cert_pem.as_ref() {
        format!("{}\n{}", leaf_cert_pem.trim_end(), parent.trim_start())
    } else {
        leaf_cert_pem.clone()
    };

    let use_sudo = payload.use_sudo.unwrap_or(true);
    let sudo = if use_sudo { "sudo " } else { "" };
    let cert_path = payload.cert_path.trim();
    let key_path = payload.key_path.trim();
    let chain_path = payload
        .chain_path
        .as_deref()
        .unwrap_or(cert_path)
        .trim()
        .to_string();
    let websocket_location = payload
        .websocket_location
        .clone()
        .unwrap_or_else(|| "/ws/".to_string());
    let websocket_upstream = payload
        .websocket_upstream
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:3000".to_string());
    let nginx_conf_path = payload
        .nginx_conf_path
        .clone()
        .unwrap_or_else(|| "/etc/nginx/conf.d/wss.conf".to_string());
    let reload_command =
        payload
            .reload_command
            .clone()
            .unwrap_or_else(|| match payload.target.as_str() {
                "nginx" => "systemctl reload nginx".to_string(),
                "nginx_docker_container" => {
                    format!(
                        "docker exec {} nginx -s reload",
                        payload.container_name.as_deref().unwrap_or("nginx")
                    )
                }
                "nginx_podman_container" => {
                    format!(
                        "podman exec {} nginx -s reload",
                        payload.container_name.as_deref().unwrap_or("nginx")
                    )
                }
                "apache" => "systemctl reload apache2".to_string(),
                "haproxy" => "systemctl reload haproxy".to_string(),
                _ => "systemctl restart <service-name>".to_string(),
            });

    let is_container_target = matches!(
        payload.target.as_str(),
        "nginx_docker_container" | "nginx_podman_container"
    );
    let runtime = if payload.target == "nginx_podman_container" {
        "podman"
    } else {
        "docker"
    };
    let container_name = payload
        .container_name
        .clone()
        .unwrap_or_else(|| "nginx".to_string());
    let commands = if is_container_target {
        let mut c = vec![
            format!(
                "cat <<'EOF' | {runtime} exec -i {container} sh -c \"cat > '{path}'\"\n{cert}\nEOF",
                runtime = runtime,
                container = shell_escape_single_quotes(&container_name),
                path = shell_escape_single_quotes(cert_path),
                cert = leaf_cert_pem
            ),
            format!(
                "cat <<'EOF' | {runtime} exec -i {container} sh -c \"cat > '{path}'\"\n{chain}\nEOF",
                runtime = runtime,
                container = shell_escape_single_quotes(&container_name),
                path = shell_escape_single_quotes(&chain_path),
                chain = full_chain_pem
            ),
        ];
        if let Some(key) = private_key_pem.as_ref() {
            c.push(format!(
                "cat <<'EOF' | {runtime} exec -i {container} sh -c \"cat > '{path}'\"\n{key}\nEOF",
                runtime = runtime,
                container = shell_escape_single_quotes(&container_name),
                path = shell_escape_single_quotes(key_path),
                key = key
            ));
            c.push(format!(
                "{runtime} exec {container} sh -c \"chmod 600 '{path}'\"",
                runtime = runtime,
                container = shell_escape_single_quotes(&container_name),
                path = shell_escape_single_quotes(key_path)
            ));
        }
        let ws_snippet = nginx_websocket_tls_snippet(
            &chain_path,
            key_path,
            &websocket_location,
            &websocket_upstream,
        );
        c.push(format!(
            "cat <<'EOF' | {runtime} exec -i {container} sh -c \"cat > '{path}'\"\n{snippet}\nEOF",
            runtime = runtime,
            container = shell_escape_single_quotes(&container_name),
            path = shell_escape_single_quotes(&nginx_conf_path),
            snippet = ws_snippet
        ));
        c.push(format!(
            "{runtime} exec {container} nginx -t",
            runtime = runtime,
            container = shell_escape_single_quotes(&container_name)
        ));
        c.push(reload_command.clone());
        c
    } else {
        let mut c = vec![
            format!(
                "cat <<'EOF' | {sudo}tee '{path}' > /dev/null\n{cert}\nEOF",
                sudo = sudo,
                path = shell_escape_single_quotes(cert_path),
                cert = leaf_cert_pem
            ),
            format!(
                "cat <<'EOF' | {sudo}tee '{path}' > /dev/null\n{chain}\nEOF",
                sudo = sudo,
                path = shell_escape_single_quotes(&chain_path),
                chain = full_chain_pem
            ),
        ];
        if let Some(key) = private_key_pem.as_ref() {
            c.push(format!(
                "cat <<'EOF' | {sudo}tee '{path}' > /dev/null\n{key}\nEOF",
                sudo = sudo,
                path = shell_escape_single_quotes(key_path),
                key = key
            ));
            c.push(format!(
                "{sudo}chmod 600 '{path}'",
                sudo = sudo,
                path = shell_escape_single_quotes(key_path)
            ));
        }
        c.push(format!(
            "{sudo}{reload}",
            sudo = sudo,
            reload = reload_command
        ));
        c
    };

    let mut warnings = Vec::new();
    if private_key_pem.is_none() {
        warnings.push(
            "Private key export is disabled. Enable private key export before using automatic deployment commands."
                .to_string(),
        );
    }
    if cert_level == "leaf" && parent_cert_pem.is_none() {
        warnings.push(
            "No parent intermediate certificate linked. Some clients may require full chain."
                .to_string(),
        );
    }
    if is_container_target
        && payload
            .container_name
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    {
        warnings.push("Container name was not provided; default `nginx` was used.".to_string());
    }

    audit(
        &state,
        &auth_user.username,
        "tls.deploy.guide.build",
        "tls_key",
        &id,
        json!({"target": payload.target, "cert_path": cert_path, "key_path": key_path}),
    )
    .await?;

    let websocket_snippet = nginx_websocket_tls_snippet(
        &chain_path,
        key_path,
        &websocket_location,
        &websocket_upstream,
    );

    Ok(Json(json!({
        "certificate": {
            "id": id,
            "common_name": cert_common_name,
            "cert_level": cert_level,
            "allow_private_key_export": allow_private_export,
            "has_intermediate_chain": parent_cert_pem.is_some(),
        },
        "target": payload.target,
        "paths": {
            "cert_path": cert_path,
            "key_path": key_path,
            "chain_path": chain_path,
            "nginx_conf_path": nginx_conf_path,
        },
        "container": {
            "name": container_name,
            "runtime": if is_container_target { runtime } else { "" },
        },
        "websocket": {
            "location": websocket_location,
            "upstream": websocket_upstream,
        },
        "steps": tls_target_steps(&payload.target),
        "commands": commands,
        "artifacts": {
            "leaf_cert_pem": leaf_cert_pem,
            "intermediate_cert_pem": parent_cert_pem,
            "full_chain_pem": full_chain_pem,
            "private_key_pem": private_key_pem.unwrap_or_else(|| "not published".to_string()),
            "nginx_websocket_conf": websocket_snippet,
        },
        "warnings": warnings,
    })))
}

async fn export_ssh_public(
    Path(id): Path<String>,
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<(axum::http::HeaderMap, String)> {
    let row: (String, String) =
        sqlx::query_as("SELECT COALESCE(machine_name, id), public_key FROM ssh_keys WHERE id = ?")
            .bind(&id)
            .fetch_one(&state.pool)
            .await?;
    let filename = format!("{}-id.pub", row.0.replace(' ', "_"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename))
            .map_err(|e| AppError::Internal(format!("content disposition error: {e}")))?,
    );
    Ok((headers, row.1))
}

async fn export_ssh_private(
    Path(id): Path<String>,
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<(axum::http::HeaderMap, String)> {
    let row: (String, String, bool) = sqlx::query_as(
        "SELECT COALESCE(machine_name, id), private_key_enc, allow_private_key_export FROM ssh_keys WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;
    if !row.2 {
        return Err(AppError::Forbidden);
    }
    let filename = format!("{}-id", row.0.replace(' ', "_"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename))
            .map_err(|e| AppError::Internal(format!("content disposition error: {e}")))?,
    );
    Ok((headers, decrypt_secret(&state.cfg, &row.1)?))
}

async fn certificate_tree(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let root_id = params
        .get("root_id")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(1);
    let root: Option<(i32, String, String, Option<String>, chrono::NaiveDateTime, chrono::NaiveDateTime)> =
        sqlx::query_as("SELECT id, common_name, organization, description, not_before, not_after FROM root_ca WHERE id = ?")
            .bind(root_id)
            .fetch_optional(&state.pool)
            .await?;

    let tls_rows = sqlx::query_as::<_, (String, String, Option<String>, String, chrono::NaiveDateTime, chrono::NaiveDateTime, bool)>(
        "SELECT id, common_name, parent_cert_id, cert_level, valid_from, valid_to, is_revoked FROM tls_keys WHERE root_ca_id = ? ORDER BY created_at DESC",
    )
    .bind(root_id)
    .fetch_all(&state.pool)
    .await?;
    let tls: Vec<serde_json::Value> = tls_rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.0,
                "common_name": r.1,
                "parent_cert_id": r.2,
                "cert_level": r.3,
                "valid_from": r.4,
                "valid_to": r.5,
                "is_revoked": r.6,
            })
        })
        .collect();

    Ok(Json(json!({
        "root": root.map(|r| json!({"id": r.0, "name": r.1, "organization": r.2, "description": r.3, "valid_from": r.4, "valid_to": r.5, "depth": 0})).unwrap_or_else(|| json!({})),
        "leaf": tls,
    })))
}

async fn list_crl(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<Vec<CrlEntryRecord>>> {
    let rows = sqlx::query_as::<_, CrlEntryRecord>(
        "SELECT id, tls_key_id, serial_hex, revoked_at, reason, created_by, created_at FROM crl_entries ORDER BY revoked_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}

async fn list_users(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<Vec<serde_json::Value>>> {
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            chrono::NaiveDateTime,
            Option<String>,
            bool,
        ),
    >(
        "SELECT id, username, role, created_at, email, totp_enabled FROM users ORDER BY username ASC",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                json!({
                    "id": r.0,
                    "username": r.1,
                    "role": r.2,
                    "created_at": r.3,
                    "email": r.4,
                    "totp_enabled": r.5,
                })
            })
            .collect(),
    ))
}

async fn create_user(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateUserRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("unable to hash user password: {e}")))?
        .to_string();

    let email = normalize_optional_email(payload.email.as_deref().unwrap_or(""))?;
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    sqlx::query("INSERT INTO users (id, username, password_hash, role, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(&payload.username)
        .bind(hash)
        .bind(&payload.role)
        .bind(&email)
        .bind(now)
        .bind(now)
        .execute(&state.pool)
        .await?;

    audit(
        &state,
        &auth_user.username,
        "user.create",
        "user",
        &id,
        json!({"username": payload.username, "role": payload.role, "email": email}),
    )
    .await?;

    Ok(Json(json!({"status": "created", "id": id})))
}

async fn update_user_role(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<UpdateUserRoleRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    sqlx::query("UPDATE users SET role = ?, updated_at = ? WHERE id = ?")
        .bind(&payload.role)
        .bind(Utc::now().naive_utc())
        .bind(&id)
        .execute(&state.pool)
        .await?;

    audit(
        &state,
        &auth_user.username,
        "user.role.update",
        "user",
        &id,
        json!({"role": payload.role}),
    )
    .await?;

    Ok(Json(json!({"status": "updated"})))
}

async fn reset_user_password(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<ResetUserPasswordRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("unable to hash user password: {e}")))?
        .to_string();
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(hash)
        .bind(Utc::now().naive_utc())
        .bind(&id)
        .execute(&state.pool)
        .await?;

    audit(
        &state,
        &auth_user.username,
        "user.password.reset",
        "user",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status":"updated"})))
}

async fn delete_user(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }
    let mine: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(&auth_user.username)
        .fetch_optional(&state.pool)
        .await?;
    if mine.map(|r| r.0) == Some(id.clone()) {
        return Err(AppError::Validation(
            "you cannot delete your own account".to_string(),
        ));
    }

    for table in [
        "user_profiles",
        "user_recovery_codes",
        "webauthn_credentials",
        "password_reset_tokens",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id = ?"))
            .bind(&id)
            .execute(&state.pool)
            .await?;
    }
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    audit(
        &state,
        &auth_user.username,
        "user.delete",
        "user",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status":"deleted"})))
}

async fn get_me(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let row: (
        String,
        String,
        String,
        chrono::NaiveDateTime,
        Option<String>,
        bool,
    ) = sqlx::query_as(
        "SELECT id, username, role, created_at, email, totp_enabled FROM users WHERE username = ?",
    )
    .bind(&auth_user.username)
    .fetch_one(&state.pool)
    .await?;

    let picture: Option<(Option<String>,)> =
        sqlx::query_as("SELECT picture_data_url FROM user_profiles WHERE user_id = ?")
            .bind(&row.0)
            .fetch_optional(&state.pool)
            .await?;

    let history = sqlx::query_as::<_, (String, String, chrono::NaiveDateTime)>(
        "SELECT action, target_type, created_at FROM audit_logs WHERE actor = ? ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&auth_user.username)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(json!({
        "id": row.0,
        "username": row.1,
        "role": row.2,
        "created_at": row.3,
        "email": row.4,
        "totp_enabled": row.5,
        "picture_data_url": picture.and_then(|p| p.0),
        "history": history.into_iter().map(|h| json!({"action": h.0, "target_type": h.1, "created_at": h.2})).collect::<Vec<_>>()
    })))
}

async fn change_my_password(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    let row: (String, String) =
        sqlx::query_as("SELECT id, password_hash FROM users WHERE username = ?")
            .bind(&auth_user.username)
            .fetch_one(&state.pool)
            .await?;

    let parsed_hash = PasswordHash::new(&row.1).map_err(|_| AppError::Auth)?;
    if Argon2::default()
        .verify_password(payload.old_password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(AppError::Auth);
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("unable to hash password: {e}")))?
        .to_string();

    sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(hash)
        .bind(Utc::now().naive_utc())
        .bind(&row.0)
        .execute(&state.pool)
        .await?;

    audit(
        &state,
        &auth_user.username,
        "user.password.change",
        "user",
        &row.0,
        json!({}),
    )
    .await?;

    Ok(Json(json!({"status": "updated"})))
}

// ---------------------------------------------------------------------------
// API token management
//
// API tokens (`ezk_…`) let scripts/CI authenticate to the programmatic API.
// They are least-privilege: each carries an explicit set of scopes that must be
// a subset of what the creating user's role is allowed to grant. Token callers
// can never manage tokens or users themselves (`require_human`).
// ---------------------------------------------------------------------------

async fn list_api_tokens(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<Vec<serde_json::Value>>> {
    require_human(&auth_user)?;

    // full_admin sees every token; everyone else sees only their own.
    let is_admin = auth_user.role == "full_admin";
    let rows = if is_admin {
        sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<String>,
                String,
                String,
                String,
                chrono::NaiveDateTime,
                Option<chrono::NaiveDateTime>,
                Option<chrono::NaiveDateTime>,
                Option<String>,
                bool,
            ),
        >(
            "SELECT id, name, comment, token_prefix, scopes, owner_username, created_at, expires_at, last_used_at, last_used_ip, is_revoked FROM api_tokens ORDER BY created_at DESC",
        )
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, name, comment, token_prefix, scopes, owner_username, created_at, expires_at, last_used_at, last_used_ip, is_revoked FROM api_tokens WHERE owner_username = ? ORDER BY created_at DESC",
        )
        .bind(&auth_user.username)
        .fetch_all(&state.pool)
        .await?
    };

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                json!({
                    "id": r.0,
                    "name": r.1,
                    "comment": r.2,
                    "token_prefix": r.3,
                    "scopes": r.4.split_whitespace().collect::<Vec<_>>(),
                    "owner_username": r.5,
                    "created_at": r.6,
                    "expires_at": r.7,
                    "last_used_at": r.8,
                    "last_used_ip": r.9,
                    "is_revoked": r.10,
                })
            })
            .collect(),
    ))
}

async fn create_api_token(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateApiTokenRequest>,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    // Normalize + validate requested scopes against the vocabulary and the
    // grant ceiling for the creator's role.
    let grantable = grantable_scopes_for_role(&auth_user.role);
    if grantable.is_empty() {
        return Err(AppError::Forbidden);
    }
    let mut scopes: Vec<String> = Vec::new();
    for raw in &payload.scopes {
        let scope = raw.trim();
        if scope.is_empty() {
            continue;
        }
        if !ALL_SCOPES.contains(&scope) {
            return Err(AppError::Validation(format!("unknown scope: {scope}")));
        }
        if !grantable.contains(&scope) {
            return Err(AppError::Forbidden);
        }
        if !scopes.iter().any(|s| s == scope) {
            scopes.push(scope.to_string());
        }
    }
    if scopes.is_empty() {
        return Err(AppError::Validation(
            "at least one scope is required".to_string(),
        ));
    }

    let owner: (String,) = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(&auth_user.username)
        .fetch_one(&state.pool)
        .await?;

    let (full_token, prefix, hash) = generate_api_token();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    let expires_at = payload
        .expires_in_days
        .map(|d| now + chrono::Duration::days(d));
    let scopes_str = scopes.join(" ");

    sqlx::query(
        "INSERT INTO api_tokens (id, name, comment, token_prefix, token_hash, scopes, owner_user_id, owner_username, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.name)
    .bind(&payload.comment)
    .bind(&prefix)
    .bind(&hash)
    .bind(&scopes_str)
    .bind(&owner.0)
    .bind(&auth_user.username)
    .bind(&auth_user.username)
    .bind(now)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "token.create",
        "api_token",
        &id,
        json!({"name": payload.name, "scopes": scopes, "expires_at": expires_at}),
    )
    .await?;

    // Plaintext token is returned exactly once — never retrievable again.
    Ok(Json(json!({
        "id": id,
        "token": full_token,
        "token_prefix": prefix,
        "name": payload.name,
        "scopes": scopes,
        "expires_at": expires_at,
    })))
}

/// Resolves a token by id, enforcing that the caller owns it or is full_admin.
/// Returns the token owner username (for auditing).
async fn load_manageable_token(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    id: &str,
) -> AppResult<String> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT owner_username FROM api_tokens WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
    let owner = row.ok_or(AppError::NotFound)?.0;
    if auth_user.role != "full_admin" && owner != auth_user.username {
        return Err(AppError::Forbidden);
    }
    Ok(owner)
}

async fn revoke_api_token(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    load_manageable_token(&state, &auth_user, &id).await?;

    sqlx::query("UPDATE api_tokens SET is_revoked = TRUE, revoked_at = ? WHERE id = ?")
        .bind(Utc::now().naive_utc())
        .bind(&id)
        .execute(&state.pool)
        .await?;

    audit(
        &state,
        &auth_user.username,
        "token.revoke",
        "api_token",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status": "revoked"})))
}

async fn delete_api_token(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    load_manageable_token(&state, &auth_user, &id).await?;

    sqlx::query("DELETE FROM api_tokens WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;

    audit(
        &state,
        &auth_user.username,
        "token.delete",
        "api_token",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status": "deleted"})))
}

/// Public-ish helper so the UI can render the scope picker without hardcoding
/// the vocabulary. Returns the scopes the current user may grant.
async fn list_grantable_scopes(auth_user: AuthenticatedUser) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    let scopes = grantable_scopes_for_role(&auth_user.role);
    Ok(Json(json!({
        "scopes": scopes,
        "descriptions": {
            "tls:issue": "Issue TLS leaf/intermediate certificates and keys",
            "tls:read": "Read TLS certificate details and the CRL",
            "ssh:issue": "Generate SSH keypairs",
            "ssh:sign": "Sign SSH certificates from the SSH CA",
            "ssh:read": "Read SSH key/certificate details",
            "ca:read": "Read CA public keys (TLS root, SSH user/host CAs)"
        }
    })))
}

async fn upload_my_picture(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<SaveProfilePictureRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;

    let user: (String,) = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(&auth_user.username)
        .fetch_one(&state.pool)
        .await?;

    sqlx::query(
        "INSERT INTO user_profiles (user_id, picture_data_url, updated_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE picture_data_url = VALUES(picture_data_url), updated_at = VALUES(updated_at)",
    )
    .bind(&user.0)
    .bind(&payload.picture_data_url)
    .bind(Utc::now().naive_utc())
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "user.picture.upload",
        "user",
        &user.0,
        json!({}),
    )
    .await?;

    Ok(Json(json!({"status": "updated"})))
}

async fn delete_my_picture(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let user: (String,) = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(&auth_user.username)
        .fetch_one(&state.pool)
        .await?;

    sqlx::query(
        "UPDATE user_profiles SET picture_data_url = NULL, updated_at = ? WHERE user_id = ?",
    )
    .bind(Utc::now().naive_utc())
    .bind(&user.0)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "user.picture.delete",
        "user",
        &user.0,
        json!({}),
    )
    .await?;

    Ok(Json(json!({"status": "deleted"})))
}

async fn get_defaults(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT key_name, value_text FROM settings WHERE key_name IN ('default_tls_cipher', 'default_tls_key_length', 'default_ssh_cipher', 'default_ssh_key_length', 'cert_owners_json', 'cert_environments_json', 'public_base_url', 'crl_base_url')",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut map = HashMap::new();
    for (k, v) in rows {
        map.insert(k, v);
    }

    Ok(Json(json!({
        "default_tls_cipher": map.get("default_tls_cipher").cloned().unwrap_or_else(|| "ed25519".to_string()),
        "default_tls_key_length": map.get("default_tls_key_length").cloned().unwrap_or_else(|| "256".to_string()).parse::<i64>().unwrap_or(256),
        "default_ssh_cipher": map.get("default_ssh_cipher").cloned().unwrap_or_else(|| "ed25519".to_string()),
        "default_ssh_key_length": map.get("default_ssh_key_length").cloned().unwrap_or_else(|| "256".to_string()).parse::<i64>().unwrap_or(256),
        "cert_owners_json": map.get("cert_owners_json").cloned().unwrap_or_else(|| "[\"lab-ops\",\"security\",\"devops\"]".to_string()),
        "cert_environments_json": map.get("cert_environments_json").cloned().unwrap_or_else(|| "[\"production\",\"staging\",\"internal-lab\",\"development\"]".to_string()),
        "public_base_url": map.get("public_base_url").cloned().unwrap_or_default(),
        "crl_base_url": map.get("crl_base_url").cloned().unwrap_or_default(),
    })))
}

async fn save_defaults(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<SaveDefaultsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    let now = Utc::now().naive_utc();
    for (k, v) in [
        ("default_tls_cipher", payload.default_tls_cipher.clone()),
        (
            "default_tls_key_length",
            payload.default_tls_key_length.to_string(),
        ),
        ("default_ssh_cipher", payload.default_ssh_cipher.clone()),
        (
            "default_ssh_key_length",
            payload.default_ssh_key_length.to_string(),
        ),
        (
            "cert_owners_json",
            payload
                .cert_owners_json
                .clone()
                .unwrap_or_else(|| "[\"lab-ops\",\"security\",\"devops\"]".to_string()),
        ),
        (
            "cert_environments_json",
            payload.cert_environments_json.clone().unwrap_or_else(|| {
                "[\"production\",\"staging\",\"internal-lab\",\"development\"]".to_string()
            }),
        ),
        (
            "public_base_url",
            payload.public_base_url.clone().unwrap_or_default(),
        ),
        (
            "crl_base_url",
            payload.crl_base_url.clone().unwrap_or_default(),
        ),
    ] {
        sqlx::query(
            "INSERT INTO settings (key_name, value_text, updated_by, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE value_text = VALUES(value_text), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)",
        )
        .bind(k)
        .bind(v)
        .bind(&auth_user.username)
        .bind(now)
        .execute(&state.pool)
        .await?;
    }

    audit(
        &state,
        &auth_user.username,
        "settings.update",
        "settings",
        "defaults",
        json!({}),
    )
    .await?;

    Ok(Json(json!({"status": "updated"})))
}

async fn get_notification_settings(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT key_name, value_text FROM settings WHERE key_name IN ('notify_webhook_url', 'notify_days_before', 'notify_cooldown_hours', 'notify_email_to')",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut map = HashMap::new();
    for (k, v) in rows {
        map.insert(k, v);
    }

    Ok(Json(json!({
        "webhook_url": map.get("notify_webhook_url").cloned().unwrap_or_default(),
        "days_before": map.get("notify_days_before").cloned().unwrap_or_else(|| "30".to_string()).parse::<i64>().unwrap_or(30),
        "cooldown_hours": map.get("notify_cooldown_hours").cloned().unwrap_or_else(|| "24".to_string()).parse::<i64>().unwrap_or(24),
        "email_to": map.get("notify_email_to").cloned().unwrap_or_default(),
    })))
}

async fn save_notification_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<SaveNotificationSettingsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    let now = Utc::now().naive_utc();
    for (k, v) in [
        ("notify_webhook_url", payload.webhook_url.clone()),
        ("notify_days_before", payload.days_before.to_string()),
        ("notify_cooldown_hours", payload.cooldown_hours.to_string()),
        (
            "notify_email_to",
            payload.email_to.clone().unwrap_or_default(),
        ),
    ] {
        sqlx::query(
            "INSERT INTO settings (key_name, value_text, updated_by, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE value_text = VALUES(value_text), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)",
        )
        .bind(k)
        .bind(v)
        .bind(&auth_user.username)
        .bind(now)
        .execute(&state.pool)
        .await?;
    }

    audit(
        &state,
        &auth_user.username,
        "settings.notifications.update",
        "settings",
        "notifications",
        json!({}),
    )
    .await?;

    Ok(Json(json!({"status": "updated"})))
}

async fn get_machine_monitor_settings(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT key_name, value_text FROM settings WHERE key_name IN ('machine_monitor_enabled', 'machine_monitor_frequency_hours', 'machine_monitor_default_ports_csv', 'machine_monitor_alert_webhook_url', 'machine_monitor_alert_email_to', 'machine_monitor_alert_cooldown_hours')",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut map = HashMap::new();
    for (k, v) in rows {
        map.insert(k, v);
    }

    Ok(Json(json!({
        "monitor_enabled": map.get("machine_monitor_enabled").map(|v| v == "true" || v == "1").unwrap_or(true),
        "frequency_hours": map.get("machine_monitor_frequency_hours").cloned().unwrap_or_else(|| "24".to_string()).parse::<i64>().unwrap_or(24),
        "default_ports_csv": map.get("machine_monitor_default_ports_csv").cloned().unwrap_or_else(|| "443,8443".to_string()),
        "alert_webhook_url": map.get("machine_monitor_alert_webhook_url").cloned().unwrap_or_default(),
        "alert_email_to": map.get("machine_monitor_alert_email_to").cloned().unwrap_or_default(),
        "alert_cooldown_hours": map.get("machine_monitor_alert_cooldown_hours").cloned().unwrap_or_else(|| "24".to_string()).parse::<i64>().unwrap_or(24),
    })))
}

async fn save_machine_monitor_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<SaveMachineMonitorSettingsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    let now = Utc::now().naive_utc();
    for (k, v) in [
        (
            "machine_monitor_enabled",
            if payload.monitor_enabled {
                "true".to_string()
            } else {
                "false".to_string()
            },
        ),
        (
            "machine_monitor_frequency_hours",
            payload.frequency_hours.to_string(),
        ),
        (
            "machine_monitor_default_ports_csv",
            payload.default_ports_csv.clone(),
        ),
        (
            "machine_monitor_alert_webhook_url",
            payload.alert_webhook_url.clone(),
        ),
        (
            "machine_monitor_alert_email_to",
            payload.alert_email_to.clone(),
        ),
        (
            "machine_monitor_alert_cooldown_hours",
            payload.alert_cooldown_hours.to_string(),
        ),
    ] {
        sqlx::query(
            "INSERT INTO settings (key_name, value_text, updated_by, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE value_text = VALUES(value_text), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)",
        )
        .bind(k)
        .bind(v)
        .bind(&auth_user.username)
        .bind(now)
        .execute(&state.pool)
        .await?;
    }

    audit(
        &state,
        &auth_user.username,
        "settings.machine_monitor.update",
        "settings",
        "machine_monitor",
        json!({}),
    )
    .await?;

    Ok(Json(json!({"status": "updated"})))
}

async fn get_siem_settings(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT key_name, value_text FROM settings WHERE key_name IN ('siem_webhook_url', 'siem_bruteforce_window_minutes', 'siem_bruteforce_threshold', 'siem_alert_cooldown_minutes')",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut map = HashMap::new();
    for (k, v) in rows {
        map.insert(k, v);
    }

    Ok(Json(json!({
        "webhook_url": map.get("siem_webhook_url").cloned().unwrap_or_default(),
        "brute_force_window_minutes": map.get("siem_bruteforce_window_minutes").cloned().unwrap_or_else(|| "10".to_string()).parse::<i64>().unwrap_or(10),
        "brute_force_threshold": map.get("siem_bruteforce_threshold").cloned().unwrap_or_else(|| "5".to_string()).parse::<i64>().unwrap_or(5),
        "alert_cooldown_minutes": map.get("siem_alert_cooldown_minutes").cloned().unwrap_or_else(|| "30".to_string()).parse::<i64>().unwrap_or(30),
    })))
}

async fn save_siem_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<SaveSiemSettingsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    let now = Utc::now().naive_utc();
    for (k, v) in [
        ("siem_webhook_url", payload.webhook_url.clone()),
        (
            "siem_bruteforce_window_minutes",
            payload.brute_force_window_minutes.to_string(),
        ),
        (
            "siem_bruteforce_threshold",
            payload.brute_force_threshold.to_string(),
        ),
        (
            "siem_alert_cooldown_minutes",
            payload.alert_cooldown_minutes.to_string(),
        ),
    ] {
        sqlx::query(
            "INSERT INTO settings (key_name, value_text, updated_by, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE value_text = VALUES(value_text), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)",
        )
        .bind(k)
        .bind(v)
        .bind(&auth_user.username)
        .bind(now)
        .execute(&state.pool)
        .await?;
    }

    audit(
        &state,
        &auth_user.username,
        "settings.siem.update",
        "settings",
        "siem",
        json!({}),
    )
    .await?;

    Ok(Json(json!({"status": "updated"})))
}

async fn list_addons(
    _state: State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<Vec<serde_json::Value>>> {
    let dir = std::env::var("ADDONS_DIR").unwrap_or_else(|_| "/data/addons".to_string());
    let mut addons = load_addons(&dir);
    if addons.is_empty() {
        addons = load_addons("/app/addons");
    }
    Ok(Json(
        addons
            .into_iter()
            .map(|a| {
                json!({
                    "id": a.id,
                    "name": a.name,
                    "target": a.target,
                    "connection": a.connection,
                    "auth": a.auth,
                    "deployment": a.deployment,
                })
            })
            .collect(),
    ))
}

async fn build_integration_plan(
    _state: State<AppState>,
    _auth: AuthenticatedUser,
    Json(payload): Json<IntegrationPlanRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    let dir = std::env::var("ADDONS_DIR").unwrap_or_else(|_| "/data/addons".to_string());
    let mut addons = load_addons(&dir);
    if addons.is_empty() {
        addons = load_addons("/app/addons");
    }
    let addon = addons
        .into_iter()
        .find(|a| a.id == payload.addon_id)
        .ok_or_else(|| AppError::Validation("addon not found".to_string()))?;

    Ok(Json(json!({
        "addon": addon,
        "values": payload.values,
        "plan": [
            "connect using addon.connection + addon.auth",
            "copy key/cert files to deployment paths",
            "run reload command and post commands",
            "write action log",
        ],
    })))
}

async fn list_action_logs(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_audit(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let actor_filter = params.get("actor").cloned().unwrap_or_default();
    let action_filter = params.get("action").cloned().unwrap_or_default();
    let (limit, offset) = parse_pagination_from_map(&params);

    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE (? = '' OR actor LIKE ?) AND (? = '' OR action LIKE ?)",
    )
    .bind(&actor_filter)
    .bind(format!("%{}%", actor_filter))
    .bind(&action_filter)
    .bind(format!("%{}%", action_filter))
    .fetch_one(&state.pool)
    .await?;

    let rows = sqlx::query_as::<_, (
        String,
        String,
        String,
        String,
        String,
        String,
        chrono::NaiveDateTime,
    )>(
        "SELECT id, actor, action, target_type, target_id, details_json, created_at FROM audit_logs WHERE (? = '' OR actor LIKE ?) AND (? = '' OR action LIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(&actor_filter)
    .bind(format!("%{}%", actor_filter))
    .bind(&action_filter)
    .bind(format!("%{}%", action_filter))
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(json!({
        "items": rows.into_iter()
            .map(|r| {
                json!({
                    "id": r.0,
                    "actor": r.1,
                    "action": r.2,
                    "target_type": r.3,
                    "target_id": r.4,
                    "details": serde_json::from_str::<serde_json::Value>(&r.5).unwrap_or_else(|_| json!({"raw": r.5})),
                    "created_at": r.6,
                })
            })
            .collect::<Vec<_>>(),
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

async fn list_access_logs(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_audit(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let actor_filter = params.get("actor").cloned().unwrap_or_default();
    let path_filter = params.get("path").cloned().unwrap_or_default();
    let (limit, offset) = parse_pagination_from_map(&params);

    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM access_logs WHERE (? = '' OR actor LIKE ?) AND (? = '' OR path LIKE ?)",
    )
    .bind(&actor_filter)
    .bind(format!("%{}%", actor_filter))
    .bind(&path_filter)
    .bind(format!("%{}%", path_filter))
    .fetch_one(&state.pool)
    .await?;

    let rows = sqlx::query_as::<_, (
        String,
        String,
        String,
        String,
        String,
        i32,
        chrono::NaiveDateTime,
    )>(
        "SELECT id, actor, source_ip, method, path, status_code, created_at FROM access_logs WHERE (? = '' OR actor LIKE ?) AND (? = '' OR path LIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(&actor_filter)
    .bind(format!("%{}%", actor_filter))
    .bind(&path_filter)
    .bind(format!("%{}%", path_filter))
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(json!({
        "items": rows.into_iter()
            .map(|r| {
                json!({
                    "id": r.0,
                    "actor": r.1,
                    "source_ip": r.2,
                    "method": r.3,
                    "path": r.4,
                    "status_code": r.5,
                    "created_at": r.6,
                })
            })
            .collect::<Vec<_>>(),
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

async fn list_security_logs(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_audit(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let event_filter = params.get("event_type").cloned().unwrap_or_default();
    let ip_filter = params.get("source_ip").cloned().unwrap_or_default();
    let (limit, offset) = parse_pagination_from_map(&params);

    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM security_events WHERE (? = '' OR event_type LIKE ?) AND (? = '' OR source_ip LIKE ?)",
    )
    .bind(&event_filter)
    .bind(format!("%{}%", event_filter))
    .bind(&ip_filter)
    .bind(format!("%{}%", ip_filter))
    .fetch_one(&state.pool)
    .await?;

    let rows = sqlx::query_as::<_, (
        String,
        String,
        String,
        String,
        String,
        chrono::NaiveDateTime,
    )>(
        "SELECT id, event_type, severity, source_ip, details_json, created_at FROM security_events WHERE (? = '' OR event_type LIKE ?) AND (? = '' OR source_ip LIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(&event_filter)
    .bind(format!("%{}%", event_filter))
    .bind(&ip_filter)
    .bind(format!("%{}%", ip_filter))
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(json!({
        "items": rows.into_iter()
            .map(|r| {
                json!({
                    "id": r.0,
                    "event_type": r.1,
                    "severity": r.2,
                    "source_ip": r.3,
                    "details": serde_json::from_str::<serde_json::Value>(&r.4).unwrap_or_else(|_| json!({"raw": r.4})),
                    "created_at": r.5,
                })
            })
            .collect::<Vec<_>>(),
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

async fn resolve_network_info(
    Query(params): Query<HashMap<String, String>>,
    _state: State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let hostname = params.get("hostname").cloned().unwrap_or_default();
    let ip = params.get("ip").cloned().unwrap_or_default();

    let mut ips = Vec::new();
    let mut reverse = String::new();

    if !hostname.is_empty() {
        let addrs = tokio::net::lookup_host((hostname.as_str(), 0))
            .await
            .map_err(|e| AppError::Validation(format!("hostname resolution failed: {e}")))?;
        for a in addrs {
            let v = a.ip().to_string();
            if !ips.contains(&v) {
                ips.push(v);
            }
        }
    }

    if !ip.is_empty() {
        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|e| AppError::Validation(format!("invalid ip: {e}")))?;
        reverse = dns_lookup::lookup_addr(&ip_addr)
            .map_err(|e| AppError::Validation(format!("reverse dns failed: {e}")))?;
    }

    Ok(Json(json!({"ips": ips, "reverse_hostname": reverse})))
}

/// Ce qu'un nom de certificat désigne sur le réseau, rapproché des machines
/// connues. Sert au formulaire de création : avant d'affecter un certificat,
/// on montre à l'opérateur où son nom pointe et si l'hôte existe déjà.
#[derive(Debug, Serialize)]
pub struct HostMatchAddress {
    pub ip: String,
    /// Nom obtenu par résolution inverse, quand il y en a un.
    pub reverse: Option<String>,
    /// Machine déjà enregistrée qui porte cette adresse — ou ce nom.
    pub machine: Option<HostMatchMachine>,
}

#[derive(Debug, Serialize)]
pub struct HostMatchMachine {
    pub id: String,
    pub hostname: String,
    pub ip_address: String,
}

#[derive(Debug, Serialize)]
pub struct HostMatchResponse {
    /// Ce qui a été demandé, tel quel.
    pub queried: String,
    /// Ce qui a réellement été résolu : pour `*.example.com`, le domaine de
    /// base — un joker ne se résout pas.
    pub resolved: String,
    pub wildcard: bool,
    /// Nom canonique renvoyé par le résolveur. S'il diffère de `resolved`,
    /// un CNAME est passé par là.
    pub canonical_name: Option<String>,
    pub addresses: Vec<HostMatchAddress>,
    /// Machines dont le NOM correspond, même si aucune adresse ne concorde —
    /// une machine enregistrée sous ce nom mais avec une autre IP mérite
    /// d'être signalée plutôt que dupliquée.
    pub machines_by_name: Vec<HostMatchMachine>,
    pub error: Option<String>,
}

/// GET /api/v1/network/match?name=<nom>
///
/// Résolution directe avec demande du nom canonique, résolution inverse de
/// chaque adresse, puis rapprochement avec la table des machines par adresse
/// et par nom. Aucune de ces étapes n'est bloquante : une résolution qui
/// échoue produit une réponse avec `error` rempli, pas une erreur HTTP — le
/// formulaire doit rester utilisable hors ligne ou pour un nom pas encore
/// publié dans le DNS.
async fn match_hostname(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<HostMatchResponse>> {
    let queried = params
        .get("name")
        .map(|n| n.trim().trim_end_matches('.').to_string())
        .unwrap_or_default();
    if queried.is_empty() || queried.len() > 253 {
        return Err(AppError::Validation(
            "name: a host name of 1 to 253 characters is required".to_string(),
        ));
    }
    let wildcard = queried.starts_with("*.");
    let resolved = if wildcard {
        queried.trim_start_matches("*.").to_string()
    } else {
        queried.clone()
    };
    if resolved.is_empty() {
        return Err(AppError::Validation(
            "name: a wildcard needs a base domain".to_string(),
        ));
    }

    // AI_CANONNAME vaut 2 sur Linux (glibc et musl) : l'image est Debian.
    // getaddrinfo renvoie alors le nom canonique final dans le premier
    // résultat, ce qui suffit à dire « un CNAME est passé par là ».
    const AI_CANONNAME: i32 = 2;
    let lookup_name = resolved.clone();
    let lookup = tokio::task::spawn_blocking(move || {
        let hints = dns_lookup::AddrInfoHints {
            flags: AI_CANONNAME,
            ..dns_lookup::AddrInfoHints::default()
        };
        dns_lookup::getaddrinfo(Some(&lookup_name), None, Some(hints)).map(|iter| {
            let mut canonical: Option<String> = None;
            let mut ips: Vec<IpAddr> = Vec::new();
            for entry in iter.flatten() {
                if canonical.is_none() {
                    canonical = entry.canonname.clone();
                }
                let ip = entry.sockaddr.ip();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            (canonical, ips)
        })
    })
    .await
    .map_err(|e| AppError::Internal(format!("dns task failed: {e}")))?;

    let (canonical_name, ips, error) = match lookup {
        Ok((canonical, ips)) => (canonical, ips, None),
        Err(e) => (
            None,
            Vec::new(),
            Some(format!("resolution failed: {:?}", e.kind())),
        ),
    };
    let canonical_name = canonical_name
        .map(|c| c.trim_end_matches('.').to_string())
        .filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case(&resolved));

    // Résolution inverse, adresse par adresse, sans jamais échouer.
    let mut addresses: Vec<HostMatchAddress> = Vec::with_capacity(ips.len());
    for ip in ips {
        let reverse = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok())
            .await
            .ok()
            .flatten()
            .map(|r| r.trim_end_matches('.').to_string())
            .filter(|r| !r.is_empty() && r != &ip.to_string());
        let ip_text = ip.to_string();
        let machine: Option<(String, String, String)> = sqlx::query_as(
            "SELECT id, hostname, ip_address FROM machines WHERE ip_address = ? LIMIT 1",
        )
        .bind(&ip_text)
        .fetch_optional(&state.pool)
        .await?;
        addresses.push(HostMatchAddress {
            ip: ip_text,
            reverse,
            machine: machine.map(|(id, hostname, ip_address)| HostMatchMachine {
                id,
                hostname,
                ip_address,
            }),
        });
    }

    // Rapprochement par nom : le nom demandé, le canonique, les inverses.
    let mut names: Vec<String> = vec![resolved.to_ascii_lowercase()];
    if let Some(c) = &canonical_name {
        names.push(c.to_ascii_lowercase());
    }
    for a in &addresses {
        if let Some(r) = &a.reverse {
            names.push(r.to_ascii_lowercase());
        }
    }
    names.sort();
    names.dedup();
    let mut machines_by_name: Vec<HostMatchMachine> = Vec::new();
    for n in &names {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT id, hostname, ip_address FROM machines WHERE LOWER(hostname) = ? LIMIT 10",
        )
        .bind(n)
        .fetch_all(&state.pool)
        .await?;
        for (id, hostname, ip_address) in rows {
            let deja_par_adresse = addresses
                .iter()
                .any(|a| a.machine.as_ref().is_some_and(|m| m.id == id));
            if !deja_par_adresse && !machines_by_name.iter().any(|m| m.id == id) {
                machines_by_name.push(HostMatchMachine {
                    id,
                    hostname,
                    ip_address,
                });
            }
        }
    }

    Ok(Json(HostMatchResponse {
        queried,
        resolved,
        wildcard,
        canonical_name,
        addresses,
        machines_by_name,
        error,
    }))
}

async fn download_root_ca(
    Path(platform): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> AppResult<(axum::http::HeaderMap, String)> {
    let root_id = params
        .get("root_id")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(1);
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT cert_pem, organization FROM root_ca WHERE id = ?")
            .bind(root_id)
            .fetch_optional(&state.pool)
            .await?;

    let Some((cert_pem, organization)) = row else {
        return Err(AppError::NotFound);
    };

    let prefix = organization_filename_prefix(&organization);
    let filename = match platform.as_str() {
        "windows" => format!("{prefix}-root-ca.cer"),
        "macos" => format!("{prefix}-root-ca.pem"),
        "linux" => format!("{prefix}-root-ca.pem"),
        "ios" => format!("{prefix}-root-ca.cer"),
        "android" => format!("{prefix}-root-ca.crt"),
        _ => {
            return Err(AppError::Validation(
                "platform must be one of: windows, macos, linux, ios, android".to_string(),
            ))
        }
    };

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-pem-file"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|e| AppError::Internal(format!("content disposition error: {e}")))?,
    );

    Ok((headers, cert_pem))
}

// ---- Applications (deployment target catalog) ----

async fn list_applications(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    // Un built-in « supprimé » reste en base — sinon le semis du démarrage le
    // ferait revenir — mais il disparaît du catalogue. `?include_retired=true`
    // le remontre, ce qui est le seul moyen de le réactiver.
    let include_retired = params
        .get("include_retired")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let rows = sqlx::query_as::<_, ApplicationRecord>(
        "SELECT id, slug, name, default_cert_path, default_key_path, default_chain_path, \
         default_config_dir, default_reload_command, config_example, notes, expected_cert_format, \
         default_use_sudo, default_staging_dir, is_builtin, is_retired, \
         created_at, updated_at FROM applications \
         WHERE (? OR is_retired = FALSE) ORDER BY name ASC",
    )
    .bind(include_retired)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "items": rows })))
}

async fn create_application(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<UpsertApplicationRequest>,
) -> AppResult<Json<ApplicationRecord>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let now = Utc::now().naive_utc();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO applications (id, slug, name, default_cert_path, default_key_path, \
         default_chain_path, default_config_dir, default_reload_command, config_example, notes, \
         expected_cert_format, default_use_sudo, default_staging_dir, is_builtin, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.slug)
    .bind(&payload.name)
    .bind(&payload.default_cert_path)
    .bind(&payload.default_key_path)
    .bind(&payload.default_chain_path)
    .bind(&payload.default_config_dir)
    .bind(&payload.default_reload_command)
    .bind(&payload.config_example)
    .bind(&payload.notes)
    .bind(&payload.expected_cert_format)
    .bind(payload.default_use_sudo.unwrap_or(false))
    .bind(&payload.default_staging_dir)
    .bind(now)
    .bind(now)
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "application.create",
        "application",
        &id,
        json!({"slug": payload.slug}),
    )
    .await?;
    fetch_application(&state, &id).await
}

async fn update_application(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<UpsertApplicationRequest>,
) -> AppResult<Json<ApplicationRecord>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let affected = sqlx::query(
        "UPDATE applications SET slug = ?, name = ?, default_cert_path = ?, default_key_path = ?, \
         default_chain_path = ?, default_config_dir = ?, default_reload_command = ?, \
         config_example = ?, notes = ?, expected_cert_format = ?, default_use_sudo = ?, \
         default_staging_dir = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&payload.slug)
    .bind(&payload.name)
    .bind(&payload.default_cert_path)
    .bind(&payload.default_key_path)
    .bind(&payload.default_chain_path)
    .bind(&payload.default_config_dir)
    .bind(&payload.default_reload_command)
    .bind(&payload.config_example)
    .bind(&payload.notes)
    .bind(&payload.expected_cert_format)
    .bind(payload.default_use_sudo.unwrap_or(false))
    .bind(&payload.default_staging_dir)
    .bind(Utc::now().naive_utc())
    .bind(&id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        &state,
        &auth_user.username,
        "application.update",
        "application",
        &id,
        json!({}),
    )
    .await?;
    fetch_application(&state, &id).await
}

async fn delete_application(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let builtin: Option<(bool,)> =
        sqlx::query_as("SELECT is_builtin FROM applications WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.pool)
            .await?;
    let is_builtin = match builtin {
        None => return Err(AppError::NotFound),
        Some((v,)) => v,
    };

    // Une application encore rattachée à un hôte ne part pas : la cible de
    // déploiement perdrait ses chemins par défaut sans que rien ne le dise.
    let in_use: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM host_applications WHERE application_id = ?")
            .bind(&id)
            .fetch_one(&state.pool)
            .await?;
    if in_use.0 > 0 {
        return Err(AppError::Validation(
            "application is linked to one or more hosts".to_string(),
        ));
    }

    // Un built-in ne peut pas être supprimé pour de bon : `seed_applications`
    // le réinsère à chaque démarrage, et l'opérateur verrait sa suppression
    // annulée par le premier redéploiement. On le retire du catalogue en
    // gardant la ligne, ce qui neutralise l'INSERT IGNORE du semis. Une
    // application créée à la main, elle, disparaît vraiment.
    if is_builtin {
        sqlx::query("UPDATE applications SET is_retired = TRUE, updated_at = ? WHERE id = ?")
            .bind(Utc::now().naive_utc())
            .bind(&id)
            .execute(&state.pool)
            .await?;
    } else {
        sqlx::query("DELETE FROM applications WHERE id = ?")
            .bind(&id)
            .execute(&state.pool)
            .await?;
    }
    audit(
        &state,
        &auth_user.username,
        "application.delete",
        "application",
        &id,
        json!({"builtin": is_builtin}),
    )
    .await?;
    Ok(Json(json!({
        "status": if is_builtin { "retired" } else { "deleted" }
    })))
}

/// Duplique une application du catalogue.
///
/// C'est le seul moyen d'adapter un built-in : ses chemins et sa commande de
/// rechargement sont réinscrits à chaque démarrage par `seed_applications`, si
/// bien qu'une modification directe finirait par être écrasée. La copie naît
/// non-built-in, donc modifiable et supprimable pour de bon.
///
/// ENTRÉE : l'identifiant de l'application à copier.
/// SORTIE : la nouvelle application. Son slug est celui de l'original suffixé
/// de `-copy`, puis `-copy-2`, `-copy-3`… jusqu'au premier libre — le slug est
/// UNIQUE en base, et rendre une erreur de contrainte à l'exploitant pour lui
/// faire retaper un nom serait de la paresse.
async fn duplicate_application(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<ApplicationRecord>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let source = sqlx::query_as::<_, ApplicationRecord>(
        "SELECT id, slug, name, default_cert_path, default_key_path, default_chain_path, \
         default_config_dir, default_reload_command, config_example, notes, expected_cert_format, \
         default_use_sudo, default_staging_dir, is_builtin, is_retired, \
         created_at, updated_at FROM applications WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let taken: Vec<(String,)> = sqlx::query_as("SELECT slug FROM applications")
        .fetch_all(&state.pool)
        .await?;
    let taken: std::collections::HashSet<String> = taken.into_iter().map(|(s,)| s).collect();
    let slug = next_free_slug(&source.slug, &taken);

    let now = Utc::now().naive_utc();
    let new_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO applications (id, slug, name, default_cert_path, default_key_path, \
         default_chain_path, default_config_dir, default_reload_command, config_example, notes, \
         expected_cert_format, default_use_sudo, default_staging_dir, is_builtin, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, ?, ?)",
    )
    .bind(&new_id)
    .bind(&slug)
    .bind(format!("{} (copy)", source.name))
    .bind(&source.default_cert_path)
    .bind(&source.default_key_path)
    .bind(&source.default_chain_path)
    .bind(&source.default_config_dir)
    .bind(&source.default_reload_command)
    .bind(&source.config_example)
    .bind(&source.notes)
    .bind(&source.expected_cert_format)
    .bind(source.default_use_sudo)
    .bind(&source.default_staging_dir)
    .bind(now)
    .bind(now)
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "application.duplicate",
        "application",
        &new_id,
        json!({"source_id": id, "slug": slug}),
    )
    .await?;
    fetch_application(&state, &new_id).await
}

/// Premier slug libre dérivé de `base` : `base-copy`, puis `base-copy-2`, etc.
///
/// Le slug est limité à 64 caractères en base ; un nom déjà long est tronqué
/// avant d'être suffixé, sinon l'insertion échouerait sur une contrainte de
/// longueur au lieu de rendre un nom utilisable.
fn next_free_slug(base: &str, taken: &std::collections::HashSet<String>) -> String {
    const MAX: usize = 64;
    let mut n = 1usize;
    loop {
        let suffix = if n == 1 {
            "-copy".to_string()
        } else {
            format!("-copy-{n}")
        };
        let room = MAX.saturating_sub(suffix.len());
        let stem: String = base.chars().take(room).collect();
        let candidate = format!("{stem}{suffix}");
        if !taken.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

async fn fetch_application(state: &AppState, id: &str) -> AppResult<Json<ApplicationRecord>> {
    let row = sqlx::query_as::<_, ApplicationRecord>(
        "SELECT id, slug, name, default_cert_path, default_key_path, default_chain_path, \
         default_config_dir, default_reload_command, config_example, notes, expected_cert_format, \
         default_use_sudo, default_staging_dir, is_builtin, is_retired, \
         created_at, updated_at FROM applications WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(row))
}

// ---- Credentials (used to connect to hosts) ----

async fn list_credentials(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let rows = sqlx::query_as::<_, CredentialRow>(
        "SELECT id, name, kind, username, secret_enc, ssh_private_key_enc, ssh_passphrase_enc, \
         notes, created_by, created_at, updated_at FROM credentials ORDER BY name ASC",
    )
    .fetch_all(&state.pool)
    .await?;
    let items: Vec<CredentialSummary> = rows.into_iter().map(CredentialSummary::from).collect();
    Ok(Json(json!({ "items": items })))
}

async fn create_credential(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateCredentialRequest>,
) -> AppResult<Json<CredentialSummary>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let secret_enc = encrypt_optional(&state, payload.secret.as_deref())?;
    // Reuse an existing Akamana SSH key (passwordless) when requested; otherwise take the pasted key.
    // Both this table and ssh_keys encrypt with the same KEK, so the ciphertext can be copied directly.
    let (key_enc, pass_enc) = if let Some(ssh_key_id) = payload.ssh_key_id.as_deref() {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT private_key_enc FROM ssh_keys WHERE id = ? AND is_revoked = false",
        )
        .bind(ssh_key_id)
        .fetch_optional(&state.pool)
        .await?;
        let (enc,) = row.ok_or_else(|| {
            AppError::Validation("selected SSH key not found or revoked".to_string())
        })?;
        (Some(enc), None)
    } else {
        (
            encrypt_optional(&state, payload.ssh_private_key.as_deref())?,
            encrypt_optional(&state, payload.ssh_passphrase.as_deref())?,
        )
    };
    let now = Utc::now().naive_utc();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO credentials (id, name, kind, username, secret_enc, ssh_private_key_enc, \
         ssh_passphrase_enc, notes, created_by, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.name)
    .bind(&payload.kind)
    .bind(&payload.username)
    .bind(&secret_enc)
    .bind(&key_enc)
    .bind(&pass_enc)
    .bind(&payload.notes)
    .bind(&auth_user.username)
    .bind(now)
    .bind(now)
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "credential.create",
        "credential",
        &id,
        json!({"name": payload.name, "kind": payload.kind}),
    )
    .await?;
    fetch_credential(&state, &id).await
}

async fn update_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<UpdateCredentialRequest>,
) -> AppResult<Json<CredentialSummary>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let existing = sqlx::query_as::<_, CredentialRow>(
        "SELECT id, name, kind, username, secret_enc, ssh_private_key_enc, ssh_passphrase_enc, \
         notes, created_by, created_at, updated_at FROM credentials WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let name = payload.name.unwrap_or(existing.name);
    let username = payload.username.or(existing.username);
    let notes = payload.notes.or(existing.notes);
    let secret_enc = match payload.secret.as_deref() {
        Some(s) => encrypt_optional(&state, Some(s))?,
        None => existing.secret_enc,
    };
    let key_enc = match payload.ssh_private_key.as_deref() {
        Some(s) => encrypt_optional(&state, Some(s))?,
        None => existing.ssh_private_key_enc,
    };
    let pass_enc = match payload.ssh_passphrase.as_deref() {
        Some(s) => encrypt_optional(&state, Some(s))?,
        None => existing.ssh_passphrase_enc,
    };
    sqlx::query(
        "UPDATE credentials SET name = ?, username = ?, secret_enc = ?, ssh_private_key_enc = ?, \
         ssh_passphrase_enc = ?, notes = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&name)
    .bind(&username)
    .bind(&secret_enc)
    .bind(&key_enc)
    .bind(&pass_enc)
    .bind(&notes)
    .bind(Utc::now().naive_utc())
    .bind(&id)
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "credential.update",
        "credential",
        &id,
        json!({}),
    )
    .await?;
    fetch_credential(&state, &id).await
}

async fn delete_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let in_use: (i64,) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM host_credentials WHERE credential_id = ?) + \
         (SELECT COUNT(*) FROM host_applications WHERE credential_id = ?)",
    )
    .bind(&id)
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;
    if in_use.0 > 0 {
        return Err(AppError::Validation(
            "credential is in use by a host or deployment target".to_string(),
        ));
    }
    let affected = sqlx::query("DELETE FROM credentials WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        &state,
        &auth_user.username,
        "credential.delete",
        "credential",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "status": "deleted" })))
}

async fn fetch_credential(state: &AppState, id: &str) -> AppResult<Json<CredentialSummary>> {
    let row = sqlx::query_as::<_, CredentialRow>(
        "SELECT id, name, kind, username, secret_enc, ssh_private_key_enc, ssh_passphrase_enc, \
         notes, created_by, created_at, updated_at FROM credentials WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(CredentialSummary::from(row)))
}

fn encrypt_optional(state: &AppState, value: Option<&str>) -> AppResult<Option<String>> {
    match value {
        Some(v) if !v.is_empty() => Ok(Some(encrypt_secret(&state.cfg, v)?)),
        _ => Ok(None),
    }
}

// ---- Host <-> Credential links ----

async fn list_host_credentials(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let machine_filter = params.get("machine_id").cloned();
    let rows = sqlx::query_as::<_, HostCredentialRecord>(
        "SELECT hc.id, hc.machine_id, m.hostname, hc.credential_id, c.name AS credential_name, \
         hc.protocol, hc.port, hc.is_default, hc.last_check_status, hc.last_check_at, \
         hc.last_check_message, hc.created_at \
         FROM host_credentials hc \
         JOIN machines m ON m.id = hc.machine_id \
         JOIN credentials c ON c.id = hc.credential_id \
         WHERE (? IS NULL OR hc.machine_id = ?) \
         ORDER BY m.hostname ASC, hc.protocol ASC",
    )
    .bind(&machine_filter)
    .bind(&machine_filter)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "items": rows })))
}

async fn create_host_credential(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateHostCredentialRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let protocol = payload
        .protocol
        .clone()
        .unwrap_or_else(|| "ssh".to_string());
    let is_default = payload.is_default.unwrap_or(false);
    if is_default {
        sqlx::query(
            "UPDATE host_credentials SET is_default = FALSE WHERE machine_id = ? AND protocol = ?",
        )
        .bind(&payload.machine_id)
        .bind(&protocol)
        .execute(&state.pool)
        .await?;
    }
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO host_credentials (id, machine_id, credential_id, protocol, port, is_default, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.machine_id)
    .bind(&payload.credential_id)
    .bind(&protocol)
    .bind(payload.port)
    .bind(is_default)
    .bind(Utc::now().naive_utc())
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "host_credential.create",
        "host_credential",
        &id,
        json!({"machine_id": payload.machine_id}),
    )
    .await?;
    Ok(Json(json!({ "id": id, "status": "created" })))
}

async fn delete_host_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let affected = sqlx::query("DELETE FROM host_credentials WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        &state,
        &auth_user.username,
        "host_credential.delete",
        "host_credential",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "status": "deleted" })))
}

// ---- Host <-> Application links (deployment targets) ----

async fn list_host_applications(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let machine_filter = params.get("machine_id").cloned();
    let rows = sqlx::query_as::<_, HostApplicationRecord>(
        "SELECT ha.id, ha.machine_id, m.hostname, ha.application_id, a.name AS application_name, \
         ha.tls_key_id, ha.cert_path, ha.key_path, ha.chain_path, ha.reload_command, \
         ha.credential_id, ha.use_sudo, ha.staging_dir, \
         ha.auto_deploy, ha.last_deploy_status, ha.last_deploy_at, \
         ha.created_at, ha.updated_at \
         FROM host_applications ha \
         JOIN machines m ON m.id = ha.machine_id \
         JOIN applications a ON a.id = ha.application_id \
         WHERE (? IS NULL OR ha.machine_id = ?) \
         ORDER BY m.hostname ASC, a.name ASC",
    )
    .bind(&machine_filter)
    .bind(&machine_filter)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "items": rows })))
}

async fn create_host_application(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateHostApplicationRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let now = Utc::now().naive_utc();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO host_applications (id, machine_id, application_id, tls_key_id, cert_path, \
         key_path, chain_path, reload_command, credential_id, use_sudo, staging_dir, auto_deploy, \
         created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.machine_id)
    .bind(&payload.application_id)
    .bind(&payload.tls_key_id)
    .bind(&payload.cert_path)
    .bind(&payload.key_path)
    .bind(&payload.chain_path)
    .bind(&payload.reload_command)
    .bind(&payload.credential_id)
    .bind(payload.use_sudo)
    .bind(&payload.staging_dir)
    .bind(payload.auto_deploy.unwrap_or(false))
    .bind(now)
    .bind(now)
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "host_application.create",
        "host_application",
        &id,
        json!({"machine_id": payload.machine_id, "application_id": payload.application_id}),
    )
    .await?;
    Ok(Json(json!({ "id": id, "status": "created" })))
}

async fn update_host_application(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<UpdateHostApplicationRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let existing = sqlx::query_as::<_, HostApplicationRecord>(
        "SELECT ha.id, ha.machine_id, m.hostname, ha.application_id, a.name AS application_name, \
         ha.tls_key_id, ha.cert_path, ha.key_path, ha.chain_path, ha.reload_command, \
         ha.credential_id, ha.use_sudo, ha.staging_dir, \
         ha.auto_deploy, ha.last_deploy_status, ha.last_deploy_at, \
         ha.created_at, ha.updated_at \
         FROM host_applications ha \
         JOIN machines m ON m.id = ha.machine_id \
         JOIN applications a ON a.id = ha.application_id WHERE ha.id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    // PATCH semantics, spelled out because the two "empty" cases mean opposite
    // things: a field the caller did not send is left alone, while a field sent
    // blank is an explicit request to clear it. Without the second case an
    // operator can never undo a path — they blank the box, save, and the old
    // value silently returns.
    fn patch_field(sent: Option<String>, existing: Option<String>) -> Option<String> {
        match sent {
            Some(v) if v.trim().is_empty() => None,
            Some(v) => Some(v),
            None => existing,
        }
    }

    let tls_key_id = patch_field(payload.tls_key_id, existing.tls_key_id);
    let cert_path = patch_field(payload.cert_path, existing.cert_path);
    let key_path = patch_field(payload.key_path, existing.key_path);
    let chain_path = patch_field(payload.chain_path, existing.chain_path);
    let reload_command = patch_field(payload.reload_command, existing.reload_command);
    let credential_id = patch_field(payload.credential_id, existing.credential_id);
    let staging_dir = patch_field(payload.staging_dir, existing.staging_dir);
    // Même distinction que patch_field, mais sur un tri-état : le champ absent
    // laisse la valeur en place, `null` la remet en héritage de l'application.
    let use_sudo = payload.use_sudo.unwrap_or(existing.use_sudo);
    let auto_deploy = payload.auto_deploy.unwrap_or(existing.auto_deploy);

    sqlx::query(
        "UPDATE host_applications SET tls_key_id = ?, cert_path = ?, key_path = ?, chain_path = ?, \
         reload_command = ?, credential_id = ?, use_sudo = ?, staging_dir = ?, auto_deploy = ?, \
         updated_at = ? WHERE id = ?",
    )
    .bind(&tls_key_id)
    .bind(&cert_path)
    .bind(&key_path)
    .bind(&chain_path)
    .bind(&reload_command)
    .bind(&credential_id)
    .bind(use_sudo)
    .bind(&staging_dir)
    .bind(auto_deploy)
    .bind(Utc::now().naive_utc())
    .bind(&id)
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "host_application.update",
        "host_application",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "id": id, "status": "updated" })))
}

async fn delete_host_application(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    // A target that has ever been checked or deployed owns rows in
    // deployment_jobs, which in turn own deployment_journal rows. Both foreign
    // keys are RESTRICT, so deleting the target alone fails as soon as it has
    // been used once — which is every target worth removing. The history of a
    // target that no longer exists has nowhere to live, so it goes with it, in
    // one transaction so a half-deleted target cannot survive a failure.
    let mut tx = state.pool.begin().await?;

    let journal_removed = sqlx::query(
        "DELETE j FROM deployment_journal j \
         JOIN deployment_jobs d ON d.id = j.job_id \
         WHERE d.host_application_id = ?",
    )
    .bind(&id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    let jobs_removed = sqlx::query("DELETE FROM deployment_jobs WHERE host_application_id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    let affected = sqlx::query("DELETE FROM host_applications WHERE id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if affected == 0 {
        tx.rollback().await?;
        return Err(AppError::NotFound);
    }
    tx.commit().await?;

    // The counts belong in the audit trail: this is the only remaining trace
    // that those deployments ever happened.
    audit(
        &state,
        &auth_user.username,
        "host_application.delete",
        "host_application",
        &id,
        json!({"deployment_jobs_removed": jobs_removed, "journal_entries_removed": journal_removed}),
    )
    .await?;
    Ok(Json(json!({
        "status": "deleted",
        "deployment_jobs_removed": jobs_removed,
        "journal_entries_removed": journal_removed,
    })))
}

#[derive(sqlx::FromRow)]
struct MachineFullRow {
    hostname: String,
    ip_address: String,
    owner: String,
    environment: String,
    alert_email: Option<String>,
    test_url: Option<String>,
    os_type: Option<String>,
    monitor_only: bool,
}

async fn update_machine(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<UpdateMachineRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let existing = sqlx::query_as::<_, MachineFullRow>(
        "SELECT hostname, ip_address, owner, environment, alert_email, test_url, os_type, monitor_only FROM machines WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;
    let hostname = payload.hostname.unwrap_or(existing.hostname);
    let ip_address = payload.ip_address.unwrap_or(existing.ip_address);
    let owner = payload.owner.unwrap_or(existing.owner);
    let environment = payload.environment.unwrap_or(existing.environment);
    let alert_email = payload.alert_email.or(existing.alert_email);
    let test_url = payload.test_url.or(existing.test_url);
    let os_type = payload.os_type.or(existing.os_type);
    let monitor_only = payload.monitor_only.unwrap_or(existing.monitor_only);
    sqlx::query(
        "UPDATE machines SET hostname = ?, ip_address = ?, owner = ?, environment = ?, alert_email = ?, test_url = ?, os_type = ?, monitor_only = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&hostname)
    .bind(&ip_address)
    .bind(&owner)
    .bind(&environment)
    .bind(&alert_email)
    .bind(&test_url)
    .bind(&os_type)
    .bind(monitor_only)
    .bind(Utc::now().naive_utc())
    .bind(&id)
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "machine.update",
        "machine",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "status": "updated" })))
}

async fn delete_machine(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let deps: (i64,) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM machine_monitor_ports WHERE machine_id = ?) \
         + (SELECT COUNT(*) FROM host_applications WHERE machine_id = ?) \
         + (SELECT COUNT(*) FROM host_credentials WHERE machine_id = ?) \
         + (SELECT COUNT(*) FROM certbot_configs WHERE machine_id = ?) \
         + (SELECT COUNT(*) FROM tls_keys WHERE machine_id = ?) \
         + (SELECT COUNT(*) FROM ssh_keys WHERE machine_id = ?)",
    )
    .bind(&id)
    .bind(&id)
    .bind(&id)
    .bind(&id)
    .bind(&id)
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;
    if deps.0 > 0 {
        return Err(AppError::Validation(
            "host still has linked certificates, monitored ports, credentials, applications, or certbot configs — remove those first".to_string(),
        ));
    }
    let affected = sqlx::query("DELETE FROM machines WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        &state,
        &auth_user.username,
        "machine.delete",
        "machine",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "status": "deleted" })))
}

async fn set_tls_auto_renew(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<SetAutoRenewRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let days = payload.renew_days_before.unwrap_or(30) as i32;
    let affected = sqlx::query(
        "UPDATE tls_keys SET auto_renew = ?, renew_days_before = ? WHERE id = ? AND cert_level = 'leaf'",
    )
    .bind(payload.auto_renew)
    .bind(days)
    .bind(&id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        &state,
        &auth_user.username,
        "tls.auto_renew",
        "tls_key",
        &id,
        json!({"auto_renew": payload.auto_renew, "renew_days_before": days}),
    )
    .await?;
    Ok(Json(
        json!({ "status": "updated", "auto_renew": payload.auto_renew, "renew_days_before": days }),
    ))
}

async fn deploy_host_application(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let result =
        crate::deploy::run_deployment(&state, &id, "manual", &auth_user.username, false).await?;
    audit(
        &state,
        &auth_user.username,
        "host_application.deploy",
        "host_application",
        &id,
        json!({"status": result.status, "job_id": result.job_id}),
    )
    .await?;
    Ok(Json(
        json!({ "job_id": result.job_id, "status": result.status }),
    ))
}

async fn check_host_application(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let result =
        crate::deploy::run_deployment(&state, &id, "manual", &auth_user.username, true).await?;
    Ok(Json(
        json!({ "job_id": result.job_id, "status": result.status }),
    ))
}

#[derive(sqlx::FromRow, Serialize)]
struct DeploymentJobRow {
    id: String,
    host_application_id: Option<String>,
    tls_key_id: Option<String>,
    trigger_source: String,
    status: String,
    job_type: String,
    started_at: Option<chrono::NaiveDateTime>,
    finished_at: Option<chrono::NaiveDateTime>,
    created_by: String,
    created_at: chrono::NaiveDateTime,
}

#[derive(sqlx::FromRow, Serialize)]
struct DeploymentJournalRow {
    id: String,
    job_id: String,
    step: String,
    status: String,
    message: Option<String>,
    created_at: chrono::NaiveDateTime,
}

async fn list_host_application_deployments(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let rows = sqlx::query_as::<_, DeploymentJobRow>(
        "SELECT id, host_application_id, tls_key_id, trigger_source, status, job_type, \
         started_at, finished_at, created_by, created_at FROM deployment_jobs \
         WHERE host_application_id = ? ORDER BY created_at DESC LIMIT 50",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "items": rows })))
}

async fn get_deployment_journal(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let job = sqlx::query_as::<_, DeploymentJobRow>(
        "SELECT id, host_application_id, tls_key_id, trigger_source, status, job_type, \
         started_at, finished_at, created_by, created_at FROM deployment_jobs WHERE id = ?",
    )
    .bind(&job_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;
    let steps = sqlx::query_as::<_, DeploymentJournalRow>(
        "SELECT id, job_id, step, status, message, created_at FROM deployment_journal \
         WHERE job_id = ? ORDER BY created_at ASC",
    )
    .bind(&job_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "job": job, "steps": steps })))
}

// ---- Network discovery scan ----

fn is_private_v4(a: u8, b: u8) -> bool {
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
}

fn server_default_network() -> Option<(u8, u8, u8)> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // Connecting a UDP socket just selects the outbound interface; no packets are sent.
    sock.connect("10.255.255.255:9").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            Some((o[0], o[1], o[2]))
        }
        _ => None,
    }
}

async fn scan_network(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<NetworkScanRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let port = payload.port.unwrap_or(443).clamp(1, 65535) as u16;

    let (a, b, c) = match payload
        .cidr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(cidr) => {
            let ip_part = cidr.split('/').next().unwrap_or(cidr).trim();
            let octs: Vec<&str> = ip_part.split('.').collect();
            if octs.len() < 3 {
                return Err(AppError::Validation(
                    "invalid network; use a form like 192.168.1.0/24".to_string(),
                ));
            }
            let parse = |s: &str| -> Result<u8, AppError> {
                s.parse::<u8>()
                    .map_err(|_| AppError::Validation("invalid network octet".to_string()))
            };
            (parse(octs[0])?, parse(octs[1])?, parse(octs[2])?)
        }
        None => server_default_network().ok_or_else(|| {
            AppError::Internal("could not determine the server's network".to_string())
        })?,
    };

    if !is_private_v4(a, b) {
        return Err(AppError::Validation(
            "only private networks may be scanned (10.x, 172.16-31.x, 192.168.x)".to_string(),
        ));
    }

    let mut handles = Vec::with_capacity(254);
    for h in 1..=254u8 {
        let ip = std::net::Ipv4Addr::new(a, b, c, h);
        handles.push(tokio::spawn(async move {
            let addr = std::net::SocketAddr::from((ip, port));
            match tokio::time::timeout(
                std::time::Duration::from_millis(800),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            {
                Ok(Ok(_)) => Some(ip),
                _ => None,
            }
        }));
    }

    let mut alive: Vec<std::net::Ipv4Addr> = Vec::new();
    for handle in handles {
        if let Ok(Some(ip)) = handle.await {
            alive.push(ip);
        }
    }
    alive.sort();

    let known: Vec<(String,)> = sqlx::query_as("SELECT ip_address FROM machines")
        .fetch_all(&state.pool)
        .await?;
    let known: std::collections::HashSet<String> = known.into_iter().map(|r| r.0).collect();

    let mut items = Vec::new();
    for ip in alive {
        let ip_str = ip.to_string();
        let hostname = guess_hostname(ip, port).await;
        items.push(json!({
            "ip": ip_str,
            "hostname": hostname,
            "port": port,
            "already_known": known.contains(&ip.to_string()),
        }));
    }

    audit(
        &state,
        &auth_user.username,
        "network.scan",
        "network",
        &format!("{a}.{b}.{c}.0/24"),
        json!({"port": port, "found": items.len()}),
    )
    .await?;
    Ok(Json(json!({
        "network": format!("{a}.{b}.{c}.0/24"),
        "port": port,
        "items": items,
    })))
}

/// Best-effort hostname discovery: reverse DNS, then the TLS certificate's CN/SAN
/// (handy since we probe TLS ports), then a NetBIOS node-status query for Windows hosts.
async fn guess_hostname(ip: std::net::Ipv4Addr, port: u16) -> Option<String> {
    if let Ok(Some(h)) =
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&std::net::IpAddr::V4(ip)).ok())
            .await
    {
        let h = h.trim().trim_end_matches('.').to_string();
        if !h.is_empty() {
            return Some(h);
        }
    }
    if let Ok(Some(h)) = tokio::task::spawn_blocking(move || tls_cert_hostname(ip, port)).await {
        return Some(h);
    }
    if let Ok(Some(h)) = tokio::task::spawn_blocking(move || netbios_hostname(ip)).await {
        return Some(h);
    }
    None
}

fn tls_cert_hostname(ip: std::net::Ipv4Addr, port: u16) -> Option<String> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let addr = std::net::SocketAddr::from((ip, port));
    let tcp =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(900)).ok()?;
    tcp.set_read_timeout(Some(std::time::Duration::from_millis(900)))
        .ok()?;
    tcp.set_write_timeout(Some(std::time::Duration::from_millis(900)))
        .ok()?;
    let mut builder = SslConnector::builder(SslMethod::tls()).ok()?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let stream = connector.connect(&ip.to_string(), tcp).ok()?;
    let cert = stream.ssl().peer_certificate()?;
    if let Some(entry) = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
        if let Ok(s) = entry.data().as_utf8() {
            let v = s.to_string();
            if !v.is_empty() && !v.contains('*') {
                return Some(v);
            }
        }
    }
    if let Some(sans) = cert.subject_alt_names() {
        for san in sans.iter() {
            if let Some(d) = san.dnsname() {
                if !d.contains('*') {
                    return Some(d.to_string());
                }
            }
        }
    }
    None
}

fn netbios_hostname(ip: std::net::Ipv4Addr) -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(std::time::Duration::from_millis(700)))
        .ok()?;
    // NBSTAT (node status) query for the wildcard name "*".
    let mut req: Vec<u8> = vec![
        0xA2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
    ];
    req.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    req.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]);
    sock.send_to(&req, (ip, 137u16)).ok()?;

    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    // header(12) + echoed name(34) + type(2) + class(2) + ttl(4) + rdlength(2) = 56, then name count.
    if n < 57 {
        return None;
    }
    let count = buf[56] as usize;
    let mut offset = 57;
    for _ in 0..count {
        if offset + 18 > n {
            break;
        }
        let name_bytes = &buf[offset..offset + 15];
        let suffix = buf[offset + 15];
        let flags = u16::from_be_bytes([buf[offset + 16], buf[offset + 17]]);
        let is_group = flags & 0x8000 != 0;
        if suffix == 0x00 && !is_group {
            let name = String::from_utf8_lossy(name_bytes)
                .trim()
                .trim_matches('\u{0}')
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
        offset += 18;
    }
    None
}

// ---- Backup / restore ----

async fn backup_export(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<(axum::http::HeaderMap, Vec<u8>)> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let dump = crate::backup::export_dump(&state, false).await?;
    audit(
        &state,
        &auth_user.username,
        "backup.export",
        "database",
        "-",
        json!({"bytes": dump.len()}),
    )
    .await?;
    let filename = format!("akamana-{}.sql", Utc::now().format("%Y%m%d%H%M%S"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/sql"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|e| AppError::Internal(format!("content disposition error: {e}")))?,
    );
    Ok((headers, dump))
}

async fn backup_import(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> AppResult<Json<serde_json::Value>> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    if body.is_empty() {
        return Err(AppError::Validation("empty backup file".to_string()));
    }
    // Encrypted (.ezbak) uploads may carry a passphrase via header for
    // off-instance restores; otherwise the configured passphrase is used.
    let passphrase = headers
        .get("x-backup-passphrase")
        .and_then(|v| v.to_str().ok());
    crate::backup::restore_backup(&state, &body, passphrase, None, None).await?;
    audit(
        &state,
        &auth_user.username,
        "backup.import",
        "database",
        "-",
        json!({"bytes": body.len(), "encrypted": crate::backup_crypto::is_encrypted(&body)}),
    )
    .await?;
    Ok(Json(json!({ "status": "restored", "bytes": body.len() })))
}

async fn backup_run(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let skip = read_setting_value(&state, "backup_skip_unchanged")
        .await
        .map(|v| v == "true")
        .unwrap_or(true);
    let retention = read_setting_value(&state, "backup_retention")
        .await
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(5);
    let result = crate::backup::run_backup(&state, skip, retention).await?;
    audit(
        &state,
        &auth_user.username,
        "backup.run",
        "database",
        "-",
        json!({"created": result.file, "remote": result.remote}),
    )
    .await?;
    Ok(Json(json!({
        "status": "ok",
        "created": result.file,
        "skipped": result.file.is_none(),
        "remote": result.remote,
        "remote_error": result.remote_error,
    })))
}

async fn backup_list(
    State(_state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    Ok(Json(json!({ "items": crate::backup::list_backups() })))
}

async fn read_setting_value(state: &AppState, key: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>("SELECT value_text FROM settings WHERE key_name = ?")
        .bind(key)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .map(|r| r.0)
}

async fn get_backup_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let encryption_mode = read_setting_value(&state, "backup_encryption_mode")
        .await
        .unwrap_or_else(|| "none".to_string());
    let has_passphrase = read_setting_value(&state, "backup_passphrase_enc")
        .await
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    Ok(Json(json!({
        "enabled": read_setting_value(&state, "backup_enabled").await.map(|v| v == "true").unwrap_or(false),
        "frequency_hours": read_setting_value(&state, "backup_frequency_hours").await.and_then(|v| v.parse::<i64>().ok()).unwrap_or(24),
        "retention": read_setting_value(&state, "backup_retention").await.and_then(|v| v.parse::<i64>().ok()).unwrap_or(5),
        "skip_unchanged": read_setting_value(&state, "backup_skip_unchanged").await.map(|v| v == "true").unwrap_or(true),
        "encryption_mode": encryption_mode,
        "has_passphrase": has_passphrase,
    })))
}

async fn save_backup_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<BackupSettingsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let now = Utc::now().naive_utc();
    let encryption_mode = match payload.encryption_mode.as_deref() {
        Some("passphrase") => "passphrase",
        Some("envelope") => "envelope",
        _ => "none",
    };
    let mut kv: Vec<(&str, String)> = vec![
        ("backup_enabled", payload.enabled.to_string()),
        (
            "backup_frequency_hours",
            payload.frequency_hours.to_string(),
        ),
        ("backup_retention", payload.retention.to_string()),
        ("backup_skip_unchanged", payload.skip_unchanged.to_string()),
        ("backup_encryption_mode", encryption_mode.to_string()),
    ];
    // Store the passphrase (KEK-encrypted) only when a new one is supplied.
    if let Some(pass) = payload.passphrase.as_ref().filter(|p| !p.trim().is_empty()) {
        kv.push(("backup_passphrase_enc", encrypt_secret(&state.cfg, pass)?));
    }
    // Guard: enabling passphrase mode requires a passphrase to exist.
    if encryption_mode == "passphrase"
        && payload
            .passphrase
            .as_deref()
            .map(|p| p.trim().is_empty())
            .unwrap_or(true)
    {
        let existing = read_setting_value(&state, "backup_passphrase_enc")
            .await
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        if !existing {
            return Err(AppError::Validation(
                "set a backup passphrase before enabling passphrase encryption".to_string(),
            ));
        }
    }
    for (k, v) in kv {
        sqlx::query(
            "INSERT INTO settings (key_name, value_text, updated_by, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE value_text = VALUES(value_text), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)",
        )
        .bind(k)
        .bind(v)
        .bind(&auth_user.username)
        .bind(now)
        .execute(&state.pool)
        .await?;
    }
    audit(
        &state,
        &auth_user.username,
        "backup.settings",
        "settings",
        "backup",
        json!({"encryption_mode": encryption_mode}),
    )
    .await?;
    Ok(Json(json!({ "status": "saved" })))
}

/// Reads the remote-destination settings for a `prefix` as JSON (no secrets).
async fn remote_settings_json(state: &AppState, prefix: &str) -> serde_json::Value {
    let k = |s: &str| format!("{prefix}_{s}");
    let has = |v: Option<String>| v.map(|s| !s.is_empty()).unwrap_or(false);
    json!({
        "dest_type": read_setting_value(state, &k("dest_type")).await.unwrap_or_else(|| "local".to_string()),
        "remote_path": read_setting_value(state, &k("remote_path")).await.unwrap_or_default(),
        "remote_retention": read_setting_value(state, &k("remote_retention")).await.and_then(|v| v.parse::<i64>().ok()).unwrap_or(7),
        "sftp_host": read_setting_value(state, &k("sftp_host")).await.unwrap_or_default(),
        "sftp_port": read_setting_value(state, &k("sftp_port")).await.and_then(|v| v.parse::<i64>().ok()).unwrap_or(22),
        "sftp_user": read_setting_value(state, &k("sftp_user")).await.unwrap_or_default(),
        "sftp_auth": read_setting_value(state, &k("sftp_auth")).await.unwrap_or_else(|| "password".to_string()),
        "sftp_remote_dir": read_setting_value(state, &k("sftp_remote_dir")).await.unwrap_or_default(),
        "has_sftp_password": has(read_setting_value(state, &k("sftp_password_enc")).await),
        "has_sftp_key": has(read_setting_value(state, &k("sftp_private_key_enc")).await),
    })
}

/// Persists remote-destination settings for a `prefix` (secrets KEK-encrypted,
/// only when newly supplied).
async fn save_remote_settings(
    state: &AppState,
    prefix: &str,
    username: &str,
    payload: &BackupRemoteSettingsRequest,
) -> AppResult<()> {
    let dest_type = match payload.dest_type.as_str() {
        "path" | "sftp" => payload.dest_type.as_str(),
        _ => "local",
    };
    let now = Utc::now().naive_utc();
    let k = |s: &str| format!("{prefix}_{s}");
    let mut kv: Vec<(String, String)> = vec![
        (k("dest_type"), dest_type.to_string()),
        (
            k("remote_path"),
            payload.remote_path.clone().unwrap_or_default(),
        ),
        (
            k("remote_retention"),
            payload.remote_retention.unwrap_or(7).to_string(),
        ),
        (
            k("sftp_host"),
            payload.sftp_host.clone().unwrap_or_default(),
        ),
        (k("sftp_port"), payload.sftp_port.unwrap_or(22).to_string()),
        (
            k("sftp_user"),
            payload.sftp_user.clone().unwrap_or_default(),
        ),
        (
            k("sftp_auth"),
            match payload.sftp_auth.as_deref() {
                Some("key") => "key".to_string(),
                _ => "password".to_string(),
            },
        ),
        (
            k("sftp_remote_dir"),
            payload.sftp_remote_dir.clone().unwrap_or_default(),
        ),
    ];
    if let Some(v) = payload
        .sftp_password
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        kv.push((k("sftp_password_enc"), encrypt_secret(&state.cfg, v)?));
    }
    if let Some(v) = payload
        .sftp_private_key
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        kv.push((k("sftp_private_key_enc"), encrypt_secret(&state.cfg, v)?));
    }
    if let Some(v) = payload
        .sftp_passphrase
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        kv.push((k("sftp_passphrase_enc"), encrypt_secret(&state.cfg, v)?));
    }
    for (key, v) in kv {
        sqlx::query(
            "INSERT INTO settings (key_name, value_text, updated_by, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE value_text = VALUES(value_text), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)",
        )
        .bind(&key)
        .bind(v)
        .bind(username)
        .bind(now)
        .execute(&state.pool)
        .await?;
    }
    Ok(())
}

async fn get_backup_remote_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    Ok(Json(remote_settings_json(&state, "backup").await))
}

async fn save_backup_remote_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<BackupRemoteSettingsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    save_remote_settings(&state, "backup", &auth_user.username, &payload).await?;
    audit(
        &state,
        &auth_user.username,
        "backup.remote.settings",
        "settings",
        "backup",
        json!({"dest_type": payload.dest_type}),
    )
    .await?;
    Ok(Json(json!({ "status": "saved" })))
}

async fn test_backup_remote(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let result = crate::backup_remote::test_remote(&state, "backup").await?;
    Ok(Json(json!({ "status": "ok", "detail": result })))
}

async fn get_crl_remote_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    Ok(Json(remote_settings_json(&state, "crl").await))
}

async fn save_crl_remote_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<BackupRemoteSettingsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    save_remote_settings(&state, "crl", &auth_user.username, &payload).await?;
    audit(
        &state,
        &auth_user.username,
        "crl.remote.settings",
        "settings",
        "crl",
        json!({"dest_type": payload.dest_type}),
    )
    .await?;
    Ok(Json(json!({ "status": "saved" })))
}

async fn test_crl_remote(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let result = crate::backup_remote::test_remote(&state, "crl").await?;
    Ok(Json(json!({ "status": "ok", "detail": result })))
}

/// Regenerates every root CA's CRL and uploads it (`<root_id>.crl`) to the
/// configured CRL remote destination. Also called best-effort after revocation.
async fn publish_crls(state: &AppState) -> AppResult<Vec<String>> {
    let roots: Vec<(i32,)> = sqlx::query_as("SELECT id FROM root_ca ORDER BY id")
        .fetch_all(&state.pool)
        .await?;
    let mut published = Vec::new();
    for (root_id,) in roots {
        let der = crate::crypto::generate_crl_der(&state.pool, &state.cfg, root_id).await?;
        if let Some(loc) =
            crate::backup_remote::push_to_remote(state, "crl", &format!("{root_id}.crl"), &der)
                .await?
        {
            published.push(loc);
        }
    }
    Ok(published)
}

async fn publish_crl_now(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let published = publish_crls(&state).await?;
    audit(
        &state,
        &auth_user.username,
        "crl.publish",
        "crl",
        "-",
        json!({"count": published.len()}),
    )
    .await?;
    Ok(Json(json!({ "status": "ok", "published": published })))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Builds a self-contained HTML page that lets any machine (in a less-restricted
/// zone) download and trust the root CA certificate(s) and find the CRL. The
/// root PEMs are embedded inline so target hosts don't need to reach this server.
async fn generate_deploy_html(state: &AppState) -> AppResult<String> {
    let roots = sqlx::query_as::<_, (i32, String, String)>(
        "SELECT id, common_name, cert_pem FROM root_ca ORDER BY id",
    )
    .fetch_all(&state.pool)
    .await?;
    let crl_base = read_setting_value(state, "crl_base_url")
        .await
        .unwrap_or_default();

    let mut sections = String::new();
    for (id, cn, pem) in &roots {
        let b64 = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
        let file = format!("akamana-root-{id}.crt");
        let crl_line = if crl_base.is_empty() {
            String::new()
        } else {
            let url = format!("{}/crl/{}.crl", crl_base.trim_end_matches('/'), id).to_lowercase();
            format!(
                "<p>Revocation list (CRL): <a href=\"{url}\"><code>{url}</code></a></p>",
                url = html_escape(&url)
            )
        };
        sections.push_str(&format!(
            "<section class=\"ca\">\n<h2>{cn}</h2>\n\
             <p><a class=\"btn\" download=\"{file}\" href=\"data:application/x-pem-file;base64,{b64}\">Download root certificate ({file})</a></p>\n\
             {crl_line}\n\
             <details><summary>How to install (trust) this root certificate</summary>\n\
             <ul>\
             <li><strong>Windows:</strong> double-click the .crt, Install Certificate → Local Machine → Trusted Root Certification Authorities.</li>\
             <li><strong>Linux (Debian/Ubuntu):</strong> copy to <code>/usr/local/share/ca-certificates/</code> (as <code>.crt</code>) then <code>sudo update-ca-certificates</code>.</li>\
             <li><strong>Linux (RHEL/Fedora):</strong> copy to <code>/etc/pki/ca-trust/source/anchors/</code> then <code>sudo update-ca-trust extract</code>.</li>\
             <li><strong>macOS:</strong> import into Keychain Access (System) and set Trust to Always Trust.</li>\
             </ul></details>\n\
             <details><summary>PEM (copy/paste)</summary><pre>{pem}</pre></details>\n\
             </section>\n",
            cn = html_escape(cn),
            file = html_escape(&file),
            b64 = b64,
            crl_line = crl_line,
            pem = html_escape(pem),
        ));
    }
    if roots.is_empty() {
        sections.push_str("<p>No root certificate authority has been created yet.</p>");
    }

    Ok(format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title} — Certificate deployment</title>\n\
         <style>body{{font-family:system-ui,Segoe UI,Helvetica,Arial,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;color:#1f2937;line-height:1.5}}\
         h1{{color:#0b5fb6}} .ca{{border:1px solid #d9deea;border-radius:12px;padding:1rem;margin:1rem 0;background:#fbfcfe}}\
         .btn{{display:inline-block;background:#0b5fb6;color:#fff;padding:.5rem .8rem;border-radius:8px;text-decoration:none}}\
         pre{{white-space:pre-wrap;word-break:break-all;background:#f5f7fb;border:1px solid #dce2ef;border-radius:8px;padding:.6rem;font-size:.8rem}}\
         summary{{cursor:pointer;color:#0b5fb6;font-weight:600;margin:.4rem 0}} code{{background:#eef2f7;padding:0 .25rem;border-radius:4px}}</style>\n\
         </head><body>\n\
         <h1>Certificate deployment</h1>\n\
         <p>Install the root certificate(s) below so this organization's internal HTTPS/SSH services are trusted on your machine. Check the CRL link to confirm a certificate has not been revoked.</p>\n\
         {sections}\n\
         <p style=\"color:#5f6676;font-size:.85rem\">Published by {title}.</p>\n\
         </body></html>\n",
        sections = sections,
        // Follow APP_TITLE like every other visible surface, rather than baking
        // the product name into the published page.
        title = html_escape(&state.cfg.app_title),
    ))
}

async fn preview_deploy_html(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let html = generate_deploy_html(&state).await?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

async fn get_deploy_html_remote_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    Ok(Json(remote_settings_json(&state, "deploy_html").await))
}

async fn save_deploy_html_remote_settings(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<BackupRemoteSettingsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    save_remote_settings(&state, "deploy_html", &auth_user.username, &payload).await?;
    audit(
        &state,
        &auth_user.username,
        "deploy_html.remote.settings",
        "settings",
        "deploy_html",
        json!({"dest_type": payload.dest_type}),
    )
    .await?;
    Ok(Json(json!({ "status": "saved" })))
}

async fn test_deploy_html_remote(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let result = crate::backup_remote::test_remote(&state, "deploy_html").await?;
    Ok(Json(json!({ "status": "ok", "detail": result })))
}

async fn publish_deploy_html(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let html = generate_deploy_html(&state).await?;
    let filename = read_setting_value(&state, "deploy_html_filename")
        .await
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "index.html".to_string());
    let published =
        crate::backup_remote::push_to_remote(&state, "deploy_html", &filename, html.as_bytes())
            .await?;
    audit(
        &state,
        &auth_user.username,
        "deploy_html.publish",
        "deploy_html",
        "-",
        json!({"published": published}),
    )
    .await?;
    match published {
        Some(loc) => Ok(Json(json!({ "status": "ok", "published": loc }))),
        None => Err(AppError::Validation(
            "no deploy-page upload destination is configured".to_string(),
        )),
    }
}

async fn list_backup_recipients(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, chrono::NaiveDateTime)>(
        "SELECT id, name, key_type, fingerprint_sha256, is_active, created_at FROM backup_recipients ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({
        "items": rows.into_iter().map(|r| json!({
            "id": r.0, "name": r.1, "key_type": r.2, "fingerprint_sha256": r.3,
            "is_active": r.4, "created_at": r.5,
        })).collect::<Vec<_>>()
    })))
}

async fn add_backup_recipient(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<AddBackupRecipientRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    // Validate the key and derive a stable fingerprint + normalized PEM.
    let (fingerprint, normalized_pem, key_type) =
        crate::backup_crypto::recipient_from_public_pem(&payload.public_key_pem)?;
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO backup_recipients (id, name, key_type, public_key_pem, fingerprint_sha256, is_active, created_by, created_at) VALUES (?, ?, ?, ?, ?, TRUE, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.name)
    .bind(&key_type)
    .bind(&normalized_pem)
    .bind(&fingerprint)
    .bind(&auth_user.username)
    .bind(Utc::now().naive_utc())
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "backup.recipient.add",
        "backup_recipient",
        &id,
        json!({"name": payload.name, "fingerprint": fingerprint}),
    )
    .await?;
    Ok(Json(
        json!({ "status": "added", "id": id, "fingerprint_sha256": fingerprint }),
    ))
}

async fn delete_backup_recipient(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    sqlx::query("DELETE FROM backup_recipients WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    audit(
        &state,
        &auth_user.username,
        "backup.recipient.delete",
        "backup_recipient",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "status": "deleted" })))
}

async fn backup_restore(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<RestoreBackupRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(payload.data_b64.trim())
        .map_err(|_| AppError::Validation("invalid base64 backup data".to_string()))?;
    if data.is_empty() {
        return Err(AppError::Validation("empty backup file".to_string()));
    }
    crate::backup::restore_backup(
        &state,
        &data,
        payload.passphrase.as_deref(),
        payload.private_key_pem.as_deref(),
        payload.key_passphrase.as_deref(),
    )
    .await?;
    audit(
        &state,
        &auth_user.username,
        "backup.restore",
        "database",
        "-",
        json!({"bytes": data.len(), "encrypted": crate::backup_crypto::is_encrypted(&data)}),
    )
    .await?;
    Ok(Json(json!({ "status": "restored", "bytes": data.len() })))
}

// ---- Certbot (remote Let's Encrypt) ----

async fn list_certbot_configs(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let machine_filter = params.get("machine_id").cloned();
    let rows = sqlx::query_as::<_, CertbotConfigRecord>(
        "SELECT cc.id, cc.machine_id, m.hostname, cc.domains, cc.email, cc.challenge, \
         cc.webroot_path, cc.dns_plugin, cc.extra_args, cc.staging, cc.live_cert_path, \
         cc.last_run_status, cc.last_run_at, cc.last_not_after, cc.auto_renew, cc.renew_days_before, \
         cc.created_at, cc.updated_at \
         FROM certbot_configs cc JOIN machines m ON m.id = cc.machine_id \
         WHERE (? IS NULL OR cc.machine_id = ?) ORDER BY m.hostname ASC",
    )
    .bind(&machine_filter)
    .bind(&machine_filter)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "items": rows })))
}

async fn create_certbot_config(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateCertbotConfigRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let now = Utc::now().naive_utc();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO certbot_configs (id, machine_id, domains, email, challenge, webroot_path, \
         dns_plugin, extra_args, staging, live_cert_path, auto_renew, renew_days_before, \
         created_by, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.machine_id)
    .bind(&payload.domains)
    .bind(&payload.email)
    .bind(&payload.challenge)
    .bind(&payload.webroot_path)
    .bind(&payload.dns_plugin)
    .bind(&payload.extra_args)
    .bind(payload.staging.unwrap_or(false))
    .bind(&payload.live_cert_path)
    .bind(payload.auto_renew.unwrap_or(true))
    .bind(payload.renew_days_before.unwrap_or(30) as i32)
    .bind(&auth_user.username)
    .bind(now)
    .bind(now)
    .execute(&state.pool)
    .await?;
    audit(
        &state,
        &auth_user.username,
        "certbot.create",
        "certbot_config",
        &id,
        json!({"machine_id": payload.machine_id, "domains": payload.domains}),
    )
    .await?;
    Ok(Json(json!({ "id": id, "status": "created" })))
}

async fn delete_certbot_config(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let affected = sqlx::query("DELETE FROM certbot_configs WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        &state,
        &auth_user.username,
        "certbot.delete",
        "certbot_config",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "status": "deleted" })))
}

async fn run_certbot_config(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let result = crate::deploy::run_certbot(&state, &id, &auth_user.username).await?;
    audit(
        &state,
        &auth_user.username,
        "certbot.run",
        "certbot_config",
        &id,
        json!({"status": result.status, "job_id": result.job_id}),
    )
    .await?;
    Ok(Json(
        json!({ "job_id": result.job_id, "status": result.status }),
    ))
}

// ---------------------------------------------------------------------------
// SSH certificates (CA-signed)
//
// Distinct from raw SSH keys (`/certificates/ssh`): here Akamana's SSH User/Host
// CA signs a public key into an OpenSSH certificate embedding principals,
// validity, and options. Grouped under `/api/v1/ssh/...`.
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct SshCaRow {
    id: String,
    ca_type: String,
    private_key_enc: String,
    fingerprint_sha256: String,
}

#[derive(sqlx::FromRow)]
struct SshCertDetailRow {
    id: String,
    ca_type: String,
    cert_type: String,
    key_id: String,
    principals: String,
    critical_options: Option<String>,
    extensions: Option<String>,
    subject_public_key: String,
    certificate: String,
    private_key_enc: Option<String>,
    allow_private_key_export: bool,
    fingerprint_sha256: String,
    machine_id: Option<String>,
    valid_from: chrono::NaiveDateTime,
    valid_to: chrono::NaiveDateTime,
    is_revoked: bool,
    revoked_reason: Option<String>,
}

async fn list_ssh_cas(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<Vec<serde_json::Value>>> {
    // CA public keys are needed to configure sshd/known_hosts; readable by any
    // human or a token with `ca:read`.
    authorize(&auth_user, "ca:read", true)?;

    let rows = sqlx::query_as::<_, (String, String, String, String, String, String, bool, chrono::NaiveDateTime)>(
        "SELECT id, ca_type, name, algorithm, public_key, fingerprint_sha256, is_active, created_at FROM ssh_cas ORDER BY ca_type ASC, created_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                json!({
                    "id": r.0,
                    "ca_type": r.1,
                    "name": r.2,
                    "algorithm": r.3,
                    "public_key": r.4,
                    "fingerprint_sha256": r.5,
                    "is_active": r.6,
                    "created_at": r.7,
                })
            })
            .collect(),
    ))
}

async fn export_ssh_ca_public(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<axum::response::Response> {
    authorize(&auth_user, "ca:read", true)?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT ca_type, public_key FROM ssh_cas WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.pool)
            .await?;
    let (ca_type, public_key) = row.ok_or(AppError::NotFound)?;

    use axum::response::IntoResponse;
    let filename = format!("akamana_ssh_{ca_type}_ca.pub");
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "text/plain".to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        public_key,
    )
        .into_response())
}

async fn rotate_ssh_ca(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    require_human(&auth_user)?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }

    let row: Option<(String,)> = sqlx::query_as("SELECT ca_type FROM ssh_cas WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
    let ca_type = row.ok_or(AppError::NotFound)?.0;
    let comment = if ca_type == "host" {
        "Akamana SSH Host CA"
    } else {
        "Akamana SSH User CA"
    };

    // Deactivate all current CAs of this type, then insert a fresh active one.
    sqlx::query("UPDATE ssh_cas SET is_active = FALSE WHERE ca_type = ?")
        .bind(&ca_type)
        .execute(&state.pool)
        .await?;

    let material = generate_ssh_ca_material(comment)?;
    let enc = encrypt_secret(&state.cfg, &material.private_key)?;
    let new_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO ssh_cas (id, ca_type, name, algorithm, public_key, private_key_enc, fingerprint_sha256, is_active, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?, ?)",
    )
    .bind(&new_id)
    .bind(&ca_type)
    .bind(comment)
    .bind(&material.algorithm)
    .bind(&material.public_key)
    .bind(&enc)
    .bind(&material.fingerprint_sha256)
    .bind(&auth_user.username)
    .bind(Utc::now().naive_utc())
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "ssh_ca.rotate",
        "ssh_ca",
        &new_id,
        json!({"ca_type": ca_type, "fingerprint": material.fingerprint_sha256}),
    )
    .await?;

    Ok(Json(json!({
        "status": "rotated",
        "id": new_id,
        "ca_type": ca_type,
        "public_key": material.public_key,
        "fingerprint_sha256": material.fingerprint_sha256,
    })))
}

async fn issue_ssh_certificate(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<IssueSshCertificateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(crate::errors::message_validation(&e)))?;
    authorize(&auth_user, "ssh:sign", can_manage_ssh(&auth_user.role))?;

    let cert_type = match payload.cert_type.as_str() {
        "user" | "host" => payload.cert_type.as_str(),
        _ => {
            return Err(AppError::Validation(
                "cert_type must be 'user' or 'host'".to_string(),
            ))
        }
    };
    if payload.principals.is_empty() {
        return Err(AppError::Validation(
            "at least one principal is required".to_string(),
        ));
    }
    for p in &payload.principals {
        if p.trim().is_empty() || p.len() > 255 {
            return Err(AppError::Validation("invalid principal".to_string()));
        }
    }

    // Resolve the signing CA (explicit id or the active CA of this type).
    let ca: Option<SshCaRow> = if let Some(ca_id) = payload.ca_id.as_deref() {
        sqlx::query_as::<_, SshCaRow>(
            "SELECT id, ca_type, private_key_enc, fingerprint_sha256 FROM ssh_cas WHERE id = ?",
        )
        .bind(ca_id)
        .fetch_optional(&state.pool)
        .await?
    } else {
        sqlx::query_as::<_, SshCaRow>(
            "SELECT id, ca_type, private_key_enc, fingerprint_sha256 FROM ssh_cas WHERE ca_type = ? AND is_active = TRUE ORDER BY created_at DESC LIMIT 1",
        )
        .bind(cert_type)
        .fetch_optional(&state.pool)
        .await?
    };
    let ca =
        ca.ok_or_else(|| AppError::Validation(format!("no active SSH {cert_type} CA available")))?;
    if ca.ca_type != cert_type {
        return Err(AppError::Validation(
            "selected CA type does not match cert_type".to_string(),
        ));
    }

    // Resolve the subject public key + optional generated private key.
    let mut generated_private: Option<String> = None;
    let mut source_ssh_key_id: Option<String> = None;
    let mut publish_generated = true;
    let subject_public: String = if let Some(gen) = &payload.generate {
        let material = generate_ssh_material(&gen.comment, gen.valid_days)?;
        generated_private = Some(material.private_key);
        publish_generated = gen.publish_private_key;
        material.public_key
    } else if let Some(key_id) = payload.ssh_key_id.as_deref() {
        let row: Option<(String,)> = sqlx::query_as("SELECT public_key FROM ssh_keys WHERE id = ?")
            .bind(key_id)
            .fetch_optional(&state.pool)
            .await?;
        source_ssh_key_id = Some(key_id.to_string());
        row.ok_or(AppError::NotFound)?.0
    } else if let Some(pk) = payload.public_key.as_deref() {
        if pk.trim().is_empty() {
            return Err(AppError::Validation("public_key is empty".to_string()));
        }
        pk.to_string()
    } else {
        return Err(AppError::Validation(
            "one of generate, ssh_key_id, or public_key is required".to_string(),
        ));
    };

    let ca_private = decrypt_secret(&state.cfg, &ca.private_key_enc)?;

    // Random 63-bit serial (BIGINT UNSIGNED-safe, non-zero).
    let serial: u64 = (Uuid::new_v4().as_u128() as u64) >> 1 | 1;

    let critical_options: Vec<(String, String)> = payload
        .critical_options
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|kv| (kv.name.clone(), kv.value.clone()))
                .collect()
        })
        .unwrap_or_default();
    let extensions: Vec<(String, String)> = payload
        .extensions
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|kv| (kv.name.clone(), kv.value.clone()))
                .collect()
        })
        .unwrap_or_default();

    let signed = sign_ssh_certificate(
        &ca_private,
        &subject_public,
        SshCertParams {
            cert_type,
            key_id: &payload.key_id,
            principals: &payload.principals,
            valid_days: payload.valid_days,
            serial,
            critical_options: &critical_options,
            extensions: &extensions,
        },
    )?;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    let principals_json =
        serde_json::to_string(&payload.principals).unwrap_or_else(|_| "[]".to_string());
    let critical_json = serde_json::to_string(&critical_options).ok();
    let ext_json = serde_json::to_string(&extensions).ok();
    let private_enc = match &generated_private {
        Some(pk) => Some(encrypt_secret(&state.cfg, pk)?),
        None => None,
    };

    sqlx::query(
        "INSERT INTO ssh_certificates (id, ca_id, ca_type, cert_type, serial, key_id, principals, critical_options, extensions, subject_public_key, certificate, private_key_enc, allow_private_key_export, fingerprint_sha256, machine_id, ssh_key_id, valid_from, valid_to, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&ca.id)
    .bind(&ca.ca_type)
    .bind(cert_type)
    .bind(serial)
    .bind(&payload.key_id)
    .bind(&principals_json)
    .bind(&critical_json)
    .bind(&ext_json)
    .bind(&subject_public)
    .bind(&signed.certificate)
    .bind(&private_enc)
    .bind(publish_generated)
    .bind(&signed.fingerprint_sha256)
    .bind(&payload.machine_id)
    .bind(&source_ssh_key_id)
    .bind(signed.valid_from.naive_utc())
    .bind(signed.valid_to.naive_utc())
    .bind(&auth_user.username)
    .bind(now)
    .execute(&state.pool)
    .await?;

    audit(
        &state,
        &auth_user.username,
        "ssh_cert.sign",
        "ssh_certificate",
        &id,
        json!({"cert_type": cert_type, "key_id": payload.key_id, "principals": payload.principals, "serial": serial}),
    )
    .await?;

    // Return private key only when freshly generated AND marked exportable.
    let include_private = generated_private
        .as_ref()
        .filter(|_| publish_generated)
        .cloned();

    Ok(Json(json!({
        "cert_id": id,
        "certificate": signed.certificate,
        "public_key": subject_public,
        "private_key": include_private,
        "serial": serial,
        "cert_type": cert_type,
        "key_id": payload.key_id,
        "principals": payload.principals,
        "valid_from": signed.valid_from,
        "valid_to": signed.valid_to,
        "fingerprint_sha256": signed.fingerprint_sha256,
        "ca_fingerprint_sha256": ca.fingerprint_sha256,
    })))
}

async fn list_ssh_certificates(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Query(params): Query<PaginationParams>,
) -> AppResult<Json<serde_json::Value>> {
    authorize(&auth_user, "ssh:read", true)?;
    let (limit, offset) = parse_pagination(params);

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ssh_certificates")
        .fetch_one(&state.pool)
        .await?;

    let rows = sqlx::query_as::<_, (String, String, String, String, String, bool, chrono::NaiveDateTime, chrono::NaiveDateTime, bool, Option<String>, String)>(
        "SELECT id, ca_type, cert_type, key_id, principals, allow_private_key_export, valid_from, valid_to, is_revoked, revoked_reason, fingerprint_sha256 FROM ssh_certificates ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let principals: Vec<String> = serde_json::from_str(&r.4).unwrap_or_default();
            json!({
                "id": r.0,
                "ca_type": r.1,
                "cert_type": r.2,
                "key_id": r.3,
                "principals": principals,
                "allow_private_key_export": r.5,
                "valid_from": r.6,
                "valid_to": r.7,
                "is_revoked": r.8,
                "revoked_reason": r.9,
                "fingerprint_sha256": r.10,
            })
        })
        .collect();

    Ok(Json(
        json!({"items": items, "total": total.0, "limit": limit, "offset": offset}),
    ))
}

async fn get_ssh_certificate(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    authorize(&auth_user, "ssh:read", true)?;

    let row = sqlx::query_as::<_, SshCertDetailRow>(
        "SELECT id, ca_type, cert_type, key_id, principals, critical_options, extensions, subject_public_key, certificate, private_key_enc, allow_private_key_export, fingerprint_sha256, machine_id, valid_from, valid_to, is_revoked, revoked_reason FROM ssh_certificates WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let principals: Vec<String> = serde_json::from_str(&row.principals).unwrap_or_default();
    let private_key = if row.allow_private_key_export {
        match &row.private_key_enc {
            Some(enc) => Some(decrypt_secret(&state.cfg, enc)?),
            None => None,
        }
    } else {
        None
    };

    Ok(Json(json!({
        "id": row.id,
        "ca_type": row.ca_type,
        "cert_type": row.cert_type,
        "key_id": row.key_id,
        "principals": principals,
        "critical_options": row.critical_options,
        "extensions": row.extensions,
        "public_key": row.subject_public_key,
        "certificate": row.certificate,
        "private_key": private_key,
        "allow_private_key_export": row.allow_private_key_export,
        "fingerprint_sha256": row.fingerprint_sha256,
        "machine_id": row.machine_id,
        "valid_from": row.valid_from,
        "valid_to": row.valid_to,
        "is_revoked": row.is_revoked,
        "revoked_reason": row.revoked_reason,
    })))
}

async fn revoke_ssh_certificate(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_ssh(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    sqlx::query("UPDATE ssh_certificates SET is_revoked = TRUE, revoked_at = ?, revoked_reason = 'manual revocation' WHERE id = ?")
        .bind(Utc::now().naive_utc())
        .bind(&id)
        .execute(&state.pool)
        .await?;
    audit(
        &state,
        &auth_user.username,
        "ssh_cert.revoke",
        "ssh_certificate",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status": "revoked"})))
}

async fn delete_ssh_certificate(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    if !can_manage_ssh(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    sqlx::query("DELETE FROM ssh_certificates WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    audit(
        &state,
        &auth_user.username,
        "ssh_cert.delete",
        "ssh_certificate",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"status": "deleted"})))
}

async fn audit(
    state: &AppState,
    actor: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    details: serde_json::Value,
) -> AppResult<()> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_logs (id, actor, action, target_type, target_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(actor)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(details.to_string())
    .bind(Utc::now().naive_utc())
    .execute(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(
            "audit_log_failed: id={} actor={} action={} target_type={} target_id={} error={}",
            id,
            actor,
            action,
            target_type,
            target_id,
            e
        );
        AppError::Internal(format!("audit log failed: {e}"))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{next_free_slug, normalize_domain};
    use std::collections::HashSet;

    // `unwrap`/`expect` are denied crate-wide, tests included: a panicking
    // helper in a test is still a panicking helper. Pattern matching says the
    // same thing without one.
    #[test]
    fn normalize_domain_accepts_a_bare_name() {
        assert!(matches!(
            normalize_domain("pki.example.com").as_deref(),
            Ok("pki.example.com")
        ));
    }

    #[test]
    fn normalize_domain_reduces_a_pasted_url() {
        // Operators paste what their browser shows; the intent is unambiguous.
        assert!(matches!(
            normalize_domain("https://PKI.Example.COM/admin/hosts?tab=1").as_deref(),
            Ok("pki.example.com")
        ));
        assert!(matches!(
            normalize_domain("http://pki.example.com:8443").as_deref(),
            Ok("pki.example.com")
        ));
    }

    #[test]
    fn normalize_domain_drops_the_trailing_root_dot() {
        // `dig` and friends print the fully qualified form with a final dot.
        assert!(matches!(
            normalize_domain("pki.example.com.").as_deref(),
            Ok("pki.example.com")
        ));
    }

    #[test]
    fn normalize_domain_keeps_ipv6_literals_intact() {
        // The port-stripping pass must not eat the address' own colons.
        assert!(matches!(
            normalize_domain("[2001:db8::1]").as_deref(),
            Ok("[2001:db8::1]")
        ));
    }

    #[test]
    fn normalize_domain_rejects_empty_and_hostile_input() {
        assert!(normalize_domain("   ").is_err());
        assert!(normalize_domain("https://").is_err());
        assert!(normalize_domain("bad host name").is_err());
        assert!(normalize_domain("host;rm -rf /").is_err());
        // A path is dropped rather than rejected: the host part is still valid.
        assert!(matches!(
            normalize_domain("pki.example.com/../../etc/passwd").as_deref(),
            Ok("pki.example.com")
        ));
    }

    #[test]
    fn a_first_copy_is_simply_suffixed() {
        let taken = HashSet::new();
        assert_eq!(next_free_slug("nginx", &taken), "nginx-copy");
    }

    #[test]
    fn copies_of_copies_get_numbered_until_one_is_free() {
        let taken: HashSet<String> = ["nginx-copy", "nginx-copy-2", "nginx-copy-3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(next_free_slug("nginx", &taken), "nginx-copy-4");
    }

    #[test]
    fn a_long_slug_is_trimmed_to_leave_room_for_the_suffix() {
        // La colonne slug est un VARCHAR(64) : sans troncature, l'insertion
        // échouerait sur une contrainte de longueur au lieu de rendre un nom
        // utilisable.
        let base = "a".repeat(64);
        let taken = HashSet::new();
        let slug = next_free_slug(&base, &taken);
        assert_eq!(slug.len(), 64);
        assert!(slug.ends_with("-copy"));
    }
}
