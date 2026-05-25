use crate::{
    addons::load_addons,
    auth::{create_local_token, verify_local_user, AuthenticatedUser},
    crypto::{
        create_root_ca, decrypt_secret, encrypt_secret, generate_ssh_material,
        generate_tls_material, CreateRootCaParams, GenerateTlsMaterialParams, SubjectDn,
    },
    errors::{AppError, AppResult},
    machine_monitor,
    models::{
        ApplicationRecord, CertbotConfigRecord, ChangePasswordRequest,
        CreateCertbotConfigRequest, CreateCredentialRequest,
        CreateHostApplicationRequest, CreateHostCredentialRequest, CreateIntermediateRequest,
        CreateMachineRequest, CreateMachineMonitorPortRequest,
        CreateOrganizationRequest, CreateUserRequest, CredentialRow, CredentialSummary,
        CrlEntryRecord, GenerateSshKeyRequest,
        GenerateSshKeyResponse, GenerateTlsKeyRequest, GenerateTlsKeyResponse,
        HostApplicationRecord, HostCredentialRecord,
        ImportSshCertificateRequest, ImportTlsCertificateRequest, IntegrationPlanRequest,
        LoginRequest, MachineRecord, NetworkScanRequest, PublishKeyRequest, RenewTlsRequest, ResetUserPasswordRequest,
        RevokeTlsRequest, SaveDefaultsRequest, SaveMachineMonitorSettingsRequest,
        SaveNotificationSettingsRequest, SaveProfilePictureRequest, SaveSiemSettingsRequest,
        SetAutoRenewRequest, TlsDeployGuideRequest, TokenResponse, UpdateCredentialRequest,
        UpdateHostApplicationRequest, UpdateMachineRequest, UpdateMachineMonitorPortRequest,
        UpsertApplicationRequest, UpdateUserRoleRequest,
    },
    AppState,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{Path, Query, State},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::Utc;
use openssl::{nid::Nid, x509::X509};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, net::IpAddr};
use uuid::Uuid;
use validator::Validate;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/login", post(login))
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
        .route("/api/v1/certificates/tls", get(list_tls_certs))
        .route("/api/v1/certificates/ssh", get(list_ssh_certs))
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
        .route(
            "/api/v1/certificates/ssh/import",
            post(import_ssh_certificate),
        )
        .route("/api/v1/keys/ssh/revoke/:id", post(revoke_ssh_key))
        .route(
            "/api/v1/certificates/tls/:id/export/public",
            get(export_tls_public),
        )
        .route(
            "/api/v1/certificates/tls/:id/export/private",
            get(export_tls_private),
        )
        .route(
            "/api/v1/deploy/tls/:id/guide",
            post(build_tls_deploy_guide),
        )
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
            "/api/v1/machines/monitor/ports/:id/scan",
            post(scan_machine_monitor_port),
        )
        .route(
            "/api/v1/machines/monitor/ports/:id",
            patch(update_machine_monitor_port).delete(delete_machine_monitor_port),
        )
        .route("/api/v1/machines/monitor/scan", post(scan_all_machine_monitor_ports))
        .route("/api/v1/keys/tls", post(generate_tls_key))
        .route("/api/v1/keys/ssh", post(generate_ssh_key))
        .route("/api/v1/crl/revoke", post(revoke_tls))
        .route("/api/v1/crl", get(list_crl))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/:id/role", patch(update_user_role))
        .route("/api/v1/users/:id/password", post(reset_user_password))
        .route("/api/v1/users/:id", axum::routing::delete(delete_user))
        .route("/api/v1/users/me", get(get_me))
        .route("/api/v1/users/me/password", post(change_my_password))
        .route(
            "/api/v1/users/me/picture",
            post(upload_my_picture).delete(delete_my_picture),
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
        .route(
            "/api/v1/certbot/configs/:id/run",
            post(run_certbot_config),
        )
        .route("/api/v1/integrations/addons", get(list_addons))
        .route("/api/v1/integrations/plan", post(build_integration_plan))
        .route("/api/v1/logs/actions", get(list_action_logs))
        .route("/api/v1/logs/access", get(list_access_logs))
        .route("/api/v1/logs/security", get(list_security_logs))
        .route("/api/v1/audit", get(list_action_logs))
        .route("/api/v1/network/resolve", get(resolve_network_info))
        .route("/api/v1/network/scan", post(scan_network))
}

pub async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok", "service": "ezkey", "version": "0.3.1"}))
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

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<TokenResponse>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let role = verify_local_user(&state.pool, &payload.username, &payload.password)
        .await?
        .ok_or(AppError::Auth)?;

    let (token, expires) = create_local_token(&state.cfg, &payload.username, &role)?;
    audit(
        &state,
        &payload.username,
        "auth.login",
        "user",
        &payload.username,
        json!({"success": true}),
    )
    .await?;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in_seconds: expires,
        username: payload.username,
        role,
    }))
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !matches!(
        auth_user.role.as_str(),
        "full_admin" | "tls_admin"
    ) {
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !matches!(
        auth_user.role.as_str(),
        "full_admin" | "tls_admin"
    ) {
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
    if !matches!(
        auth_user.role.as_str(),
        "full_admin" | "tls_admin"
    ) {
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
    if !matches!(
        auth_user.role.as_str(),
        "full_admin" | "tls_admin"
    ) {
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
    if !matches!(
        auth_user.role.as_str(),
        "full_admin" | "tls_admin"
    ) {
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

    let deleted_crl = sqlx::query(
        "DELETE FROM crl_entries WHERE tls_key_id IN (SELECT id FROM tls_keys WHERE root_ca_id = ?)",
    )
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
    let path = std::env::var("EZKEY_CRYPTO_OPTIONS_PATH")
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

async fn create_machine(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateMachineRequest>,
) -> AppResult<Json<MachineRecord>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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

async fn update_machine_monitor_port(
    Path(id): Path<String>,
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<UpdateMachineMonitorPortRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    if payload.port.is_none() && payload.monitor_enabled.is_none() {
        return Err(AppError::Validation(
            "at least one field (port, monitor_enabled) must be provided".to_string(),
        ));
    }

    let existing: Option<(String, i32)> = sqlx::query_as(
        "SELECT machine_id, port FROM machine_monitor_ports WHERE id = ?",
    )
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
        let (current_enabled,): (bool,) = sqlx::query_as(
            "SELECT monitor_enabled FROM machine_monitor_ports WHERE id = ?",
        )
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

    Ok(Json(json!({"status": "updated", "id": id, "port": new_port, "monitor_enabled": new_enabled})))
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
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
    let purpose = payload.purpose.clone().unwrap_or_else(|| "server".to_string());

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
    let machine_id_to_store = if is_ca {
        None
    } else {
        payload.machine_id.as_deref()
    };

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

    audit(
        &state,
        &auth_user.username,
        "tls.generate",
        "tls_key",
        &id,
        json!({"machine_id": payload.machine_id, "common_name": payload.common_name, "serial_hex": material.serial_hex, "root_id": root_id, "cert_level": cert_level}),
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

async fn import_tls_certificate(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<ImportTlsCertificateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;
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

async fn import_ssh_certificate(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<ImportSshCertificateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
    let req = GenerateTlsKeyRequest {
        machine_id: old.machine_id,
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_ssh(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_tls(&auth_user.role) {
        return Err(AppError::Forbidden);
    }

    let found: Option<(String,)> = sqlx::query_as("SELECT serial_hex FROM tls_keys WHERE id = ?")
        .bind(&payload.tls_key_id)
        .fetch_optional(&state.pool)
        .await?;
    let Some((serial_hex,)) = found else {
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
    sqlx::query("INSERT INTO crl_entries (id, tls_key_id, serial_hex, revoked_at, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(&crl_id)
        .bind(&payload.tls_key_id)
        .bind(serial_hex)
        .bind(now)
        .bind(&payload.reason)
        .bind(&auth_user.username)
        .bind(now)
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

    sqlx::query("DELETE FROM tls_keys WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
    let reload_command = payload
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
        let ws_snippet =
            nginx_websocket_tls_snippet(&chain_path, key_path, &websocket_location, &websocket_upstream);
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
    if is_container_target && payload.container_name.as_deref().unwrap_or("").trim().is_empty() {
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

    let websocket_snippet =
        nginx_websocket_tls_snippet(&chain_path, key_path, &websocket_location, &websocket_upstream);

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

    let rows = sqlx::query_as::<_, (String, String, String, chrono::NaiveDateTime)>(
        "SELECT id, username, role, created_at FROM users ORDER BY username ASC",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| json!({"id": r.0, "username": r.1, "role": r.2, "created_at": r.3}))
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("unable to hash user password: {e}")))?
        .to_string();

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    sqlx::query("INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(&payload.username)
        .bind(hash)
        .bind(&payload.role)
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
        json!({"username": payload.username, "role": payload.role}),
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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

    sqlx::query("DELETE FROM user_profiles WHERE user_id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;
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
    let row: (String, String, String, chrono::NaiveDateTime) =
        sqlx::query_as("SELECT id, username, role, created_at FROM users WHERE username = ?")
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
        .map_err(|e| AppError::Validation(e.to_string()))?;

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

async fn upload_my_picture(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<SaveProfilePictureRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

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
        "SELECT key_name, value_text FROM settings WHERE key_name IN ('default_tls_cipher', 'default_tls_key_length', 'default_ssh_cipher', 'default_ssh_key_length', 'cert_owners_json', 'cert_environments_json')",
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
    })))
}

async fn save_defaults(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<SaveDefaultsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
            payload
                .cert_environments_json
                .clone()
                .unwrap_or_else(|| "[\"production\",\"staging\",\"internal-lab\",\"development\"]".to_string()),
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !matches!(auth_user.role.as_str(), "full_admin") {
        return Err(AppError::Forbidden);
    }

    let now = Utc::now().naive_utc();
    for (k, v) in [
        ("notify_webhook_url", payload.webhook_url.clone()),
        ("notify_days_before", payload.days_before.to_string()),
        ("notify_cooldown_hours", payload.cooldown_hours.to_string()),
        ("notify_email_to", payload.email_to.clone().unwrap_or_default()),
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
    _auth: AuthenticatedUser,
) -> AppResult<Json<serde_json::Value>> {
    let rows = sqlx::query_as::<_, ApplicationRecord>(
        "SELECT id, slug, name, default_cert_path, default_key_path, default_chain_path, \
         default_config_dir, default_reload_command, config_example, notes, is_builtin, \
         created_at, updated_at FROM applications ORDER BY name ASC",
    )
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let now = Utc::now().naive_utc();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO applications (id, slug, name, default_cert_path, default_key_path, \
         default_chain_path, default_config_dir, default_reload_command, config_example, notes, \
         is_builtin, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, ?, ?)",
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
    .bind(now)
    .bind(now)
    .execute(&state.pool)
    .await?;
    audit(&state, &auth_user.username, "application.create", "application", &id, json!({"slug": payload.slug})).await?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let affected = sqlx::query(
        "UPDATE applications SET slug = ?, name = ?, default_cert_path = ?, default_key_path = ?, \
         default_chain_path = ?, default_config_dir = ?, default_reload_command = ?, \
         config_example = ?, notes = ?, updated_at = ? WHERE id = ?",
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
    .bind(Utc::now().naive_utc())
    .bind(&id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    audit(&state, &auth_user.username, "application.update", "application", &id, json!({})).await?;
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
    let builtin: Option<(bool,)> = sqlx::query_as("SELECT is_builtin FROM applications WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
    match builtin {
        None => return Err(AppError::NotFound),
        Some((true,)) => {
            return Err(AppError::Validation("built-in applications cannot be deleted".to_string()))
        }
        Some((false,)) => {}
    }
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
    sqlx::query("DELETE FROM applications WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    audit(&state, &auth_user.username, "application.delete", "application", &id, json!({})).await?;
    Ok(Json(json!({ "status": "deleted" })))
}

async fn fetch_application(state: &AppState, id: &str) -> AppResult<Json<ApplicationRecord>> {
    let row = sqlx::query_as::<_, ApplicationRecord>(
        "SELECT id, slug, name, default_cert_path, default_key_path, default_chain_path, \
         default_config_dir, default_reload_command, config_example, notes, is_builtin, \
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if auth_user.role != "full_admin" {
        return Err(AppError::Forbidden);
    }
    let secret_enc = encrypt_optional(&state, payload.secret.as_deref())?;
    // Reuse an existing EZKey SSH key (passwordless) when requested; otherwise take the pasted key.
    // Both this table and ssh_keys encrypt with the same KEK, so the ciphertext can be copied directly.
    let (key_enc, pass_enc) = if let Some(ssh_key_id) = payload.ssh_key_id.as_deref() {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT private_key_enc FROM ssh_keys WHERE id = ? AND is_revoked = false")
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
    audit(&state, &auth_user.username, "credential.create", "credential", &id, json!({"name": payload.name, "kind": payload.kind})).await?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
    audit(&state, &auth_user.username, "credential.update", "credential", &id, json!({})).await?;
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
    audit(&state, &auth_user.username, "credential.delete", "credential", &id, json!({})).await?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let protocol = payload.protocol.clone().unwrap_or_else(|| "ssh".to_string());
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
    audit(&state, &auth_user.username, "host_credential.create", "host_credential", &id, json!({"machine_id": payload.machine_id})).await?;
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
    audit(&state, &auth_user.username, "host_credential.delete", "host_credential", &id, json!({})).await?;
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
         ha.credential_id, ha.auto_deploy, ha.last_deploy_status, ha.last_deploy_at, \
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let now = Utc::now().naive_utc();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO host_applications (id, machine_id, application_id, tls_key_id, cert_path, \
         key_path, chain_path, reload_command, credential_id, auto_deploy, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(payload.auto_deploy.unwrap_or(false))
    .bind(now)
    .bind(now)
    .execute(&state.pool)
    .await?;
    audit(&state, &auth_user.username, "host_application.create", "host_application", &id, json!({"machine_id": payload.machine_id, "application_id": payload.application_id})).await?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let existing = sqlx::query_as::<_, HostApplicationRecord>(
        "SELECT ha.id, ha.machine_id, m.hostname, ha.application_id, a.name AS application_name, \
         ha.tls_key_id, ha.cert_path, ha.key_path, ha.chain_path, ha.reload_command, \
         ha.credential_id, ha.auto_deploy, ha.last_deploy_status, ha.last_deploy_at, \
         ha.created_at, ha.updated_at \
         FROM host_applications ha \
         JOIN machines m ON m.id = ha.machine_id \
         JOIN applications a ON a.id = ha.application_id WHERE ha.id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let tls_key_id = payload.tls_key_id.or(existing.tls_key_id);
    let cert_path = payload.cert_path.or(existing.cert_path);
    let key_path = payload.key_path.or(existing.key_path);
    let chain_path = payload.chain_path.or(existing.chain_path);
    let reload_command = payload.reload_command.or(existing.reload_command);
    let credential_id = payload.credential_id.or(existing.credential_id);
    let auto_deploy = payload.auto_deploy.unwrap_or(existing.auto_deploy);

    sqlx::query(
        "UPDATE host_applications SET tls_key_id = ?, cert_path = ?, key_path = ?, chain_path = ?, \
         reload_command = ?, credential_id = ?, auto_deploy = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&tls_key_id)
    .bind(&cert_path)
    .bind(&key_path)
    .bind(&chain_path)
    .bind(&reload_command)
    .bind(&credential_id)
    .bind(auto_deploy)
    .bind(Utc::now().naive_utc())
    .bind(&id)
    .execute(&state.pool)
    .await?;
    audit(&state, &auth_user.username, "host_application.update", "host_application", &id, json!({})).await?;
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
    let affected = sqlx::query("DELETE FROM host_applications WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    audit(&state, &auth_user.username, "host_application.delete", "host_application", &id, json!({})).await?;
    Ok(Json(json!({ "status": "deleted" })))
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
    audit(&state, &auth_user.username, "machine.update", "machine", &id, json!({})).await?;
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
    audit(&state, &auth_user.username, "machine.delete", "machine", &id, json!({})).await?;
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
    audit(&state, &auth_user.username, "tls.auto_renew", "tls_key", &id, json!({"auto_renew": payload.auto_renew, "renew_days_before": days})).await?;
    Ok(Json(json!({ "status": "updated", "auto_renew": payload.auto_renew, "renew_days_before": days })))
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
    audit(&state, &auth_user.username, "host_application.deploy", "host_application", &id, json!({"status": result.status, "job_id": result.job_id})).await?;
    Ok(Json(json!({ "job_id": result.job_id, "status": result.status })))
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
    Ok(Json(json!({ "job_id": result.job_id, "status": result.status })))
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !can_manage_machines(&auth_user.role) {
        return Err(AppError::Forbidden);
    }
    let port = payload.port.unwrap_or(443).clamp(1, 65535) as u16;

    let (a, b, c) = match payload.cidr.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
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
        None => server_default_network()
            .ok_or_else(|| AppError::Internal("could not determine the server's network".to_string()))?,
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

    audit(&state, &auth_user.username, "network.scan", "network", &format!("{a}.{b}.{c}.0/24"), json!({"port": port, "found": items.len()})).await?;
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
    let tcp = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(900)).ok()?;
    tcp.set_read_timeout(Some(std::time::Duration::from_millis(900))).ok()?;
    tcp.set_write_timeout(Some(std::time::Duration::from_millis(900))).ok()?;
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
    sock.set_read_timeout(Some(std::time::Duration::from_millis(700))).ok()?;
    // NBSTAT (node status) query for the wildcard name "*".
    let mut req: Vec<u8> = vec![0xA2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20];
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
        .map_err(|e| AppError::Validation(e.to_string()))?;
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
    audit(&state, &auth_user.username, "certbot.create", "certbot_config", &id, json!({"machine_id": payload.machine_id, "domains": payload.domains})).await?;
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
    audit(&state, &auth_user.username, "certbot.delete", "certbot_config", &id, json!({})).await?;
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
    audit(&state, &auth_user.username, "certbot.run", "certbot_config", &id, json!({"status": result.status, "job_id": result.job_id})).await?;
    Ok(Json(json!({ "job_id": result.job_id, "status": result.status })))
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
