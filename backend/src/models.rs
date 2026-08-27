use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
    pub iss: String,
    pub aud: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 3, max = 64))]
    pub username: String,
    #[validate(length(min = 12, max = 256))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in_seconds: i64,
    pub username: String,
    pub role: String,
}

/// Returned by `/auth/login` when the password was right but the session is not
/// usable yet: the account has a second factor, or MFA is mandatory and the
/// account has none. `mfa_token` is only good for the follow-up step.
#[derive(Debug, Serialize)]
pub struct MfaChallengeResponse {
    /// Always true — lets the client branch on one field.
    pub mfa_required: bool,
    /// True when the user must *enroll* a factor before they can get in.
    pub mfa_setup_required: bool,
    pub mfa_token: String,
    pub expires_in_seconds: i64,
    /// Which of `totp` / `recovery` the account can currently use.
    pub methods: Vec<String>,
    pub username: String,
}

/// `/auth/login` either signs you in or hands back a challenge. Untagged so the
/// wire format stays a flat object in both cases.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginOutcome {
    Token(TokenResponse),
    Mfa(MfaChallengeResponse),
}

#[derive(Debug, Deserialize, Validate)]
pub struct MfaLoginRequest {
    #[validate(length(min = 10, max = 4096))]
    pub mfa_token: String,
    /// A 6-digit TOTP code or a `XXXXX-XXXXX` recovery code.
    #[validate(length(min = 6, max = 32))]
    pub code: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct MfaTokenRequest {
    #[validate(length(min = 10, max = 4096))]
    pub mfa_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct TotpCodeRequest {
    #[validate(length(min = 6, max = 10))]
    pub code: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct DisableMfaRequest {
    /// Re-authenticate before removing a factor.
    #[validate(length(min = 12, max = 256))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PasswordResetRequest {
    /// Username or email address — we never say which one matched.
    #[validate(length(min = 3, max = 255))]
    pub identifier: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PasswordResetConfirmRequest {
    #[validate(length(min = 20, max = 512))]
    pub token: String,
    #[validate(length(min = 12, max = 256))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserEmailRequest {
    /// Empty string clears the address.
    #[validate(length(max = 255))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PasskeyRegisterStartRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PasskeyRegisterFinishRequest {
    #[validate(length(min = 10, max = 128))]
    pub challenge_id: String,
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    /// Raw `RegisterPublicKeyCredential` produced by `navigator.credentials.create`.
    pub credential: serde_json::Value,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PasskeyLoginStartRequest {
    #[validate(length(min = 3, max = 64))]
    pub username: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PasskeyLoginFinishRequest {
    #[validate(length(min = 10, max = 128))]
    pub challenge_id: String,
    /// Raw `PublicKeyCredential` produced by `navigator.credentials.get`.
    pub credential: serde_json::Value,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateApiTokenRequest {
    #[validate(length(min = 2, max = 128))]
    pub name: String,
    #[validate(length(max = 512))]
    pub comment: Option<String>,
    /// Requested scopes (e.g. `tls:issue`, `ssh:sign`). Must be a subset of what
    /// the creating user's role is allowed to grant.
    pub scopes: Vec<String>,
    /// Optional validity window in days. Omit / null for a non-expiring token.
    #[validate(range(min = 1, max = 3650))]
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct SshCertKeyValue {
    pub name: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct GenerateSshForCert {
    #[validate(length(min = 1, max = 255))]
    pub comment: String,
    #[serde(default = "default_ssh_cert_key_days")]
    #[validate(range(min = 1, max = 3650))]
    pub valid_days: i64,
    #[serde(default)]
    pub publish_private_key: bool,
}

fn default_ssh_cert_key_days() -> i64 {
    365
}

#[derive(Debug, Deserialize, Validate)]
pub struct IssueSshCertificateRequest {
    /// "user" or "host".
    pub cert_type: String,
    /// Optional explicit CA id; defaults to the active CA of `cert_type`.
    pub ca_id: Option<String>,
    /// Sign an existing Akamana SSH key by id.
    pub ssh_key_id: Option<String>,
    /// Sign a pasted OpenSSH public key.
    pub public_key: Option<String>,
    /// Generate a fresh keypair, then sign its public key.
    pub generate: Option<GenerateSshForCert>,
    /// Certificate identity (`key_id`), shown in `ssh-keygen -L` and sshd logs.
    #[validate(length(min = 1, max = 255))]
    pub key_id: String,
    /// Allowed principals: usernames (user certs) or hostnames (host certs).
    pub principals: Vec<String>,
    #[validate(range(min = 1, max = 3650))]
    pub valid_days: i64,
    pub critical_options: Option<Vec<SshCertKeyValue>>,
    pub extensions: Option<Vec<SshCertKeyValue>>,
    pub machine_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateMachineRequest {
    #[validate(length(min = 2, max = 255))]
    pub hostname: String,
    #[validate(length(min = 1, max = 255))]
    pub ip_address: String,
    #[validate(length(min = 2, max = 255))]
    pub owner: String,
    #[validate(length(min = 2, max = 64))]
    pub environment: String,
    #[validate(length(max = 64))]
    pub os_type: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct MachineRecord {
    pub id: String,
    pub hostname: String,
    pub ip_address: String,
    pub owner: String,
    pub environment: String,
    pub os_type: Option<String>,
    pub alert_email: Option<String>,
    pub test_url: Option<String>,
    pub monitor_only: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize, Validate)]
pub struct GenerateTlsKeyRequest {
    #[validate(length(min = 36, max = 36))]
    pub machine_id: Option<String>,
    pub root_id: Option<i32>,
    #[validate(length(min = 2, max = 32))]
    pub cert_level: Option<String>,
    #[validate(length(min = 0, max = 36))]
    pub parent_cert_id: Option<String>,
    #[validate(length(min = 2, max = 255))]
    pub common_name: String,
    #[validate(range(min = 1, max = 1825))]
    pub valid_days: i64,
    #[validate(length(min = 2, max = 64))]
    pub cipher: Option<String>,
    #[validate(range(min = 256, max = 8192))]
    pub key_length: Option<i32>,
    /// DNS names and/or IP addresses the certificate must be valid for (SubjectAltName).
    pub sans: Option<Vec<String>>,
    /// mTLS purpose: "server" (default), "client", or "both".
    #[validate(length(max = 16))]
    pub purpose: Option<String>,
    #[serde(default = "default_publish_private_key")]
    pub publish_private_key: bool,
}

#[derive(Debug, Serialize)]
pub struct GenerateTlsKeyResponse {
    pub key_id: String,
    pub serial_hex: String,
    pub cert_pem: String,
    pub private_key_pem: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct GenerateSshKeyRequest {
    #[validate(length(min = 36, max = 36))]
    pub machine_id: Option<String>,
    #[validate(range(min = 1, max = 3650))]
    pub valid_days: i64,
    #[validate(length(min = 2, max = 255))]
    pub comment: String,
    #[validate(length(min = 2, max = 64))]
    pub cipher: Option<String>,
    #[validate(range(min = 256, max = 8192))]
    pub key_length: Option<i32>,
    #[serde(default = "default_publish_private_key")]
    pub publish_private_key: bool,
}

#[derive(Debug, Serialize)]
pub struct GenerateSshKeyResponse {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
    pub fingerprint_sha256: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RevokeTlsRequest {
    #[validate(length(min = 36, max = 36))]
    pub tls_key_id: String,
    #[validate(length(min = 3, max = 255))]
    pub reason: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CrlEntryRecord {
    pub id: String,
    pub tls_key_id: String,
    pub serial_hex: String,
    pub revoked_at: chrono::NaiveDateTime,
    pub reason: String,
    pub created_by: String,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RenewTlsRequest {
    #[validate(length(min = 36, max = 36))]
    pub tls_key_id: String,
    #[validate(range(min = 1, max = 1825))]
    pub valid_days: i64,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 3, max = 64))]
    pub username: String,
    #[validate(length(min = 12, max = 256))]
    pub password: String,
    #[validate(length(min = 5, max = 32))]
    pub role: String,
    /// Optional: needed for the "forgot my password" mail to reach them.
    #[validate(length(max = 255))]
    pub email: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRoleRequest {
    #[validate(length(min = 5, max = 32))]
    pub role: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetUserPasswordRequest {
    #[validate(length(min = 12, max = 256))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 12, max = 256))]
    pub old_password: String,
    #[validate(length(min = 12, max = 256))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SaveProfilePictureRequest {
    #[validate(length(min = 20, max = 131072))]
    pub picture_data_url: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SaveDefaultsRequest {
    #[validate(length(min = 3, max = 32))]
    pub default_tls_cipher: String,
    #[validate(range(min = 256, max = 8192))]
    pub default_tls_key_length: i64,
    #[validate(length(min = 3, max = 32))]
    pub default_ssh_cipher: String,
    #[validate(range(min = 256, max = 8192))]
    pub default_ssh_key_length: i64,
    pub cert_owners_json: Option<String>,
    pub cert_environments_json: Option<String>,
    #[validate(length(max = 512))]
    pub public_base_url: Option<String>,
    /// Base URL under which CRLs are reachable; used to build the CRL
    /// Distribution Point embedded in issued certs (as `<base>/crl/<root_id>.crl`).
    /// Leave blank to omit the CDP extension.
    #[validate(length(max = 512))]
    pub crl_base_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SaveNotificationSettingsRequest {
    #[validate(length(min = 0, max = 1024))]
    pub webhook_url: String,
    #[validate(range(min = 1, max = 180))]
    pub days_before: i64,
    #[validate(range(min = 1, max = 168))]
    pub cooldown_hours: i64,
    #[validate(length(min = 0, max = 1024))]
    pub email_to: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SaveSiemSettingsRequest {
    #[validate(length(min = 0, max = 1024))]
    pub webhook_url: String,
    #[validate(range(min = 1, max = 1440))]
    pub brute_force_window_minutes: i64,
    #[validate(range(min = 3, max = 100))]
    pub brute_force_threshold: i64,
    #[validate(range(min = 1, max = 1440))]
    pub alert_cooldown_minutes: i64,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateMachineMonitorPortRequest {
    #[validate(length(min = 36, max = 36))]
    pub machine_id: String,
    #[validate(range(min = 1, max = 65535))]
    pub port: i32,
    /// Optional SNI/virtual-host to present during the TLS handshake. Empty = default host.
    #[validate(length(max = 255))]
    pub sni_host: Option<String>,
    pub monitor_enabled: Option<bool>,
}

/// Registers a domain name for monitoring without knowing its host first.
///
/// The server resolves the name, attaches it to the machine that already owns
/// that address (or creates one), then probes and scans it exactly as the
/// "add a virtual host" flow on a host's page does.
#[derive(Debug, Deserialize, Validate)]
pub struct AddMonitoredDomainRequest {
    /// Domain name to monitor. A pasted URL is accepted and reduced to its host.
    #[validate(length(min = 1, max = 255))]
    pub domain: String,
    /// Port to monitor. When absent, 443 is used if it answers, otherwise 80.
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<i32>,
    /// Only used when a new machine has to be created.
    #[validate(length(max = 255))]
    pub owner: Option<String>,
    #[validate(length(max = 64))]
    pub environment: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateMachineMonitorPortRequest {
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<i32>,
    #[validate(length(max = 255))]
    pub sni_host: Option<String>,
    pub monitor_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SaveMachineMonitorSettingsRequest {
    pub monitor_enabled: bool,
    #[validate(range(min = 1, max = 168))]
    pub frequency_hours: i64,
    #[validate(length(min = 1, max = 256))]
    pub default_ports_csv: String,
    #[validate(length(min = 0, max = 1024))]
    pub alert_webhook_url: String,
    #[validate(length(min = 0, max = 1024))]
    pub alert_email_to: String,
    #[validate(range(min = 1, max = 168))]
    pub alert_cooldown_hours: i64,
}

#[derive(Debug, Deserialize, Validate)]
pub struct IntegrationPlanRequest {
    #[validate(length(min = 1, max = 128))]
    pub addon_id: String,
    pub values: serde_json::Value,
}

#[derive(Debug, Deserialize, Validate)]
pub struct TlsDeployGuideRequest {
    #[validate(length(min = 2, max = 32))]
    pub target: String,
    #[validate(length(min = 1, max = 512))]
    pub cert_path: String,
    #[validate(length(min = 1, max = 512))]
    pub key_path: String,
    #[validate(length(min = 0, max = 512))]
    pub chain_path: Option<String>,
    #[validate(length(min = 0, max = 512))]
    pub reload_command: Option<String>,
    pub use_sudo: Option<bool>,
    #[validate(length(min = 0, max = 128))]
    pub container_name: Option<String>,
    #[validate(length(min = 0, max = 512))]
    pub nginx_conf_path: Option<String>,
    #[validate(length(min = 0, max = 128))]
    pub websocket_location: Option<String>,
    #[validate(length(min = 0, max = 512))]
    pub websocket_upstream: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PublishKeyRequest {
    pub allow_private_key_export: bool,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ImportRootCaRequest {
    #[validate(length(min = 2, max = 255))]
    pub organization: String,
    #[validate(length(min = 32, max = 262144))]
    pub cert_pem: String,
    /// Optional. Without it the root is a trust anchor only — Akamana can publish
    /// and distribute it but cannot sign intermediates/leaves under it.
    #[validate(length(min = 0, max = 262144))]
    pub private_key_pem: Option<String>,
    #[validate(length(max = 1024))]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ImportTlsCertificateRequest {
    #[validate(length(min = 36, max = 36))]
    pub machine_id: Option<String>,
    pub root_id: Option<i32>,
    #[validate(length(min = 2, max = 32))]
    pub cert_level: Option<String>,
    #[validate(length(min = 0, max = 36))]
    pub parent_cert_id: Option<String>,
    #[validate(length(min = 32, max = 262144))]
    pub cert_pem: String,
    #[validate(length(min = 0, max = 262144))]
    pub private_key_pem: Option<String>,
    pub publish_private_key: bool,
    #[validate(length(min = 2, max = 64))]
    pub cipher: String,
    #[validate(range(min = 256, max = 8192))]
    pub key_length: i32,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateOrganizationRequest {
    #[validate(length(min = 2, max = 255))]
    pub organization: String,
    #[validate(length(min = 2, max = 255))]
    pub root_common_name: String,
    #[validate(length(min = 0, max = 1024))]
    pub description: Option<String>,
    #[validate(range(min = 1, max = 40))]
    pub root_valid_years: i64,
    #[validate(length(min = 2, max = 2))]
    pub country: Option<String>,
    #[validate(length(max = 128))]
    pub state: Option<String>,
    #[validate(length(max = 128))]
    pub locality: Option<String>,
    #[validate(length(max = 128))]
    pub org_unit: Option<String>,
    #[validate(length(min = 2, max = 64))]
    pub root_cipher: Option<String>,
    #[validate(range(min = 256, max = 8192))]
    pub root_key_length: Option<i32>,
    pub create_intermediate: bool,
    #[validate(length(min = 2, max = 255))]
    pub intermediate_common_name: Option<String>,
    #[validate(range(min = 30, max = 7300))]
    pub intermediate_valid_days: Option<i64>,
    #[validate(length(min = 2, max = 64))]
    pub intermediate_cipher: Option<String>,
    #[validate(range(min = 256, max = 8192))]
    pub intermediate_key_length: Option<i32>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateIntermediateRequest {
    pub root_id: i32,
    #[validate(length(min = 2, max = 255))]
    pub common_name: String,
    #[validate(range(min = 30, max = 7300))]
    pub valid_days: i64,
    #[validate(length(min = 2, max = 64))]
    pub cipher: Option<String>,
    #[validate(range(min = 256, max = 8192))]
    pub key_length: Option<i32>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ImportSshCertificateRequest {
    #[validate(length(min = 36, max = 36))]
    pub machine_id: Option<String>,
    #[validate(length(min = 2, max = 255))]
    pub machine_name: Option<String>,
    #[validate(length(min = 2, max = 128))]
    pub ssh_username: String,
    #[validate(length(min = 32, max = 65536))]
    pub public_key: String,
    #[validate(length(min = 0, max = 262144))]
    pub private_key: Option<String>,
    #[validate(length(min = 2, max = 64))]
    pub cipher: String,
    #[validate(range(min = 256, max = 8192))]
    pub key_length: i32,
    pub publish_private_key: bool,
}

fn default_publish_private_key() -> bool {
    false
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CertbotConfigRecord {
    pub id: String,
    pub machine_id: String,
    pub hostname: String,
    pub domains: String,
    pub email: Option<String>,
    pub challenge: String,
    pub webroot_path: Option<String>,
    pub dns_plugin: Option<String>,
    pub extra_args: Option<String>,
    pub staging: bool,
    pub live_cert_path: Option<String>,
    pub last_run_status: Option<String>,
    pub last_run_at: Option<chrono::NaiveDateTime>,
    pub last_not_after: Option<chrono::NaiveDateTime>,
    pub auto_renew: bool,
    pub renew_days_before: i32,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateCertbotConfigRequest {
    #[validate(length(min = 36, max = 36))]
    pub machine_id: String,
    #[validate(length(min = 3, max = 1024))]
    pub domains: String,
    #[validate(length(max = 255))]
    pub email: Option<String>,
    #[validate(length(min = 2, max = 32))]
    pub challenge: String,
    #[validate(length(max = 512))]
    pub webroot_path: Option<String>,
    #[validate(length(max = 64))]
    pub dns_plugin: Option<String>,
    #[validate(length(max = 1024))]
    pub extra_args: Option<String>,
    pub staging: Option<bool>,
    #[validate(length(max = 512))]
    pub live_cert_path: Option<String>,
    pub auto_renew: Option<bool>,
    #[validate(range(min = 1, max = 180))]
    pub renew_days_before: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SetAutoRenewRequest {
    pub auto_renew: bool,
    #[validate(range(min = 1, max = 180))]
    pub renew_days_before: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct BackupSettingsRequest {
    pub enabled: bool,
    #[validate(range(min = 1, max = 720))]
    pub frequency_hours: i64,
    #[validate(range(min = 1, max = 10))]
    pub retention: i64,
    pub skip_unchanged: bool,
    /// "none" or "passphrase" (envelope added later). Defaults to "none".
    #[validate(length(max = 32))]
    pub encryption_mode: Option<String>,
    /// New backup passphrase. Only sent when the operator sets/changes it; empty
    /// or omitted leaves the stored passphrase untouched.
    #[validate(length(max = 512))]
    pub passphrase: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct BackupRemoteSettingsRequest {
    /// "local" (no remote), "path" (mounted dir / NFS / SMB), or "sftp".
    #[validate(length(max = 16))]
    pub dest_type: String,
    #[validate(length(max = 1024))]
    pub remote_path: Option<String>,
    #[validate(range(min = 1, max = 100))]
    pub remote_retention: Option<i64>,
    #[validate(length(max = 255))]
    pub sftp_host: Option<String>,
    #[validate(range(min = 1, max = 65535))]
    pub sftp_port: Option<i64>,
    #[validate(length(max = 128))]
    pub sftp_user: Option<String>,
    /// "password" or "key".
    #[validate(length(max = 16))]
    pub sftp_auth: Option<String>,
    #[validate(length(max = 1024))]
    pub sftp_remote_dir: Option<String>,
    // Secrets — set-only; omitted/empty keeps the stored value.
    #[validate(length(max = 1024))]
    pub sftp_password: Option<String>,
    #[validate(length(max = 32768))]
    pub sftp_private_key: Option<String>,
    #[validate(length(max = 512))]
    pub sftp_passphrase: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AddBackupRecipientRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    /// RSA public key in PEM (SPKI or PKCS#1).
    #[validate(length(min = 40, max = 32768))]
    pub public_key_pem: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RestoreBackupRequest {
    /// Base64 of the backup file (`.sql` or `.ezbak`).
    #[validate(length(min = 1))]
    pub data_b64: String,
    pub passphrase: Option<String>,
    /// Recipient private key (PEM) for envelope-encrypted backups.
    #[validate(length(max = 32768))]
    pub private_key_pem: Option<String>,
    pub key_passphrase: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct NetworkScanRequest {
    /// A /24 network such as "192.168.1.0/24". When omitted, the Akamana server's own /24 is used.
    #[validate(length(max = 64))]
    pub cidr: Option<String>,
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<i32>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateMachineRequest {
    #[validate(length(min = 2, max = 255))]
    pub hostname: Option<String>,
    #[validate(length(min = 1, max = 255))]
    pub ip_address: Option<String>,
    #[validate(length(min = 2, max = 255))]
    pub owner: Option<String>,
    #[validate(length(min = 2, max = 64))]
    pub environment: Option<String>,
    #[validate(length(max = 255))]
    pub alert_email: Option<String>,
    #[validate(length(max = 512))]
    pub test_url: Option<String>,
    #[validate(length(max = 64))]
    pub os_type: Option<String>,
    pub monitor_only: Option<bool>,
}

// ---- Applications (deployment target catalog) ----

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ApplicationRecord {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub default_cert_path: Option<String>,
    pub default_key_path: Option<String>,
    pub default_chain_path: Option<String>,
    pub default_config_dir: Option<String>,
    pub default_reload_command: Option<String>,
    pub config_example: Option<String>,
    pub notes: Option<String>,
    /// Certificate format this application expects: "pem", "der", or "pkcs12".
    pub expected_cert_format: Option<String>,
    pub is_builtin: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpsertApplicationRequest {
    #[validate(length(min = 2, max = 64))]
    pub slug: String,
    #[validate(length(min = 2, max = 128))]
    pub name: String,
    #[validate(length(max = 512))]
    pub default_cert_path: Option<String>,
    #[validate(length(max = 512))]
    pub default_key_path: Option<String>,
    #[validate(length(max = 512))]
    pub default_chain_path: Option<String>,
    #[validate(length(max = 512))]
    pub default_config_dir: Option<String>,
    #[validate(length(max = 512))]
    pub default_reload_command: Option<String>,
    #[validate(length(max = 65535))]
    pub config_example: Option<String>,
    #[validate(length(max = 4096))]
    pub notes: Option<String>,
    #[validate(length(max = 16))]
    pub expected_cert_format: Option<String>,
}

// ---- Credentials (used to connect to hosts) ----

#[derive(Debug, sqlx::FromRow)]
pub struct CredentialRow {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub username: Option<String>,
    pub secret_enc: Option<String>,
    pub ssh_private_key_enc: Option<String>,
    pub ssh_passphrase_enc: Option<String>,
    pub notes: Option<String>,
    pub created_by: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Serialize)]
pub struct CredentialSummary {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub username: Option<String>,
    pub has_secret: bool,
    pub has_ssh_private_key: bool,
    pub notes: Option<String>,
    pub created_by: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

impl From<CredentialRow> for CredentialSummary {
    fn from(r: CredentialRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            kind: r.kind,
            username: r.username,
            has_secret: r.secret_enc.is_some(),
            has_ssh_private_key: r.ssh_private_key_enc.is_some(),
            notes: r.notes,
            created_by: r.created_by,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateCredentialRequest {
    #[validate(length(min = 2, max = 128))]
    pub name: String,
    #[validate(length(min = 2, max = 32))]
    pub kind: String,
    #[validate(length(max = 255))]
    pub username: Option<String>,
    #[validate(length(max = 8192))]
    pub secret: Option<String>,
    #[validate(length(max = 65535))]
    pub ssh_private_key: Option<String>,
    #[validate(length(max = 1024))]
    pub ssh_passphrase: Option<String>,
    /// Reuse the private key of an existing Akamana-generated SSH key instead of pasting one.
    #[validate(length(min = 36, max = 36))]
    pub ssh_key_id: Option<String>,
    #[validate(length(max = 4096))]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateCredentialRequest {
    #[validate(length(min = 2, max = 128))]
    pub name: Option<String>,
    #[validate(length(max = 255))]
    pub username: Option<String>,
    #[validate(length(max = 8192))]
    pub secret: Option<String>,
    #[validate(length(max = 65535))]
    pub ssh_private_key: Option<String>,
    #[validate(length(max = 1024))]
    pub ssh_passphrase: Option<String>,
    #[validate(length(max = 4096))]
    pub notes: Option<String>,
}

// ---- Host <-> Credential links ----

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct HostCredentialRecord {
    pub id: String,
    pub machine_id: String,
    pub hostname: String,
    pub credential_id: String,
    pub credential_name: String,
    pub protocol: String,
    pub port: Option<i32>,
    pub is_default: bool,
    pub last_check_status: Option<String>,
    pub last_check_at: Option<chrono::NaiveDateTime>,
    pub last_check_message: Option<String>,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateHostCredentialRequest {
    #[validate(length(min = 36, max = 36))]
    pub machine_id: String,
    #[validate(length(min = 36, max = 36))]
    pub credential_id: String,
    #[validate(length(min = 2, max = 32))]
    pub protocol: Option<String>,
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<i32>,
    pub is_default: Option<bool>,
}

// ---- Host <-> Application links (deployment targets) ----

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct HostApplicationRecord {
    pub id: String,
    pub machine_id: String,
    pub hostname: String,
    pub application_id: String,
    pub application_name: String,
    pub tls_key_id: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub chain_path: Option<String>,
    pub reload_command: Option<String>,
    pub credential_id: Option<String>,
    pub auto_deploy: bool,
    pub last_deploy_status: Option<String>,
    pub last_deploy_at: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateHostApplicationRequest {
    #[validate(length(min = 36, max = 36))]
    pub machine_id: String,
    #[validate(length(min = 36, max = 36))]
    pub application_id: String,
    #[validate(length(min = 36, max = 36))]
    pub tls_key_id: Option<String>,
    #[validate(length(max = 512))]
    pub cert_path: Option<String>,
    #[validate(length(max = 512))]
    pub key_path: Option<String>,
    #[validate(length(max = 512))]
    pub chain_path: Option<String>,
    #[validate(length(max = 512))]
    pub reload_command: Option<String>,
    #[validate(length(min = 36, max = 36))]
    pub credential_id: Option<String>,
    pub auto_deploy: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateHostApplicationRequest {
    #[validate(length(min = 36, max = 36))]
    pub tls_key_id: Option<String>,
    #[validate(length(max = 512))]
    pub cert_path: Option<String>,
    #[validate(length(max = 512))]
    pub key_path: Option<String>,
    #[validate(length(max = 512))]
    pub chain_path: Option<String>,
    #[validate(length(max = 512))]
    pub reload_command: Option<String>,
    #[validate(length(min = 36, max = 36))]
    pub credential_id: Option<String>,
    pub auto_deploy: Option<bool>,
}
