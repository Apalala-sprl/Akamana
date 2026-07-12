//! Off-box backup destinations: a local/mounted **path** (which transparently
//! covers NFS or SAMBA/CIFS shares mounted by the OS/container) and native
//! **SFTP** (pure-Rust via `russh`/`russh-sftp`, no system `ssh` binary).
//!
//! Security note: SFTP host-key pinning is not yet enforced (the server key is
//! accepted, mirroring `deploy.rs`). Pin the known host key before trusting an
//! untrusted network — flagged for a follow-up.

use crate::{crypto::decrypt_secret, errors::AppError, AppState};
use russh::client;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

const BACKUP_PREFIX: &str = "ezkey-";

pub enum SftpAuth {
    Password(String),
    Key {
        private_key_pem: String,
        passphrase: Option<String>,
    },
}

pub struct SftpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SftpAuth,
    pub remote_dir: String,
    pub retention: usize,
}

pub enum RemoteDest {
    None,
    Path { dir: String, retention: usize },
    Sftp(SftpConfig),
}

async fn read_setting(state: &AppState, key: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>("SELECT value_text FROM settings WHERE key_name = ?")
        .bind(key)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .map(|r| r.0)
        .filter(|s| !s.is_empty())
}

/// Resolves the configured remote destination from `settings` for a given
/// `prefix` (e.g. "backup", "crl", "deploy_html"). Secrets are KEK-decrypted.
/// Returns `RemoteDest::None` when no remote is configured.
pub async fn resolve_dest(state: &AppState, prefix: &str) -> Result<RemoteDest, AppError> {
    let k = |suffix: &str| format!("{prefix}_{suffix}");
    let retention = read_setting(state, &k("remote_retention"))
        .await
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(7)
        .clamp(1, 100);

    match read_setting(state, &k("dest_type")).await.as_deref() {
        Some("path") => {
            let dir = read_setting(state, &k("remote_path")).await.ok_or_else(|| {
                AppError::Validation("remote path is not configured".to_string())
            })?;
            Ok(RemoteDest::Path { dir, retention })
        }
        Some("sftp") => {
            let host = read_setting(state, &k("sftp_host"))
                .await
                .ok_or_else(|| AppError::Validation("SFTP host is not configured".to_string()))?;
            let port = read_setting(state, &k("sftp_port"))
                .await
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(22);
            let username = read_setting(state, &k("sftp_user"))
                .await
                .ok_or_else(|| AppError::Validation("SFTP user is not configured".to_string()))?;
            let remote_dir = read_setting(state, &k("sftp_remote_dir"))
                .await
                .unwrap_or_else(|| ".".to_string());
            let auth = match read_setting(state, &k("sftp_auth")).await.as_deref() {
                Some("key") => {
                    let enc = read_setting(state, &k("sftp_private_key_enc"))
                        .await
                        .ok_or_else(|| {
                            AppError::Validation("SFTP private key is not configured".to_string())
                        })?;
                    let private_key_pem = decrypt_secret(&state.cfg, &enc)?;
                    let passphrase = match read_setting(state, &k("sftp_passphrase_enc")).await {
                        Some(p) => Some(decrypt_secret(&state.cfg, &p)?),
                        None => None,
                    };
                    SftpAuth::Key {
                        private_key_pem,
                        passphrase,
                    }
                }
                _ => {
                    let enc = read_setting(state, &k("sftp_password_enc"))
                        .await
                        .ok_or_else(|| {
                            AppError::Validation("SFTP password is not configured".to_string())
                        })?;
                    SftpAuth::Password(decrypt_secret(&state.cfg, &enc)?)
                }
            };
            Ok(RemoteDest::Sftp(SftpConfig {
                host,
                port,
                username,
                auth,
                remote_dir,
                retention,
            }))
        }
        _ => Ok(RemoteDest::None),
    }
}

struct BackupSshHandler;

#[async_trait::async_trait]
impl client::Handler for BackupSshHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: host-key pinning (store & compare known host key from settings).
        Ok(true)
    }
}

async fn sftp_connect(cfg: &SftpConfig) -> Result<russh_sftp::client::SftpSession, AppError> {
    let config = Arc::new(client::Config::default());
    let mut handle = client::connect(config, (cfg.host.as_str(), cfg.port), BackupSshHandler)
        .await
        .map_err(|e| AppError::Internal(format!("SFTP connect failed: {e}")))?;

    let authenticated = match &cfg.auth {
        SftpAuth::Key {
            private_key_pem,
            passphrase,
        } => {
            let key = russh_keys::decode_secret_key(private_key_pem, passphrase.as_deref())
                .map_err(|e| AppError::Validation(format!("invalid SFTP private key: {e}")))?;
            handle
                .authenticate_publickey(&cfg.username, Arc::new(key))
                .await
                .map_err(|e| AppError::Internal(format!("SFTP key auth error: {e}")))?
        }
        SftpAuth::Password(pw) => handle
            .authenticate_password(&cfg.username, pw)
            .await
            .map_err(|e| AppError::Internal(format!("SFTP password auth error: {e}")))?,
    };
    if !authenticated {
        return Err(AppError::Validation(
            "SFTP authentication rejected".to_string(),
        ));
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| AppError::Internal(format!("SFTP channel open failed: {e}")))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| AppError::Internal(format!("SFTP subsystem request failed: {e}")))?;
    russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| AppError::Internal(format!("SFTP session init failed: {e}")))
}

fn join_remote(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "." {
        name.to_string()
    } else {
        format!("{}/{}", dir.trim_end_matches('/'), name)
    }
}

async fn push_sftp(cfg: &SftpConfig, filename: &str, data: &[u8]) -> Result<String, AppError> {
    let sftp = sftp_connect(cfg).await?;
    // Best-effort mkdir of the target directory.
    if !cfg.remote_dir.is_empty() && cfg.remote_dir != "." {
        let _ = sftp.create_dir(&cfg.remote_dir).await;
    }
    let path = join_remote(&cfg.remote_dir, filename);
    let mut file = sftp
        .create(&path)
        .await
        .map_err(|e| AppError::Internal(format!("SFTP create failed: {e}")))?;
    file.write_all(data)
        .await
        .map_err(|e| AppError::Internal(format!("SFTP write failed: {e}")))?;
    file.flush()
        .await
        .map_err(|e| AppError::Internal(format!("SFTP flush failed: {e}")))?;
    file.shutdown()
        .await
        .map_err(|e| AppError::Internal(format!("SFTP close failed: {e}")))?;

    // Prune old backups beyond retention.
    if let Ok(entries) = sftp.read_dir(&cfg.remote_dir).await {
        let mut names: Vec<String> = entries
            .into_iter()
            .map(|e| e.file_name())
            .filter(|n| n.starts_with(BACKUP_PREFIX) && !n.ends_with(".sig"))
            .collect();
        names.sort();
        names.reverse();
        for old in names.into_iter().skip(cfg.retention) {
            let _ = sftp.remove_file(&join_remote(&cfg.remote_dir, &old)).await;
        }
    }
    Ok(format!("sftp://{}:{}/{}", cfg.host, cfg.port, path))
}

fn push_path(dir: &str, filename: &str, data: &[u8], retention: usize) -> Result<String, AppError> {
    let base = std::path::Path::new(dir);
    std::fs::create_dir_all(base).map_err(|e| {
        AppError::Validation(format!("cannot create/access remote path '{dir}': {e}"))
    })?;
    let target = base.join(filename);
    std::fs::write(&target, data)
        .map_err(|e| AppError::Internal(format!("cannot write to remote path: {e}")))?;

    // Prune old backups beyond retention.
    if let Ok(entries) = std::fs::read_dir(base) {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(BACKUP_PREFIX) && !n.ends_with(".sig"))
            .collect();
        names.sort();
        names.reverse();
        for old in names.into_iter().skip(retention.clamp(1, 100)) {
            let _ = std::fs::remove_file(base.join(&old));
        }
    }
    Ok(target.to_string_lossy().to_string())
}

/// Pushes a produced backup file to the configured remote destination.
/// Returns a human-readable location, or `None` when no remote is configured.
pub async fn push_to_remote(
    state: &AppState,
    prefix: &str,
    filename: &str,
    data: &[u8],
) -> Result<Option<String>, AppError> {
    match resolve_dest(state, prefix).await? {
        RemoteDest::None => Ok(None),
        RemoteDest::Path { dir, retention } => {
            Ok(Some(push_path(&dir, filename, data, retention)?))
        }
        RemoteDest::Sftp(cfg) => Ok(Some(push_sftp(&cfg, filename, data).await?)),
    }
}

/// Writes and deletes a tiny probe file to verify connectivity + write access.
pub async fn test_remote(state: &AppState, prefix: &str) -> Result<String, AppError> {
    let probe = format!("{BACKUP_PREFIX}connftest.tmp");
    let payload = b"CryptoKeyMancer destination test";
    match resolve_dest(state, prefix).await? {
        RemoteDest::None => Err(AppError::Validation(
            "no remote destination configured".to_string(),
        )),
        RemoteDest::Path { dir, .. } => {
            let base = std::path::Path::new(&dir);
            std::fs::create_dir_all(base)
                .map_err(|e| AppError::Validation(format!("cannot access path '{dir}': {e}")))?;
            let t = base.join(&probe);
            std::fs::write(&t, payload)
                .map_err(|e| AppError::Validation(format!("cannot write to '{dir}': {e}")))?;
            let _ = std::fs::remove_file(&t);
            Ok(format!("path OK: {dir}"))
        }
        RemoteDest::Sftp(cfg) => {
            let sftp = sftp_connect(&cfg).await?;
            if !cfg.remote_dir.is_empty() && cfg.remote_dir != "." {
                let _ = sftp.create_dir(&cfg.remote_dir).await;
            }
            let path = join_remote(&cfg.remote_dir, &probe);
            let mut file = sftp
                .create(&path)
                .await
                .map_err(|e| AppError::Validation(format!("SFTP write test failed: {e}")))?;
            file.write_all(payload)
                .await
                .map_err(|e| AppError::Validation(format!("SFTP write test failed: {e}")))?;
            file.shutdown()
                .await
                .map_err(|e| AppError::Internal(format!("SFTP close failed: {e}")))?;
            let _ = sftp.remove_file(&path).await;
            Ok(format!(
                "sftp OK: {}@{}:{}",
                cfg.username, cfg.host, cfg.port
            ))
        }
    }
}
