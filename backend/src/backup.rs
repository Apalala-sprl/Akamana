use crate::{errors::AppError, AppState};
use chrono::Utc;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

struct DbConn {
    host: String,
    port: String,
    user: String,
    password: String,
    database: String,
}

fn parse_db_url(url: &str) -> Option<DbConn> {
    // mysql://user:password@host:port/database
    let rest = url.strip_prefix("mysql://").or_else(|| url.strip_prefix("mariadb://"))?;
    let (userinfo, hostpart) = rest.split_once('@')?;
    let (user, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (userinfo.to_string(), String::new()),
    };
    let (hostport, database) = hostpart.split_once('/')?;
    let database = database.split(['?', '/']).next().unwrap_or(database).to_string();
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => (h.to_string(), p.to_string()),
        None => (hostport.to_string(), "3306".to_string()),
    };
    Some(DbConn {
        host,
        port,
        user,
        password,
        database,
    })
}

fn backups_dir() -> PathBuf {
    let base = std::env::var("EZKEY_DATA_DIR").unwrap_or_else(|_| "/data".to_string());
    Path::new(&base).join("backups")
}

/// High-churn tables excluded when computing the "has anything meaningful changed?"
/// signature, so growing log/journal rows don't defeat skip-if-unchanged.
const LOG_TABLES: [&str; 6] = [
    "access_logs",
    "audit_logs",
    "security_events",
    "notification_events",
    "deployment_jobs",
    "deployment_journal",
];

/// Produce a logical SQL dump of the whole database (deterministic — no date header).
/// When `ignore_logs` is set, the high-churn log tables are skipped (used for the
/// change-detection signature, not for the actual backup).
pub async fn export_dump(state: &AppState, ignore_logs: bool) -> Result<Vec<u8>, AppError> {
    let db = parse_db_url(&state.cfg.database_url)
        .ok_or_else(|| AppError::Internal("could not parse DATABASE_URL".to_string()))?;
    let mut cmd = Command::new("mariadb-dump");
    cmd.arg("--skip-dump-date")
        .arg("--single-transaction")
        .arg("--routines");
    if ignore_logs {
        for t in LOG_TABLES {
            cmd.arg(format!("--ignore-table={}.{}", db.database, t));
        }
    }
    let output = cmd
        .arg("-h")
        .arg(&db.host)
        .arg("-P")
        .arg(&db.port)
        .arg("-u")
        .arg(&db.user)
        .arg(&db.database)
        .env("MYSQL_PWD", &db.password)
        .output()
        .await
        .map_err(|e| AppError::Internal(format!("mariadb-dump failed to start: {e}")))?;
    if !output.status.success() {
        return Err(AppError::Internal(format!(
            "mariadb-dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Restore the database from an uploaded SQL dump.
pub async fn import_dump(state: &AppState, sql: &[u8]) -> Result<(), AppError> {
    let db = parse_db_url(&state.cfg.database_url)
        .ok_or_else(|| AppError::Internal("could not parse DATABASE_URL".to_string()))?;
    let mut child = Command::new("mariadb")
        .arg("-h")
        .arg(&db.host)
        .arg("-P")
        .arg(&db.port)
        .arg("-u")
        .arg(&db.user)
        .arg(&db.database)
        .env("MYSQL_PWD", &db.password)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| AppError::Internal(format!("mariadb restore failed to start: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(sql)
            .await
            .map_err(|e| AppError::Internal(format!("writing restore input failed: {e}")))?;
        stdin
            .shutdown()
            .await
            .map_err(|e| AppError::Internal(format!("closing restore input failed: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| AppError::Internal(format!("restore wait failed: {e}")))?;
    if !out.status.success() {
        return Err(AppError::Internal(format!(
            "restore failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub struct BackupFile {
    pub name: String,
    pub size_bytes: u64,
    pub created_at: String,
}

fn is_backup_file(name: &str) -> bool {
    name.starts_with("ezkey-") && (name.ends_with(".sql") || name.ends_with(".sql.ezbak"))
}

pub fn list_backups() -> Vec<BackupFile> {
    let dir = backups_dir();
    let mut items = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !is_backup_file(&name) {
                continue;
            }
            let meta = match e.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let created = meta
                .modified()
                .ok()
                .and_then(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339().into());
            items.push(BackupFile {
                name,
                size_bytes: meta.len(),
                created_at: created.unwrap_or_default(),
            });
        }
    }
    items.sort_by(|a, b| b.name.cmp(&a.name));
    items
}

/// Run a backup to the local backups dir. Skips writing when `skip_unchanged`
/// is set and the dump is byte-identical to the most recent backup. Returns the
/// Result of a backup run: the local file (None when skipped) plus the remote
/// push outcome.
#[derive(Default, serde::Serialize)]
pub struct BackupOutcome {
    pub file: Option<String>,
    pub remote: Option<String>,
    pub remote_error: Option<String>,
}

/// new file name, or None when skipped.
pub async fn run_backup(
    state: &AppState,
    skip_unchanged: bool,
    retention: usize,
) -> Result<BackupOutcome, AppError> {
    let dir = backups_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Internal(format!("cannot create backups dir: {e}")))?;
    let dump = export_dump(state, false).await?;
    // Signature excludes high-churn log tables so routine logging doesn't force a backup.
    let signature = hex(&openssl::sha::sha256(&export_dump(state, true).await?));

    if skip_unchanged {
        if let Some(latest) = list_backups().first() {
            if let Ok(prev) = std::fs::read_to_string(dir.join(format!("{}.sig", latest.name))) {
                if prev.trim() == signature {
                    return Ok(BackupOutcome::default());
                }
            }
        }
    }

    let ts = Utc::now().format("%Y%m%d%H%M%S%3f").to_string();
    // Encrypt at rest per the configured mode (passphrase or envelope), else plain SQL.
    let (name, payload) = match resolve_enc_mode(state).await? {
        ResolvedEnc::None => (format!("ezkey-{ts}.sql"), dump),
        ResolvedEnc::Passphrase(pass) => {
            let enc = crate::backup_crypto::encrypt_backup(
                &dump,
                crate::backup_crypto::EncMode::Passphrase(&pass),
                &Utc::now().to_rfc3339(),
            )?;
            (format!("ezkey-{ts}.sql.ezbak"), enc)
        }
        ResolvedEnc::Envelope(recips) => {
            let enc = crate::backup_crypto::encrypt_backup(
                &dump,
                crate::backup_crypto::EncMode::Envelope(&recips),
                &Utc::now().to_rfc3339(),
            )?;
            (format!("ezkey-{ts}.sql.ezbak"), enc)
        }
    };
    std::fs::write(dir.join(&name), &payload)
        .map_err(|e| AppError::Internal(format!("cannot write backup: {e}")))?;
    let _ = std::fs::write(dir.join(format!("{name}.sig")), &signature);

    // Rotate: keep the newest `retention` backups (and their signature sidecars).
    let keep = retention.clamp(1, 10);
    let mut all = list_backups();
    all.sort_by(|a, b| b.name.cmp(&a.name));
    for old in all.into_iter().skip(keep) {
        let _ = std::fs::remove_file(dir.join(&old.name));
        let _ = std::fs::remove_file(dir.join(format!("{}.sig", old.name)));
    }

    // Push the produced backup to the configured remote destination (if any).
    // A remote failure does not fail the run — the local copy is authoritative.
    let (remote, remote_error) = match crate::backup_remote::push_to_remote(state, &name, &payload).await {
        Ok(loc) => (loc, None),
        Err(e) => {
            tracing::warn!("remote backup push failed: {e}");
            (None, Some(e.to_string()))
        }
    };

    Ok(BackupOutcome {
        file: Some(name),
        remote,
        remote_error,
    })
}

async fn read_setting(pool: &sqlx::MySqlPool, key: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>("SELECT value_text FROM settings WHERE key_name = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|r| r.0)
}

/// Returns the configured backup passphrase (decrypted with the KEK) when
/// `backup_encryption_mode` is `passphrase`, else `None` (plain-SQL backups).
pub async fn resolve_backup_passphrase(state: &AppState) -> Result<Option<String>, AppError> {
    if read_setting(&state.pool, "backup_encryption_mode")
        .await
        .unwrap_or_default()
        != "passphrase"
    {
        return Ok(None);
    }
    match read_setting(&state.pool, "backup_passphrase_enc").await {
        Some(enc) if !enc.is_empty() => {
            let pass = crate::crypto::decrypt_secret(&state.cfg, &enc)?;
            Ok((!pass.is_empty()).then_some(pass))
        }
        _ => Ok(None),
    }
}

/// The encryption to apply to a new backup, resolved from settings.
pub enum ResolvedEnc {
    None,
    Passphrase(String),
    Envelope(Vec<crate::backup_crypto::Recipient>),
}

/// Resolves the active backup encryption mode (passphrase, envelope, or none).
pub async fn resolve_enc_mode(state: &AppState) -> Result<ResolvedEnc, AppError> {
    match read_setting(&state.pool, "backup_encryption_mode")
        .await
        .as_deref()
    {
        Some("passphrase") => match resolve_backup_passphrase(state).await? {
            Some(pass) => Ok(ResolvedEnc::Passphrase(pass)),
            None => Ok(ResolvedEnc::None),
        },
        Some("envelope") => {
            let rows = sqlx::query_as::<_, (String, String)>(
                "SELECT fingerprint_sha256, public_key_pem FROM backup_recipients WHERE is_active = TRUE",
            )
            .fetch_all(&state.pool)
            .await?;
            if rows.is_empty() {
                return Err(AppError::Validation(
                    "envelope encryption is enabled but no active recipients exist".to_string(),
                ));
            }
            let recips = rows
                .into_iter()
                .map(|(fp, pem)| crate::backup_crypto::Recipient {
                    fingerprint: fp,
                    public_key_pem: pem,
                })
                .collect();
            Ok(ResolvedEnc::Envelope(recips))
        }
        _ => Ok(ResolvedEnc::None),
    }
}

/// Restores from an uploaded backup, transparently decrypting `.ezbak`
/// containers. For passphrase backups, `passphrase` overrides the stored one;
/// for envelope backups, a recipient `private_key_pem` (with optional
/// `key_passphrase`) is required.
pub async fn restore_backup(
    state: &AppState,
    data: &[u8],
    passphrase: Option<&str>,
    private_key_pem: Option<&str>,
    key_passphrase: Option<&str>,
) -> Result<(), AppError> {
    let sql = if crate::backup_crypto::is_encrypted(data) {
        if let Some(pem) = private_key_pem.filter(|p| !p.trim().is_empty()) {
            crate::backup_crypto::decrypt_backup(
                data,
                crate::backup_crypto::Unlock::PrivateKey {
                    pem,
                    passphrase: key_passphrase.filter(|p| !p.is_empty()),
                },
            )?
        } else {
            let owned;
            let pass = match passphrase {
                Some(p) if !p.is_empty() => p,
                _ => {
                    owned = resolve_backup_passphrase(state).await?.ok_or_else(|| {
                        AppError::Validation(
                            "this backup is encrypted; a passphrase or a recipient private key is required".to_string(),
                        )
                    })?;
                    &owned
                }
            };
            crate::backup_crypto::decrypt_backup(
                data,
                crate::backup_crypto::Unlock::Passphrase(pass),
            )?
        }
    } else {
        data.to_vec()
    };
    import_dump(state, &sql).await
}

pub fn start(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let enabled = read_setting(&state.pool, "backup_enabled")
                .await
                .unwrap_or_default();
            if enabled != "true" && enabled != "1" {
                continue;
            }
            let freq = read_setting(&state.pool, "backup_frequency_hours")
                .await
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(24)
                .clamp(1, 720);
            // Pace by the newest backup's age.
            let due = match list_backups().first().and_then(|b| {
                chrono::DateTime::parse_from_rfc3339(&b.created_at).ok()
            }) {
                Some(ts) => (Utc::now() - ts.with_timezone(&Utc)).num_hours() >= freq,
                None => true,
            };
            if !due {
                continue;
            }
            let skip_unchanged = read_setting(&state.pool, "backup_skip_unchanged")
                .await
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true);
            let retention = read_setting(&state.pool, "backup_retention")
                .await
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(5);
            if let Err(e) = run_backup(&state, skip_unchanged, retention).await {
                tracing::warn!("scheduled backup failed: {e}");
            }
        }
    });
}
