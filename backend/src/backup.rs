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

pub fn list_backups() -> Vec<BackupFile> {
    let dir = backups_dir();
    let mut items = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with("ezkey-") || !name.ends_with(".sql") {
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
/// new file name, or None when skipped.
pub async fn run_backup(state: &AppState, skip_unchanged: bool, retention: usize) -> Result<Option<String>, AppError> {
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
                    return Ok(None);
                }
            }
        }
    }

    let name = format!("ezkey-{}.sql", Utc::now().format("%Y%m%d%H%M%S%3f"));
    std::fs::write(dir.join(&name), &dump)
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
    Ok(Some(name))
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
