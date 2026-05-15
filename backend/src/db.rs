use crate::{config::Config, errors::AppError};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use chrono::Utc;
use rand_core::OsRng;
use sqlx::{mysql::MySqlPoolOptions, MySqlPool};
use uuid::Uuid;

pub async fn connect(cfg: &Config) -> Result<MySqlPool, AppError> {
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &MySqlPool) -> Result<(), AppError> {
    let migrations = [
        include_str!("../migrations/001_init.sql"),
        include_str!("../migrations/002_uix_security.sql"),
        include_str!("../migrations/003_notifications.sql"),
        include_str!("../migrations/004_root_and_publish_controls.sql"),
        include_str!("../migrations/005_siem_security.sql"),
        include_str!("../migrations/006_tls_root_scope.sql"),
        include_str!("../migrations/007_root_revocation.sql"),
        include_str!("../migrations/008_certificate_machine_optional.sql"),
        include_str!("../migrations/009_root_crypto_params.sql"),
        include_str!("../migrations/010_machine_monitoring.sql"),
    ];

    for migration_sql in migrations {
        for statement in migration_sql.split(';') {
            let trimmed = statement.trim();
            if trimmed.is_empty() {
                continue;
            }
            sqlx::query(trimmed).execute(pool).await?;
        }
    }
    Ok(())
}

pub async fn bootstrap_admin(pool: &MySqlPool, cfg: &Config) -> Result<(), AppError> {
    let existing: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(&cfg.bootstrap_admin_username)
        .fetch_optional(pool)
        .await?;

    if existing.is_some() {
        return Ok(());
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(cfg.bootstrap_admin_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("unable to hash admin password: {e}")))?
        .to_string();

    let now = Utc::now().naive_utc();
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, 'full_admin', ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&cfg.bootstrap_admin_username)
    .bind(hash)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}
