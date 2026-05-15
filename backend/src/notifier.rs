use crate::AppState;
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

pub fn start(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            if let Err(e) = run_once(&state).await {
                tracing::warn!("expiration notifier failed: {e}");
            }
        }
    });
}

pub async fn run_once(state: &AppState) -> anyhow::Result<()> {
    let webhook_url = read_setting(&state.pool, "notify_webhook_url")
        .await?
        .unwrap_or_default();
    if webhook_url.trim().is_empty() {
        return Ok(());
    }

    let days_before = read_setting(&state.pool, "notify_days_before")
        .await?
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30);

    let cooldown_hours = read_setting(&state.pool, "notify_cooldown_hours")
        .await?
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(24);

    let now = Utc::now().naive_utc();
    let threshold = (Utc::now() + Duration::days(days_before)).naive_utc();

    let tls_rows = sqlx::query_as::<_, (String, String, chrono::NaiveDateTime, String)>(
        "SELECT id, common_name, valid_to, created_by FROM tls_keys WHERE is_revoked = false AND valid_to <= ?",
    )
    .bind(threshold)
    .fetch_all(&state.pool)
    .await?;

    let ssh_rows = sqlx::query_as::<_, (String, Option<String>, Option<String>, chrono::NaiveDateTime, String)>(
        "SELECT id, ssh_username, machine_name, valid_to, created_by FROM ssh_keys WHERE is_revoked = false AND valid_to <= ?",
    )
    .bind(threshold)
    .fetch_all(&state.pool)
    .await?;

    for row in tls_rows {
        if recently_sent(
            &state.pool,
            "tls",
            &row.0,
            &webhook_url,
            now - Duration::hours(cooldown_hours),
        )
        .await?
        {
            continue;
        }

        let payload = json!({
            "type": "certificate_expiration_warning",
            "cert_type": "tls",
            "cert_id": row.0,
            "name": row.1,
            "valid_to": row.2,
            "days_before": days_before,
            "created_by": row.3,
            "timestamp": Utc::now(),
        });
        send_and_record(state, "tls", &row.0, &webhook_url, payload).await?;
    }

    for row in ssh_rows {
        if recently_sent(
            &state.pool,
            "ssh",
            &row.0,
            &webhook_url,
            now - Duration::hours(cooldown_hours),
        )
        .await?
        {
            continue;
        }

        let payload = json!({
            "type": "certificate_expiration_warning",
            "cert_type": "ssh",
            "cert_id": row.0,
            "ssh_username": row.1,
            "machine_name": row.2,
            "valid_to": row.3,
            "days_before": days_before,
            "created_by": row.4,
            "timestamp": Utc::now(),
        });
        send_and_record(state, "ssh", &row.0, &webhook_url, payload).await?;
    }

    Ok(())
}

async fn send_and_record(
    state: &AppState,
    cert_type: &str,
    cert_id: &str,
    webhook_url: &str,
    payload: serde_json::Value,
) -> anyhow::Result<()> {
    let result = reqwest::Client::new()
        .post(webhook_url)
        .json(&payload)
        .send()
        .await;

    let (status, status_text) = match result {
        Ok(resp) if resp.status().is_success() => ("sent", format!("{}", resp.status())),
        Ok(resp) => ("failed", format!("{}", resp.status())),
        Err(e) => ("failed", e.to_string()),
    };

    sqlx::query(
        "INSERT INTO notification_events (id, cert_type, cert_id, channel, recipient, status, payload_json, sent_at) VALUES (?, ?, ?, 'webhook', ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(cert_type)
    .bind(cert_id)
    .bind(webhook_url)
    .bind(status)
    .bind(json!({"delivery_status": status_text, "payload": payload}).to_string())
    .bind(Utc::now().naive_utc())
    .execute(&state.pool)
    .await?;

    Ok(())
}

async fn recently_sent(
    pool: &sqlx::MySqlPool,
    cert_type: &str,
    cert_id: &str,
    recipient: &str,
    since: chrono::NaiveDateTime,
) -> anyhow::Result<bool> {
    let hit: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM notification_events WHERE cert_type = ? AND cert_id = ? AND recipient = ? AND sent_at >= ? ORDER BY sent_at DESC LIMIT 1",
    )
    .bind(cert_type)
    .bind(cert_id)
    .bind(recipient)
    .bind(since)
    .fetch_optional(pool)
    .await?;
    Ok(hit.is_some())
}

async fn read_setting(pool: &sqlx::MySqlPool, key: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value_text FROM settings WHERE key_name = ?")
            .bind(key)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}
