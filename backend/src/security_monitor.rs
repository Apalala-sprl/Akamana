use crate::AppState;
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

pub fn start(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            if let Err(e) = run_once(&state).await {
                tracing::warn!("security monitor failed: {e}");
            }
        }
    });
}

pub async fn run_once(state: &AppState) -> anyhow::Result<()> {
    let webhook_url = read_setting(&state.pool, "siem_webhook_url")
        .await?
        .or_else(|| std::env::var("SIEM_WEBHOOK_URL").ok())
        .unwrap_or_default();
    if webhook_url.trim().is_empty() {
        return Ok(());
    }

    let window_minutes = read_setting(&state.pool, "siem_bruteforce_window_minutes")
        .await?
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(10);
    let threshold = read_setting(&state.pool, "siem_bruteforce_threshold")
        .await?
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(5);
    let cooldown_minutes = read_setting(&state.pool, "siem_alert_cooldown_minutes")
        .await?
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30);

    let since = (Utc::now() - Duration::minutes(window_minutes)).naive_utc();
    let cooldown_since = (Utc::now() - Duration::minutes(cooldown_minutes)).naive_utc();

    let brute_force_hits = sqlx::query_as::<_, (String, i64, chrono::NaiveDateTime)>(
        "SELECT source_ip, COUNT(*) AS hits, MAX(created_at) AS last_seen \
         FROM access_logs \
         WHERE path = '/api/v1/auth/login' AND status_code >= 400 AND created_at >= ? \
         GROUP BY source_ip \
         HAVING COUNT(*) >= ?",
    )
    .bind(since)
    .bind(threshold)
    .fetch_all(&state.pool)
    .await?;

    for (source_ip, hits, last_seen) in brute_force_hits {
        if recently_alerted(&state.pool, "bruteforce_login", &source_ip, cooldown_since).await? {
            continue;
        }

        let payload = json!({
            "type": "security_alert",
            "event_type": "bruteforce_login",
            "severity": "high",
            "source_ip": source_ip,
            "hits": hits,
            "window_minutes": window_minutes,
            "last_seen": last_seen,
            "timestamp": Utc::now(),
        });
        send_to_siem(&webhook_url, payload.clone()).await?;
        insert_security_event(
            &state.pool,
            "bruteforce_login",
            "high",
            &source_ip,
            "",
            payload,
        )
        .await?;
    }

    let auth_attack_hits = sqlx::query_as::<_, (String, i64, chrono::NaiveDateTime)>(
        "SELECT source_ip, COUNT(*) AS hits, MAX(created_at) AS last_seen \
         FROM access_logs \
         WHERE path LIKE '/api/%' AND status_code IN (401, 403) AND created_at >= ? \
         GROUP BY source_ip \
         HAVING COUNT(*) >= ?",
    )
    .bind(since)
    .bind(threshold * 2)
    .fetch_all(&state.pool)
    .await?;

    for (source_ip, hits, last_seen) in auth_attack_hits {
        if recently_alerted(&state.pool, "auth_attack", &source_ip, cooldown_since).await? {
            continue;
        }

        let payload = json!({
            "type": "security_alert",
            "event_type": "auth_attack",
            "severity": "medium",
            "source_ip": source_ip,
            "hits": hits,
            "window_minutes": window_minutes,
            "last_seen": last_seen,
            "timestamp": Utc::now(),
        });
        send_to_siem(&webhook_url, payload.clone()).await?;
        insert_security_event(
            &state.pool,
            "auth_attack",
            "medium",
            &source_ip,
            "",
            payload,
        )
        .await?;
    }

    Ok(())
}

async fn send_to_siem(webhook_url: &str, payload: serde_json::Value) -> anyhow::Result<()> {
    let _ = reqwest::Client::new()
        .post(webhook_url)
        .json(&payload)
        .send()
        .await?;
    Ok(())
}

async fn recently_alerted(
    pool: &sqlx::MySqlPool,
    event_type: &str,
    source_ip: &str,
    since: chrono::NaiveDateTime,
) -> anyhow::Result<bool> {
    let hit: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM security_events WHERE event_type = ? AND source_ip = ? AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
    )
    .bind(event_type)
    .bind(source_ip)
    .bind(since)
    .fetch_optional(pool)
    .await?;
    Ok(hit.is_some())
}

async fn insert_security_event(
    pool: &sqlx::MySqlPool,
    event_type: &str,
    severity: &str,
    source_ip: &str,
    actor: &str,
    payload: serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO security_events (id, event_type, severity, source_ip, actor, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(event_type)
    .bind(severity)
    .bind(source_ip)
    .bind(actor)
    .bind(payload.to_string())
    .bind(Utc::now().naive_utc())
    .execute(pool)
    .await?;
    Ok(())
}

async fn read_setting(pool: &sqlx::MySqlPool, key: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value_text FROM settings WHERE key_name = ?")
            .bind(key)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}
