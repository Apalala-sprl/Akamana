use crate::{auth::AuthenticatedUser, deploy, models::GenerateTlsKeyRequest, AppState};
use chrono::Utc;

pub fn start(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = run_auto_renew(&state).await {
                tracing::warn!("auto-renew cycle failed: {e}");
            }
        }
    });
}

#[derive(sqlx::FromRow)]
struct RenewCandidate {
    id: String,
    machine_id: Option<String>,
    common_name: String,
    root_ca_id: i32,
    parent_cert_id: Option<String>,
    cipher: String,
    key_length: i32,
    renew_days_before: i32,
    valid_from: chrono::NaiveDateTime,
    valid_to: chrono::NaiveDateTime,
    sans_json: Option<String>,
    eku_purpose: Option<String>,
}

pub async fn run_auto_renew(state: &AppState) -> anyhow::Result<()> {
    let candidates = sqlx::query_as::<_, RenewCandidate>(
        "SELECT id, machine_id, common_name, root_ca_id, parent_cert_id, cipher, key_length, \
         renew_days_before, valid_from, valid_to, CAST(sans_json AS CHAR) AS sans_json, eku_purpose FROM tls_keys \
         WHERE auto_renew = true AND is_revoked = false AND cert_level = 'leaf' \
         AND valid_to <= DATE_ADD(NOW(), INTERVAL renew_days_before DAY) LIMIT 50",
    )
    .fetch_all(&state.pool)
    .await?;

    for c in candidates {
        if let Err(e) = renew_one(state, &c).await {
            tracing::warn!("auto-renew of cert {} failed: {e}", c.id);
        }
    }

    // Certbot-managed certificates: only auto-renew configs that have already issued
    // successfully at least once (last_not_after set), to avoid hammering rate limits.
    let certbot_due = sqlx::query_as::<_, (String,)>(
        "SELECT id FROM certbot_configs WHERE auto_renew = true AND last_not_after IS NOT NULL \
         AND last_not_after <= DATE_ADD(NOW(), INTERVAL renew_days_before DAY) LIMIT 50",
    )
    .fetch_all(&state.pool)
    .await?;
    for (id,) in certbot_due {
        if let Err(e) = deploy::run_certbot(state, &id, "system-autorenew").await {
            tracing::warn!("certbot auto-renew failed for {id}: {e:?}");
        }
    }
    Ok(())
}

async fn renew_one(state: &AppState, old: &RenewCandidate) -> anyhow::Result<()> {
    let valid_days = (old.valid_to - old.valid_from).num_days().clamp(1, 1825);
    let sans: Option<Vec<String>> = old
        .sans_json
        .as_deref()
        .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok());
    let req = GenerateTlsKeyRequest {
        machine_id: old.machine_id.clone(),
        root_id: Some(old.root_ca_id),
        cert_level: Some("leaf".to_string()),
        parent_cert_id: old.parent_cert_id.clone(),
        common_name: old.common_name.clone(),
        valid_days,
        cipher: Some(old.cipher.clone()),
        key_length: Some(old.key_length),
        sans,
        purpose: old.eku_purpose.clone(),
        publish_private_key: false,
    };
    let actor = AuthenticatedUser {
        username: "system-autorenew".to_string(),
        role: "full_admin".to_string(),
        is_token: false,
        scopes: Vec::new(),
    };
    let resp = crate::routes::api::generate_tls_key(
        axum::extract::State(state.clone()),
        actor,
        axum::Json(req),
    )
    .await
    .map_err(|e| anyhow::anyhow!("certificate generation failed: {e:?}"))?;
    let new_id = resp.0.key_id;

    sqlx::query(
        "UPDATE tls_keys SET auto_renew = true, renew_days_before = ?, last_status = 'renewed', last_status_at = ? WHERE id = ?",
    )
    .bind(old.renew_days_before)
    .bind(Utc::now().naive_utc())
    .bind(&new_id)
    .execute(&state.pool)
    .await?;

    // Re-point deployment targets from the old certificate to the freshly issued one.
    sqlx::query("UPDATE host_applications SET tls_key_id = ? WHERE tls_key_id = ?")
        .bind(&new_id)
        .bind(&old.id)
        .execute(&state.pool)
        .await?;

    sqlx::query(
        "UPDATE tls_keys SET auto_renew = false, last_status = 'superseded', last_status_at = ? WHERE id = ?",
    )
    .bind(Utc::now().naive_utc())
    .bind(&old.id)
    .execute(&state.pool)
    .await?;

    let targets = sqlx::query_as::<_, (String,)>(
        "SELECT id FROM host_applications WHERE tls_key_id = ? AND auto_deploy = true",
    )
    .bind(&new_id)
    .fetch_all(&state.pool)
    .await?;

    for (host_app_id,) in targets {
        if let Err(e) =
            deploy::run_deployment(state, &host_app_id, "auto_renew", "system-autorenew", false).await
        {
            tracing::warn!("auto-deploy after renewal failed for {host_app_id}: {e:?}");
        }
    }

    tracing::info!("auto-renewed certificate {} -> {}", old.id, new_id);
    Ok(())
}
