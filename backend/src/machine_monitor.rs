use crate::AppState;
use anyhow::anyhow;
use chrono::{Duration, NaiveDateTime, Utc};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use openssl::asn1::Asn1TimeRef;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::{X509NameRef, X509Ref};
use serde_json::json;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration as StdDuration;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct MonitorTargetRow {
    id: String,
    machine_id: String,
    hostname: String,
    ip_address: String,
    port: i32,
    sni_host: String,
}

#[derive(Clone)]
struct TlsScanOutcome {
    status: String,
    error: Option<String>,
    not_before: Option<NaiveDateTime>,
    not_after: Option<NaiveDateTime>,
    subject: Option<String>,
    issuer: Option<String>,
    serial_hex: Option<String>,
    chain_json: serde_json::Value,
    tls_support: serde_json::Value,
    diagnostic: String,
}

pub fn start(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = run_due_checks(&state).await {
                tracing::warn!("machine monitor failed: {e}");
            }
        }
    });
}

pub async fn run_due_checks(state: &AppState) -> anyhow::Result<()> {
    let enabled = read_setting(&state.pool, "machine_monitor_enabled")
        .await?
        .unwrap_or_else(|| "true".to_string());
    if enabled != "true" && enabled != "1" {
        return Ok(());
    }

    let freq_hours = read_setting(&state.pool, "machine_monitor_frequency_hours")
        .await?
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(24)
        .clamp(1, 168);
    let due_before = (Utc::now() - Duration::hours(freq_hours)).naive_utc();

    let rows = sqlx::query_as::<_, MonitorTargetRow>(
        "SELECT mp.id, mp.machine_id, m.hostname, m.ip_address, mp.port, mp.sni_host \
         FROM machine_monitor_ports mp \
         JOIN machines m ON m.id = mp.machine_id \
         WHERE mp.monitor_enabled = true AND (mp.last_checked_at IS NULL OR mp.last_checked_at <= ?) \
         ORDER BY mp.updated_at ASC \
         LIMIT 100",
    )
    .bind(due_before)
    .fetch_all(&state.pool)
    .await?;

    for row in rows {
        if let Err(e) = scan_target_row(state, &row, true).await {
            tracing::warn!("machine monitor scan failed for {}:{}: {e}", row.hostname, row.port);
        }
    }

    Ok(())
}

pub async fn run_all_checks(state: &AppState) -> anyhow::Result<()> {
    let rows = sqlx::query_as::<_, MonitorTargetRow>(
        "SELECT mp.id, mp.machine_id, m.hostname, m.ip_address, mp.port, mp.sni_host \
         FROM machine_monitor_ports mp \
         JOIN machines m ON m.id = mp.machine_id \
         WHERE mp.monitor_enabled = true \
         ORDER BY m.hostname ASC, mp.port ASC \
         LIMIT 500",
    )
    .fetch_all(&state.pool)
    .await?;
    for row in rows {
        if let Err(e) = scan_target_row(state, &row, true).await {
            tracing::warn!("machine monitor scan failed for {}:{}: {e}", row.hostname, row.port);
        }
    }
    Ok(())
}

pub async fn scan_and_store(
    state: &AppState,
    monitor_port_id: &str,
    trigger_alerts: bool,
) -> anyhow::Result<serde_json::Value> {
    let row: Option<MonitorTargetRow> = sqlx::query_as(
        "SELECT mp.id, mp.machine_id, m.hostname, m.ip_address, mp.port, mp.sni_host \
         FROM machine_monitor_ports mp \
         JOIN machines m ON m.id = mp.machine_id \
         WHERE mp.id = ?",
    )
    .bind(monitor_port_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = row else {
        return Err(anyhow!("monitor port not found"));
    };
    scan_target_row(state, &row, trigger_alerts).await
}

async fn scan_target_row(
    state: &AppState,
    row: &MonitorTargetRow,
    trigger_alerts: bool,
) -> anyhow::Result<serde_json::Value> {
    let target_host = if row.ip_address.trim().is_empty() {
        row.hostname.clone()
    } else {
        row.ip_address.clone()
    };
    let sni_host = if row.sni_host.trim().is_empty() {
        row.hostname.clone()
    } else {
        row.sni_host.clone()
    };
    let port = row.port;
    let scan = tokio::task::spawn_blocking(move || scan_tls_port(&target_host, &sni_host, port))
        .await
        .map_err(|e| anyhow!("scan task join failed: {e}"))?;

    let outcome = match scan {
        Ok(v) => v,
        Err(e) => TlsScanOutcome {
            status: "error".to_string(),
            error: Some(e.to_string()),
            not_before: None,
            not_after: None,
            subject: None,
            issuer: None,
            serial_hex: None,
            chain_json: json!([]),
            tls_support: json!([]),
            diagnostic: format!("Unable to query TLS certificate: {e}"),
        },
    };

    sqlx::query(
        "UPDATE machine_monitor_ports \
         SET last_checked_at = ?, last_status = ?, last_error = ?, cert_not_before = ?, cert_not_after = ?, cert_subject = ?, cert_issuer = ?, cert_serial_hex = ?, cert_chain_json = ?, tls_support_json = ?, cert_diagnostic = ?, updated_at = ? \
         WHERE id = ?",
    )
    .bind(Utc::now().naive_utc())
    .bind(&outcome.status)
    .bind(outcome.error.clone())
    .bind(outcome.not_before)
    .bind(outcome.not_after)
    .bind(outcome.subject.clone())
    .bind(outcome.issuer.clone())
    .bind(outcome.serial_hex.clone())
    .bind(outcome.chain_json.to_string())
    .bind(outcome.tls_support.to_string())
    .bind(outcome.diagnostic.clone())
    .bind(Utc::now().naive_utc())
    .bind(&row.id)
    .execute(&state.pool)
    .await?;

    if trigger_alerts {
        maybe_send_alert(state, row, &outcome).await?;
    }

    Ok(json!({
        "monitor_port_id": row.id,
        "machine_id": row.machine_id,
        "hostname": row.hostname,
        "ip_address": row.ip_address,
        "port": row.port,
        "sni_host": row.sni_host,
        "status": outcome.status,
        "error": outcome.error,
        "diagnostic": outcome.diagnostic,
        "cert_not_after": outcome.not_after,
        "cert_chain": outcome.chain_json,
        "tls_support": outcome.tls_support,
    }))
}

fn scan_tls_port(host: &str, sni_host: &str, port: i32) -> anyhow::Result<TlsScanOutcome> {
    let socket = format!("{host}:{port}");
    let addr = socket
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("unable to resolve target"))?;
    let tcp = TcpStream::connect_timeout(&addr, StdDuration::from_secs(8))?;
    tcp.set_read_timeout(Some(StdDuration::from_secs(8)))?;
    tcp.set_write_timeout(Some(StdDuration::from_secs(8)))?;

    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let ssl_stream = connector.connect(sni_host, tcp)?;
    let ssl = ssl_stream.ssl();
    let leaf = ssl
        .peer_certificate()
        .ok_or_else(|| anyhow!("peer did not provide a certificate"))?;

    let not_before = parse_asn1_datetime(leaf.not_before());
    let not_after = parse_asn1_datetime(leaf.not_after());
    let subject = x509_name_to_string(leaf.subject_name());
    let issuer = x509_name_to_string(leaf.issuer_name());
    let serial_hex = leaf.serial_number().to_bn()?.to_hex_str()?.to_string();
    let mut chain = vec![cert_to_json(&leaf)];

    if let Some(extra) = ssl.peer_cert_chain() {
        for cert in extra {
            chain.push(cert_to_json(cert));
        }
    }

    let now = Utc::now().naive_utc();
    let days = not_after.map(|d| (d - now).num_days()).unwrap_or(0);
    let status = if let Some(not_after) = not_after {
        if not_after < now {
            "expired"
        } else if days <= 7 {
            "warning"
        } else {
            "ok"
        }
    } else {
        "error"
    };

    let tls_version = ssl.version_str().to_string();
    let cipher_name = ssl
        .current_cipher()
        .map(|c| c.name().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let diagnostic = if status == "expired" {
        format!("Certificate expired {} day(s) ago. TLS {tls_version}, cipher {cipher_name}.", days.abs())
    } else if status == "warning" {
        format!("Certificate expires in {days} day(s). TLS {tls_version}, cipher {cipher_name}.")
    } else if status == "ok" {
        format!("Certificate healthy ({days} day(s) remaining). TLS {tls_version}, cipher {cipher_name}.")
    } else {
        "Unable to evaluate certificate validity dates.".to_string()
    };

    Ok(TlsScanOutcome {
        status: status.to_string(),
        error: None,
        not_before,
        not_after,
        subject: Some(subject),
        issuer: Some(issuer),
        serial_hex: Some(serial_hex),
        chain_json: json!(chain),
        tls_support: enumerate_tls_support(host, sni_host, port),
        diagnostic,
    })
}

/// Probe each TLS protocol version and record the cipher the server negotiates,
/// giving operators the list of protocols/ciphers the server actually accepts.
fn enumerate_tls_support(host: &str, sni_host: &str, port: i32) -> serde_json::Value {
    use openssl::ssl::SslVersion;
    let versions = [
        (SslVersion::TLS1, "TLSv1.0"),
        (SslVersion::TLS1_1, "TLSv1.1"),
        (SslVersion::TLS1_2, "TLSv1.2"),
        (SslVersion::TLS1_3, "TLSv1.3"),
    ];
    let socket = format!("{host}:{port}");
    let mut out = Vec::new();
    for (ver, label) in versions {
        let addr = match socket.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(a) => a,
            None => continue,
        };
        let tcp = match TcpStream::connect_timeout(&addr, StdDuration::from_secs(5)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let _ = tcp.set_read_timeout(Some(StdDuration::from_secs(5)));
        let _ = tcp.set_write_timeout(Some(StdDuration::from_secs(5)));
        let mut builder = match SslConnector::builder(SslMethod::tls()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        builder.set_verify(SslVerifyMode::NONE);
        let _ = builder.set_min_proto_version(Some(ver));
        let _ = builder.set_max_proto_version(Some(ver));
        let connector = builder.build();
        if let Ok(stream) = connector.connect(sni_host, tcp) {
            let cipher = stream
                .ssl()
                .current_cipher()
                .map(|c| c.name().to_string())
                .unwrap_or_default();
            out.push(json!({ "protocol": label, "cipher": cipher, "supported": true }));
        }
    }
    json!(out)
}

fn cert_to_json(cert: &X509Ref) -> serde_json::Value {
    let subject_alt_names = cert
        .subject_alt_names()
        .map(|sans| {
            sans.iter()
                .filter_map(|san| {
                    if let Some(d) = san.dnsname() {
                        Some(d.to_string())
                    } else {
                        san.ipaddress().map(|ip| match ip.len() {
                            4 => std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
                            16 => {
                                let mut octets = [0u8; 16];
                                octets.copy_from_slice(ip);
                                std::net::Ipv6Addr::from(octets).to_string()
                            }
                            _ => String::new(),
                        })
                    }
                })
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "subject": x509_name_to_string(cert.subject_name()),
        "issuer": x509_name_to_string(cert.issuer_name()),
        "serial_hex": cert.serial_number().to_bn().ok().and_then(|n| n.to_hex_str().ok().map(|s| s.to_string())).unwrap_or_default(),
        "not_before": parse_asn1_datetime(cert.not_before()),
        "not_after": parse_asn1_datetime(cert.not_after()),
        "signature_algorithm": cert.signature_algorithm().object().nid().long_name().unwrap_or("unknown"),
        "subject_alt_names": subject_alt_names,
    })
}

fn x509_name_to_string(name: &X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let key = entry.object().nid().short_name().unwrap_or("?");
        let value = entry
            .data()
            .as_utf8()
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "<binary>".to_string());
        parts.push(format!("{key}={value}"));
    }
    parts.join(", ")
}

fn parse_asn1_datetime(v: &Asn1TimeRef) -> Option<NaiveDateTime> {
    let text = v.to_string();
    NaiveDateTime::parse_from_str(&text, "%b %e %H:%M:%S %Y GMT").ok()
}

async fn maybe_send_alert(
    state: &AppState,
    row: &MonitorTargetRow,
    outcome: &TlsScanOutcome,
) -> anyhow::Result<()> {
    if !matches!(outcome.status.as_str(), "warning" | "expired" | "error") {
        return Ok(());
    }

    // Reachability cross-check: a bare connection error may be our own network, not the
    // target's. Only suppress for connectivity errors (not cert expiry, where TLS succeeded).
    if outcome.status == "error" && !any_other_host_reachable(state, &row.machine_id).await {
        tracing::warn!(
            "suppressing alert for {}:{} — no other monitored host is reachable, likely a local network issue",
            row.hostname,
            row.port
        );
        return Ok(());
    }

    let webhook_url = read_setting(&state.pool, "machine_monitor_alert_webhook_url")
        .await?
        .unwrap_or_default();
    let email_to = resolve_alert_recipient(state, &row.machine_id).await?;
    let cooldown_hours = read_setting(&state.pool, "machine_monitor_alert_cooldown_hours")
        .await?
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(24)
        .clamp(1, 168);
    let since = (Utc::now() - Duration::hours(cooldown_hours)).naive_utc();

    let payload = json!({
        "type": "machine_certificate_alert",
        "status": outcome.status,
        "monitor_port_id": row.id,
        "machine_id": row.machine_id,
        "hostname": row.hostname,
        "ip_address": row.ip_address,
        "port": row.port,
        "diagnostic": outcome.diagnostic,
        "cert_not_after": outcome.not_after,
        "cert_subject": outcome.subject,
        "cert_issuer": outcome.issuer,
        "chain": outcome.chain_json,
        "timestamp": Utc::now(),
    });

    if !webhook_url.trim().is_empty()
        && !recently_sent(&state.pool, &row.id, &webhook_url, since).await?
    {
        let result = reqwest::Client::new().post(&webhook_url).json(&payload).send().await;
        let status = match result {
            Ok(resp) if resp.status().is_success() => "sent",
            _ => "failed",
        };
        record_notification(
            &state.pool,
            &row.id,
            "webhook",
            &webhook_url,
            status,
            payload.clone(),
        )
        .await?;
    }

    if !email_to.trim().is_empty()
        && !recently_sent(&state.pool, &row.id, &email_to, since).await?
    {
        let status = if send_email_alert(&email_to, &payload).await.is_ok() {
            "sent"
        } else {
            "failed"
        };
        record_notification(
            &state.pool,
            &row.id,
            "email",
            &email_to,
            status,
            payload.clone(),
        )
        .await?;
    }

    Ok(())
}

async fn send_email_alert(recipient_csv: &str, payload: &serde_json::Value) -> anyhow::Result<()> {
    let smtp_host = std::env::var("SMTP_HOST").map_err(|_| anyhow!("SMTP_HOST is not set"))?;
    let smtp_from = std::env::var("SMTP_FROM").map_err(|_| anyhow!("SMTP_FROM is not set"))?;
    let smtp_port = std::env::var("SMTP_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(587);
    let smtp_user = std::env::var("SMTP_USERNAME").unwrap_or_default();
    let smtp_pass = std::env::var("SMTP_PASSWORD").unwrap_or_default();

    let mut builder = Message::builder().from(smtp_from.parse()?);
    for recipient in recipient_csv.split(',').map(|v| v.trim()).filter(|v| !v.is_empty()) {
        builder = builder.to(recipient.parse()?);
    }

    let status = payload
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("warning");
    let host = payload
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-host");
    let port = payload.get("port").and_then(|v| v.as_i64()).unwrap_or_default();
    let message = builder
        .subject(format!("[EZKey] TLS alert ({status}) {host}:{port}"))
        .body(serde_json::to_string_pretty(payload)?)?;

    let mut transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp_host)?
        .port(smtp_port);
    if !smtp_user.is_empty() {
        transport = transport.credentials(Credentials::new(smtp_user, smtp_pass));
    }
    let mailer = transport.build();
    let _ = mailer.send(message).await?;
    Ok(())
}

async fn recently_sent(
    pool: &sqlx::MySqlPool,
    monitor_port_id: &str,
    recipient: &str,
    since: NaiveDateTime,
) -> anyhow::Result<bool> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM notification_events WHERE cert_type = 'machine_port' AND cert_id = ? AND recipient = ? AND sent_at >= ? ORDER BY sent_at DESC LIMIT 1",
    )
    .bind(monitor_port_id)
    .bind(recipient)
    .bind(since)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

async fn record_notification(
    pool: &sqlx::MySqlPool,
    monitor_port_id: &str,
    channel: &str,
    recipient: &str,
    status: &str,
    payload: serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO notification_events (id, cert_type, cert_id, channel, recipient, status, payload_json, sent_at) VALUES (?, 'machine_port', ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(monitor_port_id)
    .bind(channel)
    .bind(recipient)
    .bind(status)
    .bind(payload.to_string())
    .bind(Utc::now().naive_utc())
    .execute(pool)
    .await?;
    Ok(())
}

async fn resolve_alert_recipient(state: &AppState, machine_id: &str) -> anyhow::Result<String> {
    let host_email: Option<(Option<String>,)> =
        sqlx::query_as("SELECT alert_email FROM machines WHERE id = ?")
            .bind(machine_id)
            .fetch_optional(&state.pool)
            .await?;
    if let Some((Some(addr),)) = host_email {
        if !addr.trim().is_empty() {
            return Ok(addr);
        }
    }
    let global = read_setting(&state.pool, "machine_monitor_alert_email_to")
        .await?
        .unwrap_or_default();
    if !global.trim().is_empty() {
        return Ok(global);
    }
    Ok(read_setting(&state.pool, "default_alert_email")
        .await?
        .unwrap_or_default())
}

async fn any_other_host_reachable(state: &AppState, current_machine_id: &str) -> bool {
    let rows = sqlx::query_as::<_, (String, i32)>(
        "SELECT m.ip_address, mp.port FROM machine_monitor_ports mp \
         JOIN machines m ON m.id = mp.machine_id \
         WHERE mp.monitor_enabled = true AND mp.machine_id <> ? LIMIT 5",
    )
    .bind(current_machine_id)
    .fetch_all(&state.pool)
    .await;

    let Ok(rows) = rows else {
        // If we cannot evaluate peers, do not suppress the alert.
        return true;
    };
    if rows.is_empty() {
        // No peers to compare against; do not suppress.
        return true;
    }

    for (ip, port) in rows {
        let target = format!("{ip}:{port}");
        let reachable = tokio::task::spawn_blocking(move || {
            target
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| TcpStream::connect_timeout(&addr, StdDuration::from_secs(5)).is_ok())
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if reachable {
            return true;
        }
    }
    false
}

async fn read_setting(pool: &sqlx::MySqlPool, key: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value_text FROM settings WHERE key_name = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0))
}
