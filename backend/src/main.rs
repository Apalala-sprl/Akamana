mod addons;
mod auth;
mod backup;
mod backup_crypto;
mod backup_remote;
mod config;
mod crypto;
mod db;
mod deploy;
mod errors;
mod lifecycle;
mod machine_monitor;
mod mfa;
mod models;
mod notifier;
mod passkey;
mod routes;
mod security_monitor;

use crate::{config::Config, errors::AppError};
use axum::{
    extract::Request,
    middleware::{from_fn_with_state, Next},
    response::Response,
    Router,
};
use chrono::Utc;
use sqlx::MySqlPool;

use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Config,
    pub pool: MySqlPool,
}

/// The caller's IP as resolved by [`auth_guard`] (honouring `x-forwarded-for`
/// only from a trusted proxy). Inserted as a request extension so handlers that
/// need it — the login rate limiter, password-reset auditing — don't each have
/// to redo the proxy-header dance.
#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

const HSTS_VALUE: &str = "max-age=31536000; includeSubDomains; preload";
const XCTO_VALUE: &str = "nosniff";
const XFO_VALUE: &str = "DENY";
const XXP_VALUE: &str = "1; mode=block";
const RP_VALUE: &str = "strict-origin-when-cross-origin";
const PP_VALUE: &str = "camera=(), microphone=(), geolocation=(), interest-cohort=()";
const CSP_VALUE: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'";

async fn security_headers_layer(
    _state: axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static(HSTS_VALUE),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static(XCTO_VALUE),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static(XFO_VALUE),
    );
    headers.insert(
        axum::http::header::X_XSS_PROTECTION,
        axum::http::HeaderValue::from_static(XXP_VALUE),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static(RP_VALUE),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("permissions-policy"),
        axum::http::HeaderValue::from_static(PP_VALUE),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(CSP_VALUE),
    );
    res
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,sqlx=warn".to_string()))
        .init();

    let cfg = Config::from_env()?;
    let pool = db::connect(&cfg).await?;
    db::run_migrations(&pool).await?;
    db::bootstrap_admin(&pool, &cfg).await?;
    db::seed_applications(&pool).await?;
    crypto::ensure_root_ca(&pool, &cfg).await?;
    crypto::ensure_ssh_cas(&pool, &cfg).await?;

    let state = AppState {
        cfg: cfg.clone(),
        pool,
    };
    notifier::start(state.clone());
    machine_monitor::start(state.clone());
    security_monitor::start(state.clone());
    lifecycle::start(state.clone());
    backup::start(state.clone());
    let allowed_origins = state.cfg.allowed_origins.clone();
    let cors = if allowed_origins.iter().any(|o| o == "*") {
        tracing::warn!("CORS is configured to allow any origin (*). This is insecure for production. Set ALLOWED_ORIGINS to specific domains.");
        CorsLayer::permissive()
    } else {
        let origins: Vec<axum::http::HeaderValue> = allowed_origins
            .iter()
            .filter_map(|origin| axum::http::HeaderValue::try_from(origin.as_str()).ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_credentials(true)
    };

    let app = Router::new()
        .merge(routes::api::router())
        .layer(from_fn_with_state(state.clone(), auth_guard))
        .nest_service(
            "/",
            ServeDir::new("/app/web").append_index_html_on_directories(true),
        )
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers_layer,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    info!("{} listening on {}", cfg.app_title, cfg.bind_addr);
    // `into_make_service_with_connect_info` is what puts the peer address in the
    // request extensions; without it `auth_guard` could never resolve a client
    // IP (every access-log row said "unknown") and the login rate limiter would
    // have nothing to key on.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn auth_guard(
    axum::extract::State(state): axum::extract::State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let request_id = Uuid::new_v4().to_string();
    req.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-request-id"),
        axum::http::header::HeaderValue::from_str(&request_id)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("unknown")),
    );

    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    let direct_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let forwarded_for = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());

    let source_ip = state.cfg.resolved_client_ip(forwarded_for, &direct_ip);
    req.extensions_mut().insert(ClientIp(source_ip.clone()));

    if !path.starts_with("/api/") {
        return Ok(next.run(req).await);
    }

    let mut actor = "anonymous".to_string();

    // Endpoints reachable without a bearer token. Everything under
    // `/api/v1/auth/` is part of signing in (password step, second-factor step,
    // passkey ceremony, password reset) and is guarded by its own credentials —
    // a password, a short-lived MFA token, or a single-use reset token.
    if path == "/health"
        || path.starts_with("/api/v1/auth/")
        || (path == "/api/v1/openapi.json" && method == "GET")
        || (path == "/api/v1/branding" && method == "GET")
        || (path == "/api/v1/certificates/root" && method == "GET")
        || path.starts_with("/api/v1/certificates/root/download/")
    {
        let response = next.run(req).await;
        log_access(
            &state.pool,
            &actor,
            &source_ip,
            &method,
            &path,
            response.status().as_u16() as i32,
            &request_id,
        )
        .await;
        return Ok(response);
    }

    let auth_value = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Auth)?;
    let token = auth_value.strip_prefix("Bearer ").ok_or(AppError::Auth)?;
    let user = auth::authenticate(&state, token, &source_ip, true).await?;
    actor = user.username;

    let response = next.run(req).await;
    log_access(
        &state.pool,
        &actor,
        &source_ip,
        &method,
        &path,
        response.status().as_u16() as i32,
        &request_id,
    )
    .await;

    Ok(response)
}

async fn log_access(
    pool: &MySqlPool,
    actor: &str,
    source_ip: &str,
    method: &str,
    path: &str,
    status_code: i32,
    request_id: &str,
) {
    if let Err(e) = sqlx::query(
        "INSERT INTO access_logs (id, actor, source_ip, method, path, status_code, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(request_id)
    .bind(actor)
    .bind(source_ip)
    .bind(method)
    .bind(path)
    .bind(status_code)
    .bind("{}")
    .bind(Utc::now().naive_utc())
    .execute(pool)
    .await
    {
        tracing::error!(
            "access_log_insert_failed: actor={} ip={} path={} status={} error={}",
            actor,
            source_ip,
            path,
            status_code,
            e
        );
    }
}
