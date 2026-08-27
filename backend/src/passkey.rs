//! WebAuthn (passkey) support.
//!
//! Passkeys are **opt-in**: a relying-party id and origin cannot be guessed
//! safely, and WebAuthn only works over HTTPS (or `localhost`), so the feature
//! stays off until an operator sets `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN`. Every
//! entry point calls [`instance`], which returns a `Validation` error carrying
//! setup instructions when the feature is not configured.

use crate::errors::{AppError, AppResult};
use webauthn_rs::prelude::*;

/// True when the operator has configured the relying party. Used to tell the
/// UI whether to offer "Sign in with a passkey" at all.
pub fn is_enabled() -> bool {
    read_env("WEBAUTHN_RP_ID").is_some() && read_env("WEBAUTHN_ORIGIN").is_some()
}

fn read_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Builds the relying party. Cheap enough to construct per request (it only
/// parses the configured origin), and doing so means a config change takes
/// effect on restart without extra wiring in `AppState`.
pub fn instance() -> AppResult<Webauthn> {
    let rp_id = read_env("WEBAUTHN_RP_ID").ok_or_else(|| {
        AppError::Validation(
            "Passkeys are not enabled on this server. Set WEBAUTHN_RP_ID (the site domain, e.g. akamana.example.com) and WEBAUTHN_ORIGIN (e.g. https://akamana.example.com), then restart."
                .to_string(),
        )
    })?;
    let origin_raw = read_env("WEBAUTHN_ORIGIN").ok_or_else(|| {
        AppError::Validation(
            "Passkeys are not enabled on this server: WEBAUTHN_ORIGIN is not set.".to_string(),
        )
    })?;

    let origin = Url::parse(&origin_raw).map_err(|e| {
        AppError::Internal(format!(
            "WEBAUTHN_ORIGIN is not a valid URL ({origin_raw}): {e}"
        ))
    })?;

    let builder = WebauthnBuilder::new(&rp_id, &origin)
        .map_err(|e| AppError::Internal(format!("WebAuthn relying party setup failed: {e}")))?;

    builder
        .rp_name("Akamana")
        .build()
        .map_err(|e| AppError::Internal(format!("WebAuthn relying party build failed: {e}")))
}

/// WebAuthn ceremonies fail for plenty of benign reasons (user cancelled, wrong
/// authenticator, replayed challenge). Surface them as authentication failures
/// rather than 500s, and keep the library's detail in the log only.
pub fn ceremony_error(context: &str, err: WebauthnError) -> AppError {
    tracing::warn!("webauthn_{context}_failed: {err}");
    AppError::Auth
}
