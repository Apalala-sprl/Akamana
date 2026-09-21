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
    // Une passkey remplace ici mot de passe ET second facteur : le tier
    // « Passkey » de webauthn-rs exige donc que l'authentificateur vérifie
    // l'utilisateur (PIN, biométrie) à chaque cérémonie, et ce n'est pas
    // négociable. Une clé sans PIN, ou un gestionnaire réglé pour ne rien
    // redemander, signe sans le faire : c'est de loin le refus le plus
    // fréquent, et l'utilisateur peut le corriger lui-même — on le lui dit.
    let message = match err {
        WebauthnError::UserNotVerified => {
            "Your authenticator did not verify you (no PIN or biometric check), and Akamana requires it for passkeys. Set a PIN on your security key, or enable identity verification for passkeys in your password manager, then try again."
        }
        _ => {
            "The passkey could not be verified. It may have been registered for another site address, or the challenge expired — try again."
        }
    };
    AppError::AuthMessage(message.to_string())
}

/// Décode les drapeaux de l'`authenticatorData` d'une assertion, pour le
/// journal. Octet 32 : UP (bit 0), UV (bit 2), BE (bit 3, sauvegardable),
/// BS (bit 4, sauvegardée). Diagnostic seulement — la vérification, c'est
/// webauthn-rs qui la fait.
pub fn describe_assertion(credential: &PublicKeyCredential) -> String {
    let data: &[u8] = credential.response.authenticator_data.as_ref();
    let Some(flags) = data.get(32) else {
        return "authenticator data too short".to_string();
    };
    let counter = data
        .get(33..37)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0);
    format!(
        "cred_id={} user_present={} user_verified={} backup_eligible={} backup_state={} counter={}",
        credential.id,
        flags & 0x01 != 0,
        flags & 0x04 != 0,
        flags & 0x08 != 0,
        flags & 0x10 != 0,
        counter
    )
}
