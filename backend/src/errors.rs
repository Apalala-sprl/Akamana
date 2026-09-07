use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("authentication failed")]
    Auth,
    #[error("authorization failed")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("too many requests: {0}")]
    TooManyRequests(String),
    #[error("database failure")]
    Database(#[from] sqlx::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            Self::Auth => (
                StatusCode::UNAUTHORIZED,
                "invalid or missing bearer token".to_string(),
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "insufficient permissions".to_string(),
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "resource not found".to_string()),
            Self::Validation(m) => (StatusCode::BAD_REQUEST, m),
            Self::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, m),
            Self::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database operation failed".to_string(),
            ),
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };

        (status, Json(ErrorResponse { error: msg })).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// Rend une erreur de validation SANS jamais recopier la valeur soumise.
///
/// `ValidationErrors::to_string()` sérialise les paramètres de chaque
/// contrainte avec leur `Debug`, et ces paramètres contiennent `value` :
/// exactement la donnée que l'utilisateur vient de taper. Sur `/auth/login`,
/// un mot de passe trop long revenait donc au navigateur en clair, dans le
/// corps de la réponse 400, et le bandeau d'erreur l'affichait tel quel.
///
/// Le problème n'était pas propre à la connexion : les 59 points de validation
/// de l'API partageaient ce `to_string()`, y compris ceux qui reçoivent des
/// clés privées PEM et des secrets de déploiement.
///
/// On ne garde donc que le nom du champ et la contrainte violée. Le message
/// reste actionnable — « password: length must be between 12 and 256 » dit
/// tout ce qu'il faut — sans renvoyer la donnée.
pub fn message_validation(errs: &validator::ValidationErrors) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (champ, erreurs) in errs.field_errors() {
        for err in erreurs {
            parts.push(format!("{champ}: {}", contrainte(err)));
        }
    }
    parts.sort();
    parts.dedup();
    if parts.is_empty() {
        // Jamais de repli sur to_string() : ce serait rouvrir la fuite.
        "validation failed".to_string()
    } else {
        parts.join("; ")
    }
}

fn contrainte(err: &validator::ValidationError) -> String {
    if let Some(m) = &err.message {
        return m.to_string();
    }
    // `value` est volontairement absent de ce lookup : c'est la donnée soumise.
    let param = |clef: &str| err.params.get(clef).map(|v| v.to_string());
    match err.code.as_ref() {
        "length" => match (param("min"), param("max")) {
            (Some(min), Some(max)) => format!("length must be between {min} and {max}"),
            (Some(min), None) => format!("length must be at least {min}"),
            (None, Some(max)) => format!("length must be at most {max}"),
            (None, None) => "invalid length".to_string(),
        },
        "range" => match (param("min"), param("max")) {
            (Some(min), Some(max)) => format!("must be between {min} and {max}"),
            (Some(min), None) => format!("must be at least {min}"),
            (None, Some(max)) => format!("must be at most {max}"),
            (None, None) => "out of range".to_string(),
        },
        "email" => "must be a valid email address".to_string(),
        "url" => "must be a valid URL".to_string(),
        "required" => "is required".to_string(),
        autre => autre.to_string(),
    }
}
