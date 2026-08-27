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
