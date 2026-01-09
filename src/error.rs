use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

/// Authentication and authorization errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid email format")]
    InvalidEmail,

    #[error("Password too weak: {0}")]
    WeakPassword(String),

    #[error("Refresh token not found or revoked")]
    RefreshTokenInvalid,

    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error")]
    Internal(String),

    #[error("backend error: {0}")]
    Backend(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::UserAlreadyExists => (StatusCode::CONFLICT, self.to_string()),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AuthError::InvalidEmail => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::WeakPassword(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::RefreshTokenInvalid => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::PasswordHash(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AuthError::Jwt(_) => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AuthError::Internal(ref msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AuthError::Backend(ref msg) => {
                tracing::error!("Backend error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
