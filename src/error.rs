//! Authentication error types.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Authentication and authorization errors.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Backend database error.
    #[error("Backend error: {0}")]
    Backend(String),

    /// Invalid credentials provided.
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// Invalid or malformed token.
    #[error("Invalid token")]
    InvalidToken,

    /// Token has expired.
    #[error("Token expired")]
    TokenExpired,

    /// User with this email already exists.
    #[error("User already exists")]
    UserAlreadyExists,

    /// User not found.
    #[error("User not found")]
    UserNotFound,

    /// Invalid email format.
    #[error("Invalid email format")]
    InvalidEmail,

    /// Password doesn't meet requirements.
    #[error("Password too weak: {0}")]
    WeakPassword(String),

    /// Refresh token not found or revoked.
    #[error("Refresh token not found or revoked")]
    RefreshTokenInvalid,

    /// Password hashing error.
    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    /// JWT error.
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// Internal server error.
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl AuthError {
    /// Create a backend error from any error type.
    pub fn backend<E: std::error::Error>(err: E) -> Self {
        AuthError::Backend(err.to_string())
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::UserAlreadyExists => (StatusCode::CONFLICT, self.to_string()),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AuthError::InvalidEmail => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::WeakPassword(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::RefreshTokenInvalid => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::Backend(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AuthError::PasswordHash(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AuthError::Jwt(_) => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AuthError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
