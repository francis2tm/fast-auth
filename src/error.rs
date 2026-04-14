use std::borrow::Cow;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use common::http_error::{ApiErrorResponse, HttpError, response_build};
use thiserror::Error;

use crate::AuthBackendError;

/// Shared auth error response body.
pub type AuthErrorResponse = ApiErrorResponse;

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

    #[error("Email not confirmed")]
    EmailNotConfirmed,

    #[error("Invalid email format")]
    InvalidEmail,

    #[error("{0}")]
    BadRequest(String),

    #[error("Password too weak: {0}")]
    WeakPassword(String),

    #[error("Refresh token not found or revoked")]
    RefreshTokenInvalid,

    #[error("API key not found")]
    ApiKeyNotFound,

    #[error("Organization not found")]
    OrganizationNotFound,

    #[error("Organization invite not found")]
    OrganizationInviteNotFound,

    #[error("Forbidden")]
    Forbidden,

    #[error("{0}")]
    InvalidListPage(String),

    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error")]
    Internal(String),

    #[error("backend error: {0}")]
    Backend(String),
}

impl AuthError {
    /// Map a backend error into an auth error without string parsing.
    pub(crate) fn from_backend<E: AuthBackendError>(error: E) -> Self {
        error.auth_error()
    }
}

impl HttpError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentials
            | Self::InvalidToken
            | Self::TokenExpired
            | Self::RefreshTokenInvalid
            | Self::Jwt(_) => StatusCode::UNAUTHORIZED,
            Self::UserAlreadyExists => StatusCode::CONFLICT,
            Self::UserNotFound
            | Self::ApiKeyNotFound
            | Self::OrganizationNotFound
            | Self::OrganizationInviteNotFound => StatusCode::NOT_FOUND,
            Self::EmailNotConfirmed | Self::Forbidden => StatusCode::FORBIDDEN,
            Self::InvalidEmail
            | Self::BadRequest(_)
            | Self::WeakPassword(_)
            | Self::InvalidListPage(_) => StatusCode::BAD_REQUEST,
            Self::PasswordHash(_) | Self::Internal(_) | Self::Backend(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn public_message(&self) -> Cow<'static, str> {
        match self {
            Self::InvalidCredentials
            | Self::InvalidToken
            | Self::TokenExpired
            | Self::UserAlreadyExists
            | Self::UserNotFound
            | Self::EmailNotConfirmed
            | Self::InvalidEmail
            | Self::BadRequest(_)
            | Self::WeakPassword(_)
            | Self::RefreshTokenInvalid
            | Self::ApiKeyNotFound
            | Self::OrganizationNotFound
            | Self::OrganizationInviteNotFound
            | Self::Forbidden
            | Self::InvalidListPage(_) => Cow::Owned(self.to_string()),
            Self::Jwt(_) => Cow::Borrowed("Invalid token"),
            Self::PasswordHash(_) | Self::Internal(_) | Self::Backend(_) => {
                Cow::Borrowed("Internal server error")
            }
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        response_build(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn response_body_extract(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(bytes.as_ref()).unwrap()
    }

    #[tokio::test]
    async fn invalid_token_returns_public_message() {
        let response = AuthError::InvalidToken.into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response_body_extract(response).await;
        assert_eq!(body["message"], "Invalid token");
    }

    #[tokio::test]
    async fn internal_error_is_sanitized() {
        let response = AuthError::Internal("boom".into()).into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_body_extract(response).await;
        assert_eq!(body["message"], "Internal server error");
    }
}
