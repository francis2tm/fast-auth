//! Handlers for password reset.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthUser, EmailSender,
    email::email_validate_normalize,
    error::AuthError,
    password::{password_hash, password_validate},
    tokens::{token_expiry_calculate, token_hash_sha256, token_with_hash_generate},
    verification::{VerificationTokenType, verification_link_build},
};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

pub const PASSWORD_PATH: &str = "/auth/password";
pub const PASSWORD_FORGOT_PATH: &str = "/auth/password/forgot";
pub const PASSWORD_RESET_PATH: &str = "/auth/password/reset";

#[derive(OpenApi)]
#[openapi(
    paths(password_forgot, password_reset),
    components(schemas(
        PasswordForgotRequest,
        PasswordForgotResponse,
        PasswordResetRequest,
        PasswordResetResponse,
        crate::error::AuthErrorResponse
    ))
)]
pub(crate) struct PasswordApi;

/// Returns routes for password reset endpoints.
pub fn password_reset_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
    Router::new()
        .route(PASSWORD_FORGOT_PATH, post(password_forgot::<B, H, E>))
        .route(PASSWORD_RESET_PATH, post(password_reset::<B, H, E>))
}

/// Request body for forgot password.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PasswordForgotRequest {
    /// User's email address.
    pub email: String,
}

/// Response for forgot password.
#[derive(Debug, Serialize, ToSchema)]
pub struct PasswordForgotResponse {
    /// Success message.
    pub message: String,
}

/// Request body for password reset.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PasswordResetRequest {
    /// Reset token from email link.
    pub token: String,
    /// New password.
    pub password: String,
}

/// Response for password reset.
#[derive(Debug, Serialize, ToSchema)]
pub struct PasswordResetResponse {
    /// Success message.
    pub message: String,
}

/// Request a password reset email.
///
/// Creates a reset token and sends an email with the reset link.
/// Always returns success to prevent email enumeration attacks.
#[utoipa::path(
    post,
    path = "/forgot",
    request_body = PasswordForgotRequest,
    responses(
        (status = OK, body = PasswordForgotResponse),
        (status = BAD_REQUEST, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
pub async fn password_forgot<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Json(req): Json<PasswordForgotRequest>,
) -> Result<Json<PasswordForgotResponse>, AuthError> {
    let config = auth.config();

    // Normalize email
    let email = email_validate_normalize(&req.email)?;

    // Find user by email
    let user = auth
        .backend()
        .user_find_by_email(&email)
        .await
        .map_err(AuthError::from_backend)?;

    // Only send if user exists
    if let Some(user) = user {
        // Generate token
        let (token, hash) = token_with_hash_generate();
        let expires_at = token_expiry_calculate(config.password_reset_token_expiry);

        // Store token
        auth.backend()
            .verification_token_issue(
                user.id(),
                &hash,
                VerificationTokenType::PasswordReset,
                expires_at,
            )
            .await
            .map_err(AuthError::from_backend)?;

        // Build reset link
        let reset_link = verification_link_build(config, PASSWORD_RESET_PATH, &token);

        // Send email
        let subject = "Reset your password";
        let expires_in_seconds = config.password_reset_token_expiry.as_secs();
        let body = format!(
            "You requested a password reset. Click this link to set a new password:\n\n{}\n\nThis link expires in {} seconds.\n\nIf you didn't request this, you can safely ignore this email.",
            reset_link, expires_in_seconds
        );

        if let Err(e) = auth.email_sender().send(&email, subject, &body).await {
            tracing::error!(error = ?e, "Failed to send password reset email");
            // Don't return error to prevent email enumeration
        }
    }

    // Always return success to prevent email enumeration
    Ok(Json(PasswordForgotResponse {
        message: "If an account exists with that email, a password reset link has been sent."
            .to_string(),
    }))
}

/// Reset password using the token from the email.
#[utoipa::path(
    post,
    path = "/reset",
    request_body = PasswordResetRequest,
    responses(
        (status = OK, body = PasswordResetResponse),
        (status = BAD_REQUEST, body = crate::error::AuthErrorResponse),
        (status = UNAUTHORIZED, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
pub async fn password_reset<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Json(req): Json<PasswordResetRequest>,
) -> Result<Json<PasswordResetResponse>, AuthError> {
    password_reset_apply(&auth, &req.token, &req.password).await?;

    Ok(Json(PasswordResetResponse {
        message: "Password reset successfully. You can now sign in with your new password."
            .to_string(),
    }))
}

/// Apply a password reset from a verification token.
///
/// This validates password strength, atomically consumes a `PasswordReset` token,
/// updates the user's password hash, and revokes all active refresh sessions.
///
/// Returns [`AuthError::InvalidToken`] when the token is invalid, expired, or already used.
async fn password_reset_apply<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    auth: &Auth<B, H, E>,
    token: &str,
    password: &str,
) -> Result<(), AuthError> {
    let config = auth.config();

    // Validate password strength
    password_validate(password, config)?;

    // Hash the token for lookup
    let hash = token_hash_sha256(token);

    // Hash the new password
    let hashed_password = password_hash(password)?;

    auth.backend()
        .password_reset_apply(&hash, &hashed_password)
        .await
        .map_err(AuthError::from_backend)?;

    Ok(())
}
