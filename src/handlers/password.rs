//! Handlers for password reset.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthUser, EmailSender,
    email::email_validate_normalize,
    error::AuthError,
    password::{password_hash, password_validate},
    tokens::{token_expiry_calculate, token_hash_sha256, token_with_hash_generate},
    verification::{VerificationTokenType, verification_link_build},
};
use axum::{Json, Router, extract::State, response::IntoResponse, routing::post};
use serde::{Deserialize, Serialize};

pub const PASSWORD_FORGOT_PATH: &str = "/auth/password/forgot";
pub const PASSWORD_RESET_PATH: &str = "/auth/password/reset";

/// Returns routes for password reset endpoints.
pub fn password_reset_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
    Router::new()
        .route(PASSWORD_FORGOT_PATH, post(password_forgot::<B, H, E>))
        .route(PASSWORD_RESET_PATH, post(password_reset::<B, H, E>))
}

/// Request body for forgot password.
#[derive(Debug, Deserialize)]
pub struct PasswordForgotRequest {
    /// User's email address.
    pub email: String,
}

/// Response for forgot password.
#[derive(Debug, Serialize)]
pub struct PasswordForgotResponse {
    /// Success message.
    pub message: String,
}

/// Request body for password reset.
#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    /// Reset token from email link.
    pub token: String,
    /// New password.
    pub password: String,
}

/// Response for password reset.
#[derive(Debug, Serialize)]
pub struct PasswordResetResponse {
    /// Success message.
    pub message: String,
}

/// Request a password reset email.
///
/// Creates a reset token and sends an email with the reset link.
/// Always returns success to prevent email enumeration attacks.
pub async fn password_forgot<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Json(req): Json<PasswordForgotRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let config = auth.config();

    // Normalize email
    let email = email_validate_normalize(&req.email)?;

    // Find user by email
    let user = auth
        .backend()
        .user_find_by_email(&email)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    // Only send if user exists
    if let Some(user) = user {
        // Generate token
        let (token, hash) = token_with_hash_generate();
        let expires_at = token_expiry_calculate(config.password_reset_token_expiry);

        // Store token
        auth.backend()
            .verification_token_create(
                user.id(),
                &hash,
                VerificationTokenType::PasswordReset,
                expires_at,
            )
            .await
            .map_err(|e| AuthError::Backend(e.to_string()))?;

        // Build reset link
        let reset_link = verification_link_build(config, PASSWORD_RESET_PATH, &token);

        // Send email
        let subject = "Reset your password";
        let body = format!(
            "You requested a password reset. Click this link to set a new password:\n\n{}\n\nThis link expires in 1 hour.\n\nIf you didn't request this, you can safely ignore this email.",
            reset_link
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
pub async fn password_reset<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Json(req): Json<PasswordResetRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let config = auth.config();

    // Validate password strength
    password_validate(&req.password, config)?;

    // Hash the token for lookup
    let hash = token_hash_sha256(&req.token);

    // Consume the token
    let user_id = auth
        .backend()
        .verification_token_consume(&hash, VerificationTokenType::PasswordReset)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .ok_or(AuthError::InvalidToken)?;

    // Hash the new password
    let hashed_password = password_hash(&req.password)?;

    // Update password
    auth.backend()
        .user_password_update(user_id, &hashed_password)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    Ok(Json(PasswordResetResponse {
        message: "Password reset successfully. You can now sign in with your new password."
            .to_string(),
    }))
}
