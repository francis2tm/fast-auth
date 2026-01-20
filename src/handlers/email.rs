//! Handlers for email confirmation.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthUser, EmailSender,
    email::email_validate_normalize,
    error::AuthError,
    tokens::{token_expiry_calculate, token_hash_sha256, token_with_hash_generate},
    verification::{VerificationTokenType, verification_link_build},
};
use axum::{Json, Router, extract::State, response::IntoResponse, routing::post};
use serde::{Deserialize, Serialize};

pub const EMAIL_CONFIRM_SEND_PATH: &str = "/auth/email/confirm/send";
pub const EMAIL_CONFIRM_PATH: &str = "/auth/email/confirm";

/// Returns routes for email confirmation endpoints.
pub fn email_confirm_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
    Router::new()
        .route(EMAIL_CONFIRM_SEND_PATH, post(email_confirm_send::<B, H, E>))
        .route(EMAIL_CONFIRM_PATH, post(email_confirm::<B, H, E>))
}

/// Request body for sending confirmation email.
#[derive(Debug, Deserialize)]
pub struct EmailConfirmSendRequest {
    /// User's email address.
    pub email: String,
}

/// Response for sending confirmation email.
#[derive(Debug, Serialize)]
pub struct EmailConfirmSendResponse {
    /// Success message.
    pub message: String,
}

/// Request body for confirming email.
#[derive(Debug, Deserialize)]
pub struct EmailConfirmRequest {
    /// Verification token from email link.
    pub token: String,
}

/// Response for confirming email.
#[derive(Debug, Serialize)]
pub struct EmailConfirmResponse {
    /// Success message.
    pub message: String,
}

/// Send a confirmation email to the user.
///
/// Creates a verification token and sends an email with the confirmation link.
/// Always returns success to prevent email enumeration attacks.
pub async fn email_confirm_send<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Json(req): Json<EmailConfirmSendRequest>,
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

    // Only send if user exists and email not already confirmed
    if let Some(user) = user {
        if user.email_confirmed_at().is_none() {
            // Generate token
            let (token, hash) = token_with_hash_generate();
            let expires_at = token_expiry_calculate(config.email_verification_token_expiry);

            // Store token
            auth.backend()
                .verification_token_create(
                    user.id(),
                    &hash,
                    VerificationTokenType::EmailConfirm,
                    expires_at,
                )
                .await
                .map_err(|e| AuthError::Backend(e.to_string()))?;

            // Build verification link
            let verify_link = verification_link_build(config, EMAIL_CONFIRM_PATH, &token);

            // Send email
            let subject = "Confirm your email address";
            let body = format!(
                "Please confirm your email address by clicking this link:\n\n{}\n\nThis link expires in 1 hour.",
                verify_link
            );

            if let Err(e) = auth.email_sender().send(&email, subject, &body).await {
                tracing::error!(error = ?e, "Failed to send confirmation email");
                // Don't return error to prevent email enumeration
            }
        }
    }

    // Always return success to prevent email enumeration
    Ok(Json(EmailConfirmSendResponse {
        message: "If an account exists with that email, a confirmation link has been sent."
            .to_string(),
    }))
}

/// Confirm email address using verification token.
pub async fn email_confirm<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Json(req): Json<EmailConfirmRequest>,
) -> Result<impl IntoResponse, AuthError> {
    // Hash the token for lookup
    let hash = token_hash_sha256(&req.token);

    // Consume the token
    let user_id = auth
        .backend()
        .verification_token_consume(&hash, VerificationTokenType::EmailConfirm)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .ok_or(AuthError::InvalidToken)?;

    // Mark email as confirmed
    auth.backend()
        .user_email_confirm(user_id)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    Ok(Json(EmailConfirmResponse {
        message: "Email confirmed successfully.".to_string(),
    }))
}
