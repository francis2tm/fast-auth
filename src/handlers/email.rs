//! Handlers for email confirmation.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthUser, EmailSender,
    email::email_validate_normalize,
    error::AuthError,
    tokens::{token_expiry_calculate, token_hash_sha256, token_with_hash_generate},
    verification::{VerificationTokenType, verification_link_build},
};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

pub const EMAIL_CONFIRM_SEND_PATH: &str = "/auth/email/confirm/send";
pub const EMAIL_CONFIRM_PATH: &str = "/auth/email/confirm";

#[derive(OpenApi)]
#[openapi(
    paths(email_confirm_send, email_confirm_get),
    components(schemas(
        EmailConfirmSendRequest,
        EmailConfirmSendResponse,
        EmailConfirmQuery,
        EmailConfirmResponse,
        crate::error::AuthErrorResponse
    ))
)]
pub(crate) struct EmailConfirmApi;

/// Returns routes for email confirmation endpoints.
pub fn email_confirm_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
    Router::new()
        .route(EMAIL_CONFIRM_SEND_PATH, post(email_confirm_send::<B, H, E>))
        .route(EMAIL_CONFIRM_PATH, get(email_confirm_get::<B, H, E>))
}

/// Request body for sending confirmation email.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EmailConfirmSendRequest {
    /// User's email address.
    pub email: String,
}

/// Response for sending confirmation email.
#[derive(Debug, Serialize, ToSchema)]
pub struct EmailConfirmSendResponse {
    /// Success message.
    pub message: String,
}

/// Query for browser-based email confirmation links.
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct EmailConfirmQuery {
    /// Verification token from email link.
    pub token: String,
}

/// Response for confirming email.
#[derive(Debug, Serialize, ToSchema)]
pub struct EmailConfirmResponse {
    /// Success message.
    pub message: String,
}

/// Send a confirmation email to the user.
///
/// Creates a verification token and sends an email with the confirmation link.
/// Always returns success to prevent email enumeration attacks.
#[utoipa::path(
    post,
    path = "/send",
    request_body = EmailConfirmSendRequest,
    responses(
        (status = OK, body = EmailConfirmSendResponse),
        (status = BAD_REQUEST, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
pub async fn email_confirm_send<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Json(req): Json<EmailConfirmSendRequest>,
) -> Result<Json<EmailConfirmSendResponse>, AuthError> {
    let config = auth.config();

    // Normalize email
    let email = email_validate_normalize(&req.email)?;

    // Find user by email
    let user = auth
        .backend()
        .user_find_by_email(&email)
        .await
        .map_err(AuthError::from_backend)?;

    // Only send if user exists and email not already confirmed
    if let Some(user) = user {
        if user.email_confirmed_at().is_none() {
            // Generate token
            let (token, hash) = token_with_hash_generate();
            let expires_at = token_expiry_calculate(config.email_verification_token_expiry);

            // Store token
            auth.backend()
                .verification_token_issue(
                    user.id(),
                    &hash,
                    VerificationTokenType::EmailConfirm,
                    expires_at,
                )
                .await
                .map_err(AuthError::from_backend)?;

            // Build verification link
            let verify_link = verification_link_build(config, EMAIL_CONFIRM_PATH, &token);

            // Send email
            let subject = "Confirm your email address";
            let expires_in_seconds = config.email_verification_token_expiry.as_secs();
            let body = format!(
                "Please confirm your email address by clicking this link:\n\n{}\n\nThis link expires in {} seconds.",
                verify_link, expires_in_seconds
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

/// Confirm email from a browser verification link (`GET /auth/email/confirm?token=...`).
#[utoipa::path(
    get,
    path = "",
    params(EmailConfirmQuery),
    responses(
        (status = OK, body = EmailConfirmResponse),
        (status = UNAUTHORIZED, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
pub async fn email_confirm_get<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Query(req): Query<EmailConfirmQuery>,
) -> Result<Json<EmailConfirmResponse>, AuthError> {
    // Hash the token for lookup
    let hash = token_hash_sha256(&req.token);

    // Atomically consume token and confirm email.
    auth.backend()
        .email_confirm_apply(&hash)
        .await
        .map_err(AuthError::from_backend)?;

    Ok(Json(EmailConfirmResponse {
        message: "Email confirmed successfully.".to_string(),
    }))
}
