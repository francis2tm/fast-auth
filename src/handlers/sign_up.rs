//! Handler for user sign-up.

use crate::{
    Auth, AuthBackend, AuthCookieResponse, AuthHooks, AuthUser, EmailSender, UserResponse,
    email::email_validate_normalize,
    error::AuthError,
    password::{password_hash, password_validate},
    tokens::token_cookies_generate,
};
use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;

pub const SIGN_UP_PATH: &str = "/auth/sign-up";

/// Returns routes for the /auth/sign-up endpoint.
pub fn sign_up_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
    Router::new().route(SIGN_UP_PATH, post(sign_up::<B, H, E>))
}

/// Request body for sign-up.
#[derive(Debug, Deserialize)]
pub struct SignUpRequest {
    /// User email address.
    pub email: String,
    /// User password (min 8 characters, must contain letter and number).
    pub password: String,
}

/// Sign up a new user.
///
/// Creates a new user account with email and password.
/// Sets access and refresh tokens as httpOnly cookies.
/// Calls the `on_sign_up` hook after successful user creation.
pub async fn sign_up<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Json(req): Json<SignUpRequest>,
) -> Result<Response, AuthError> {
    let config = auth.config();

    // Validate and normalize email (RFC 5322 compliant)
    let email = email_validate_normalize(&req.email)?;

    // Validate password strength
    password_validate(&req.password, config)?;

    // Hash password
    let hashed_password = password_hash(&req.password)?;

    // Create user via backend
    let user = auth
        .backend()
        .user_create_atomic(&email, &hashed_password)
        .await
        .map_err(|e| {
            // Check if it's a "user already exists" error
            let msg = e.to_string();
            if msg.to_lowercase().contains("already exists")
                || msg.to_lowercase().contains("duplicate")
            {
                AuthError::UserAlreadyExists
            } else {
                AuthError::Backend(msg)
            }
        })?;

    // Call the on_sign_up hook
    auth.hooks().on_sign_up(&user).await;

    // Generate tokens and cookies
    let jar = token_cookies_generate(&auth, user.id(), user.email()).await?;

    // Build response with user information
    let user_response = UserResponse {
        id: user.id().to_string(),
        email: user.email().to_owned(),
        email_confirmed_at: user.email_confirmed_at().map(|dt| dt.to_rfc3339()),
        created_at: user.created_at().to_rfc3339(),
    };

    let response_body = AuthCookieResponse {
        user: user_response,
    };

    Ok((jar, Json(response_body)).into_response())
}
