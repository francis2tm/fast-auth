//! Handler for user sign-in.

use crate::{
    Auth, AuthBackend, AuthCookieResponse, AuthHooks, AuthUser, EmailSender, UserResponse,
    cookies::{access_token_cookie_create, refresh_token_cookie_create},
    email::email_validate_normalize,
    error::AuthError,
    password::password_verify,
    tokens::{access_token_generate, token_expiry_calculate, token_with_hash_generate},
};
use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;

pub const SIGN_IN_PATH: &str = "/auth/sign-in";

/// Returns routes for the /auth/sign-in endpoint.
pub fn sign_in_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
    Router::new().route(SIGN_IN_PATH, post(sign_in::<B, H, E>))
}

/// Request body for sign-in.
#[derive(Debug, Deserialize)]
pub struct SignInRequest {
    /// User email address.
    pub email: String,
    /// User password.
    pub password: String,
}

/// Sign in an existing user.
///
/// Authenticates user with email and password.
/// Sets access and refresh tokens as httpOnly cookies.
/// Returns `EmailNotConfirmed` when `require_email_confirmation` is enabled and the user has not
/// confirmed their email.
/// Calls the `on_sign_in` hook after successful authentication.
pub async fn sign_in<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    Json(req): Json<SignInRequest>,
) -> Result<Response, AuthError> {
    let config = auth.config();

    // Normalize email for consistent lookup
    let email = email_validate_normalize(&req.email)?;

    // Find user by normalized email
    let user = auth
        .backend()
        .user_find_by_email(&email)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .ok_or(AuthError::InvalidCredentials)?;

    // Verify password (constant-time comparison)
    let password_valid = password_verify(&req.password, user.password_hash())?;

    if !password_valid {
        return Err(AuthError::InvalidCredentials);
    }

    // Check email confirmation if required
    if config.require_email_confirmation && user.email_confirmed_at().is_none() {
        return Err(AuthError::EmailNotConfirmed);
    }

    let access_token = access_token_generate(user.id(), user.email().to_owned(), config)?;
    let (refresh_token, refresh_token_hash) = token_with_hash_generate();
    let refresh_token_expiry = token_expiry_calculate(config.refresh_token_expiry);

    let sign_in_applied = auth
        .backend()
        .refresh_token_rotate_if_password_hash_atomic(
            user.id(),
            user.password_hash(),
            &refresh_token_hash,
            refresh_token_expiry,
        )
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    if !sign_in_applied {
        return Err(AuthError::InvalidCredentials);
    }

    // Call the on_sign_in hook only after session issuance succeeds.
    auth.hooks().on_sign_in(&user).await;

    let jar = axum_extra::extract::cookie::CookieJar::new()
        .add(access_token_cookie_create(access_token, config))
        .add(refresh_token_cookie_create(refresh_token, config));

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
