//! Sign-in handler.

use crate::{
    Auth, AuthBackend, AuthCookieResponse, AuthHooks, AuthUser, UserResponse,
    email::email_normalize,
    error::AuthError,
    password::password_verify,
    tokens::token_cookies_generate,
};
use axum::{Router, extract::State, response::IntoResponse, routing::post};
use serde::Deserialize;

/// Sign-in request body.
#[derive(Debug, Deserialize)]
pub struct SignInRequest {
    /// Email address.
    pub email: String,
    /// Password (plaintext).
    pub password: String,
}

/// Create sign-in routes.
pub fn sign_in_routes<B, H>() -> Router<Auth<B, H>>
where
    B: AuthBackend,
    H: AuthHooks<B::User>,
{
    Router::new().route("/v1/auth/sign-in", post(sign_in::<B, H>))
}

/// Handle sign-in request.
async fn sign_in<B, H>(
    State(auth): State<Auth<B, H>>,
    axum::Json(request): axum::Json<SignInRequest>,
) -> Result<impl IntoResponse, AuthError>
where
    B: AuthBackend,
    H: AuthHooks<B::User>,
{
    let email = email_normalize(&request.email)?;

    // Find user
    let user = auth
        .backend()
        .user_find_by_email(&email)
        .await
        .map_err(AuthError::backend)?
        .ok_or(AuthError::InvalidCredentials)?;

    // Verify password
    if !password_verify(&request.password, user.password_hash())? {
        return Err(AuthError::InvalidCredentials);
    }

    // Update last sign-in timestamp
    auth.backend()
        .user_update_last_sign_in(user.id())
        .await
        .map_err(AuthError::backend)?;

    // Call hook
    auth.hooks().on_sign_in(&user).await;

    // Generate tokens
    let jar = token_cookies_generate::<B, H>(auth.config(), auth.backend(), user.id(), user.email())
        .await?;

    let response = AuthCookieResponse {
        user: user_to_response(&user),
    };

    Ok((jar, axum::Json(response)))
}

/// Convert AuthUser to UserResponse.
fn user_to_response<U: AuthUser>(user: &U) -> UserResponse {
    UserResponse {
        id: user.id().to_string(),
        email: user.email().to_owned(),
        email_confirmed_at: user.email_confirmed_at().map(|dt| dt.to_rfc3339()),
        created_at: user.created_at().to_rfc3339(),
    }
}
