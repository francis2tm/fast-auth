//! Sign-up handler.

use crate::{
    Auth, AuthBackend, AuthCookieResponse, AuthHooks, AuthUser, UserResponse,
    email::email_normalize,
    error::AuthError,
    password::{password_hash, password_validate},
    tokens::token_cookies_generate,
};
use axum::{Router, extract::State, response::IntoResponse, routing::post};
use serde::Deserialize;
use uuid::Uuid;

/// Sign-up request body.
#[derive(Debug, Deserialize)]
pub struct SignUpRequest {
    /// Email address.
    pub email: String,
    /// Password (plaintext, will be hashed).
    pub password: String,
}

/// Create sign-up routes.
pub fn sign_up_routes<B, H>() -> Router<Auth<B, H>>
where
    B: AuthBackend,
    H: AuthHooks<B::User>,
{
    Router::new().route("/v1/auth/sign-up", post(sign_up::<B, H>))
}

/// Handle sign-up request.
async fn sign_up<B, H>(
    State(auth): State<Auth<B, H>>,
    axum::Json(request): axum::Json<SignUpRequest>,
) -> Result<impl IntoResponse, AuthError>
where
    B: AuthBackend,
    H: AuthHooks<B::User>,
{
    let email = email_normalize(&request.email)?;
    password_validate(&request.password, auth.config())?;

    // Check if user exists
    let existing = auth
        .backend()
        .user_find_by_email(&email)
        .await
        .map_err(AuthError::backend)?;

    if existing.is_some() {
        return Err(AuthError::UserAlreadyExists);
    }

    // Hash password
    let hashed = password_hash(&request.password)?;

    // Create user
    let user_id = Uuid::new_v4();
    let user = auth
        .backend()
        .user_create(user_id, email.clone(), hashed)
        .await
        .map_err(AuthError::backend)?;

    // Call hook
    auth.hooks().on_sign_up(&user).await;

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
