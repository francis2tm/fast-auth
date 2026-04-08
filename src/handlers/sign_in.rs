//! Handler for user sign-in.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthUser, EmailSender, auth_response_with_cookies_build,
    cookies::{access_token_cookie_create, refresh_token_cookie_create},
    email::email_validate_normalize,
    error::AuthError,
    password::password_verify,
    tokens::{access_token_generate, token_expiry_calculate, token_with_hash_generate},
};
use axum::{Json, Router, extract::State, response::Response, routing::post};
use serde::Deserialize;
use utoipa::{OpenApi, ToSchema};

pub const SIGN_IN_PATH: &str = "/auth/sign-in";

#[derive(OpenApi)]
#[openapi(
    paths(sign_in),
    components(schemas(SignInRequest, crate::AuthResponse, crate::error::AuthErrorResponse))
)]
pub(crate) struct SignInApi;

/// Returns routes for the /auth/sign-in endpoint.
pub fn sign_in_routes<B: AuthBackend, H: AuthHooks, E: EmailSender>() -> Router<Auth<B, H, E>> {
    Router::new().route(SIGN_IN_PATH, post(sign_in::<B, H, E>))
}

/// Request body for sign-in.
#[derive(Debug, Deserialize, ToSchema)]
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
#[utoipa::path(
    post,
    path = "",
    request_body = SignInRequest,
    responses(
        (status = OK, body = crate::AuthResponse),
        (status = BAD_REQUEST, body = crate::error::AuthErrorResponse),
        (status = UNAUTHORIZED, body = crate::error::AuthErrorResponse),
        (status = FORBIDDEN, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
pub async fn sign_in<B: AuthBackend, H: AuthHooks, E: EmailSender>(
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
        .map_err(AuthError::from_backend)?
        .ok_or(AuthError::InvalidCredentials)?;

    // Verify password (constant-time comparison)
    let password_valid = password_verify(&req.password, user.password_hash())?;

    if !password_valid {
        return Err(AuthError::InvalidCredentials);
    }

    // Check email confirmation if required
    if config.email_confirmation_require && user.email_confirmed_at().is_none() {
        return Err(AuthError::EmailNotConfirmed);
    }

    let (refresh_token, refresh_token_hash) = token_with_hash_generate();
    let refresh_token_expiry = token_expiry_calculate(config.refresh_token_expiry);

    auth.backend()
        .session_issue_if_password_hash(
            user.id(),
            user.password_hash(),
            &refresh_token_hash,
            refresh_token_expiry,
        )
        .await
        .map_err(AuthError::from_backend)?;

    let current_user = auth
        .backend()
        .current_user_get_by_user_id(user.id())
        .await
        .map_err(AuthError::from_backend)?
        .ok_or(AuthError::UserNotFound)?;
    let access_token = access_token_generate(&current_user, config)?;

    // Call the on_sign_in hook only after session issuance succeeds.
    auth.hooks().on_sign_in(&current_user).await;

    let jar = axum_extra::extract::cookie::CookieJar::new()
        .add(access_token_cookie_create(access_token, config))
        .add(refresh_token_cookie_create(refresh_token, config));

    auth_response_with_cookies_build(jar, &current_user)
}
