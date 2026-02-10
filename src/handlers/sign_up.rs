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
use utoipa::{OpenApi, ToSchema};

pub const SIGN_UP_PATH: &str = "/auth/sign-up";

#[derive(OpenApi)]
#[openapi(
    paths(sign_up),
    components(schemas(
        SignUpRequest,
        crate::AuthCookieResponse,
        crate::error::AuthErrorResponse
    ))
)]
pub(crate) struct SignUpApi;

/// Returns routes for the /auth/sign-up endpoint.
pub fn sign_up_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
    Router::new().route(SIGN_UP_PATH, post(sign_up::<B, H, E>))
}

/// Request body for sign-up.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SignUpRequest {
    /// User email address.
    pub email: String,
    /// User password (min 8 characters, must contain letter and number).
    pub password: String,
}

/// Sign up a new user.
///
/// Creates a new user account with email and password.
/// Sets access and refresh tokens as httpOnly cookies unless email confirmation is required.
/// Calls the `on_sign_up` hook after successful user creation.
#[utoipa::path(
    post,
    path = "",
    request_body = SignUpRequest,
    responses(
        (status = OK, body = crate::AuthCookieResponse),
        (status = BAD_REQUEST, body = crate::error::AuthErrorResponse),
        (status = CONFLICT, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
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
        .user_create(&email, &hashed_password)
        .await
        .map_err(AuthError::from_backend)?;

    // Call the on_sign_up hook
    auth.hooks().on_sign_up(&user).await;

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

    // If email confirmation is required, do not set cookies until email is confirmed
    if config.email_confirmation_require && user.email_confirmed_at().is_none() {
        return Ok(Json(response_body).into_response());
    }

    // Generate tokens and cookies
    let jar = token_cookies_generate(&auth, user.id(), user.email()).await?;
    Ok((jar, Json(response_body)).into_response())
}
