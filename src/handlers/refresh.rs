//! Handler for session refresh.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthResponse, EmailSender, auth_response_with_cookies_build,
    error::{AuthError, AuthErrorResponse},
    tokens::token_cookies_refresh,
};
use axum::{Router, extract::State, response::Response, routing::post};
use axum_extra::extract::cookie::CookieJar;
use utoipa::OpenApi;

/// Path for the refresh endpoint.
pub const REFRESH_PATH: &str = "/auth/refresh";

#[derive(OpenApi)]
#[openapi(paths(refresh), components(schemas(AuthResponse, AuthErrorResponse)))]
pub(crate) struct RefreshApi;

/// Returns routes for the /auth/refresh endpoint.
pub fn refresh_routes<B: AuthBackend, H: AuthHooks, E: EmailSender>() -> Router<Auth<B, H, E>> {
    Router::new().route(REFRESH_PATH, post(refresh::<B, H, E>))
}

/// Refresh the current session using the refresh-token cookie.
///
/// Rotates the refresh token, issues a new access token, and returns the
/// refreshed user payload.
#[utoipa::path(
    post,
    path = "",
    responses(
        (status = OK, body = AuthResponse),
        (status = UNAUTHORIZED, body = AuthErrorResponse),
        (status = FORBIDDEN, body = AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = AuthErrorResponse)
    )
)]
pub async fn refresh<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    jar: CookieJar,
) -> Result<Response, AuthError> {
    let config = auth.config();
    let refresh_token = jar
        .get(&config.cookie_refresh_token_name)
        .map(|cookie| cookie.value().to_string())
        .ok_or(AuthError::RefreshTokenInvalid)?;
    let (jar, hydrated_user) = token_cookies_refresh(&auth, &refresh_token).await?;

    Ok(auth_response_with_cookies_build(jar, &hydrated_user))
}
