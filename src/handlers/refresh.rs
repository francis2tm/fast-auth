//! Handler for session refresh.

use crate::{
    Auth, AuthBackend, AuthCookieResponse, AuthHooks, AuthUser, EmailSender, UserResponse,
    error::{AuthError, AuthErrorResponse},
    tokens::token_cookies_refresh,
};
use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use axum_extra::extract::cookie::CookieJar;
use utoipa::OpenApi;

/// Path for the refresh endpoint.
pub const REFRESH_PATH: &str = "/auth/refresh";

#[derive(OpenApi)]
#[openapi(
    paths(refresh),
    components(schemas(AuthCookieResponse, AuthErrorResponse))
)]
pub(crate) struct RefreshApi;

/// Returns routes for the /auth/refresh endpoint.
pub fn refresh_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
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
        (status = OK, body = AuthCookieResponse),
        (status = UNAUTHORIZED, body = AuthErrorResponse),
        (status = FORBIDDEN, body = AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = AuthErrorResponse)
    )
)]
pub async fn refresh<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    jar: CookieJar,
) -> Result<Response, AuthError> {
    let config = auth.config();
    let refresh_token = jar
        .get(&config.cookie_refresh_token_name)
        .map(|cookie| cookie.value().to_string())
        .ok_or(AuthError::RefreshTokenInvalid)?;
    let (jar, user) = token_cookies_refresh(&auth, &refresh_token).await?;

    let response_body = AuthCookieResponse {
        user: UserResponse {
            id: user.id().to_string(),
            email: user.email().to_owned(),
            email_confirmed_at: user.email_confirmed_at().map(|dt| dt.to_rfc3339()),
            created_at: user.created_at().to_rfc3339(),
        },
    };

    Ok((jar, Json(response_body)).into_response())
}
