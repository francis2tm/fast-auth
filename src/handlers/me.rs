//! Handler for getting current user information.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthResponse, CurrentUser, EmailSender, auth_response_build,
    error::AuthError,
};
use axum::{Json, Router, extract::State, routing::get};
use utoipa::OpenApi;

pub const ME_PATH: &str = "/auth/me";

#[derive(OpenApi)]
#[openapi(
    paths(me_get),
    components(schemas(crate::AuthResponse, crate::error::AuthErrorResponse))
)]
pub(crate) struct MeApi;

/// Returns routes for the /auth/me endpoint.
pub fn me_routes<B: AuthBackend, H: AuthHooks, E: EmailSender>() -> Router<Auth<B, H, E>> {
    Router::new().route(ME_PATH, get(me_get::<B, H, E>))
}

/// Get current authenticated user.
///
/// Returns the current user's information from the JWT token.
/// Queries the database to get fresh user data including email confirmation state.
///
/// # Requires
/// - Valid JWT access token (httpOnly cookie)
/// - Expired access tokens must be refreshed explicitly through `POST /auth/refresh`
/// - `auth::middleware::base` middleware applied to route
#[utoipa::path(
    get,
    path = "",
    security(("sessionCookie" = []), ("bearerApiKey" = [])),
    responses(
        (status = OK, body = crate::AuthResponse),
        (status = UNAUTHORIZED, body = crate::error::AuthErrorResponse),
        (status = NOT_FOUND, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
pub async fn me_get<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    current_user: CurrentUser,
    State(auth): State<Auth<B, H, E>>,
) -> Result<Json<AuthResponse>, AuthError> {
    let current_user = auth
        .backend()
        .current_user_get_by_user_id(current_user.user_id)
        .await
        .map_err(AuthError::from_backend)?
        .ok_or(AuthError::UserNotFound)?;
    Ok(Json(auth_response_build(&current_user)?))
}
