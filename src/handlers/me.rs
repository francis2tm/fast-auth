//! Handler for getting current user information.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthUser, CurrentUser, EmailSender, UserResponse,
    error::AuthError,
};
use axum::{Json, Router, extract::State, routing::get};

pub const ME_PATH: &str = "/auth/me";

/// Returns routes for the /auth/me endpoint.
pub fn me_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>() -> Router<Auth<B, H, E>> {
    Router::new().route(ME_PATH, get(me_get::<B, H, E>))
}

/// Get current authenticated user.
///
/// Returns the current user's information from the JWT token.
/// Queries the database to get fresh user data including email_confirmed_at and created_at.
///
/// # Requires
/// - Valid JWT access token (httpOnly cookie)
/// - `auth::middleware::base` middleware applied to route
pub async fn me_get<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    current_user: CurrentUser,
    State(auth): State<Auth<B, H, E>>,
) -> Result<Json<UserResponse>, AuthError> {
    // Query user from database to get fresh data
    let user = auth
        .backend()
        .user_get_by_id(current_user.user_id)
        .await
        .map_err(AuthError::from_backend)?
        .ok_or(AuthError::UserNotFound)?;

    // Build response
    let user_response = UserResponse {
        id: user.id().to_string(),
        email: user.email().to_owned(),
        email_confirmed_at: user.email_confirmed_at().map(|dt| dt.to_rfc3339()),
        created_at: user.created_at().to_rfc3339(),
    };

    Ok(Json(user_response))
}
