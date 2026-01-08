//! Me handler (get current user).

use crate::{
    Auth, AuthBackend, AuthHooks, AuthUser, UserResponse,
    error::AuthError,
    extractors::AuthUserExtractor,
};
use axum::{Router, Json, extract::State, routing::get};

/// Create me routes.
pub fn me_routes<B, H>() -> Router<Auth<B, H>>
where
    B: AuthBackend,
    H: AuthHooks<B::User>,
{
    Router::new().route("/v1/auth/me", get(me_get::<B, H>))
}

/// Handle me request.
async fn me_get<B, H>(
    State(auth): State<Auth<B, H>>,
    auth_user: AuthUserExtractor,
) -> Result<Json<UserResponse>, AuthError>
where
    B: AuthBackend,
    H: AuthHooks<B::User>,
{
    // Fetch user from database
    let user = auth
        .backend()
        .user_find_by_id(auth_user.user_id)
        .await
        .map_err(AuthError::backend)?
        .ok_or(AuthError::UserNotFound)?;

    Ok(Json(user_to_response(&user)))
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
