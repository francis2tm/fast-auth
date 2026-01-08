//! Sign-out handler.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthRefreshToken,
    cookies::{access_token_cookie_clear, refresh_token_cookie_clear},
    error::AuthError,
    tokens::refresh_token_hash,
};
use axum::{Json, Router, extract::State, response::IntoResponse, routing::post};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

/// Sign-out response body.
#[derive(Debug, Serialize)]
pub struct SignOutResponse {
    /// Success message.
    pub message: String,
}

/// Create sign-out routes.
pub fn sign_out_routes<B, H>() -> Router<Auth<B, H>>
where
    B: AuthBackend,
    H: AuthHooks<B::User>,
{
    Router::new().route("/v1/auth/sign-out", post(sign_out::<B, H>))
}

/// Handle sign-out request.
async fn sign_out<B, H>(
    State(auth): State<Auth<B, H>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AuthError>
where
    B: AuthBackend,
    H: AuthHooks<B::User>,
{
    let config = auth.config();

    // If there's a refresh token, revoke it
    if let Some(refresh_cookie) = jar.get(&config.cookie_refresh_token_name) {
        let hash = refresh_token_hash(refresh_cookie.value());

        // Find the token to get the user_id
        if let Ok(Some(token)) = auth.backend().refresh_token_find_valid(&hash).await {
            // Revoke all tokens for this user
            let _ = auth
                .backend()
                .refresh_tokens_revoke_all(token.user_id())
                .await;
        }
    }

    // Clear cookies
    let jar = jar
        .add(access_token_cookie_clear(config))
        .add(refresh_token_cookie_clear(config));

    let response = SignOutResponse {
        message: "Signed out successfully".to_string(),
    };

    Ok((jar, Json(response)))
}
