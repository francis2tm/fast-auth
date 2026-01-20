//! Handler for user sign-out.

use crate::{
    Auth, AuthBackend, AuthHooks, EmailSender,
    cookies::{access_token_cookie_clear, refresh_token_cookie_clear},
    error::AuthError,
    tokens::token_hash_sha256,
};
use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

pub const SIGN_OUT_PATH: &str = "/auth/sign-out";

/// Returns routes for the /auth/sign-out endpoint.
pub fn sign_out_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
    Router::new().route(SIGN_OUT_PATH, post(sign_out::<B, H, E>))
}

/// Response for sign-out.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignOutResponse {
    /// Sign-out success status.
    pub success: bool,
    /// Message instructing client to clear tokens.
    pub message: String,
}

/// Sign out user by revoking refresh token.
///
/// Revokes the refresh token from database and clears both access and refresh cookies.
/// The server automatically sends Set-Cookie headers to clear the cookies from the browser.
///
/// **Note**: Due to the stateless nature of JWT tokens, if the access token was copied before
/// sign-out, it will remain valid until it expires (typically 15 minutes). This is standard
/// behavior for JWT-based authentication systems.
pub async fn sign_out<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    jar: CookieJar,
) -> Result<Response, AuthError> {
    let config = auth.config();

    // Get refresh token from cookie
    let refresh_token = jar
        .get(&config.cookie_refresh_token_name)
        .map(|c| c.value().to_string())
        .ok_or(AuthError::RefreshTokenInvalid)?;

    let refresh_token_hash = token_hash_sha256(&refresh_token);

    // Revoke refresh token via backend
    let revoked = auth
        .backend()
        .refresh_token_revoke(&refresh_token_hash)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    if !revoked {
        // Token not found or already revoked
        return Err(AuthError::RefreshTokenInvalid);
    }

    // Clear cookies by setting max-age=0
    let access_clear_cookie = access_token_cookie_clear(config);
    let refresh_clear_cookie = refresh_token_cookie_clear(config);

    let jar = jar.add(access_clear_cookie).add(refresh_clear_cookie);

    let response_body = SignOutResponse {
        success: true,
        message: "Signed out successfully. Cookies have been cleared.".to_string(),
    };

    Ok((jar, Json(response_body)).into_response())
}
