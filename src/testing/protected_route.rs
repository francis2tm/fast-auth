//! Protected route test functions.

use axum_extra::extract::cookie::Cookie;
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::{StatusCode, header};
use serde_json::Value;

use crate::AuthBackendError;
use crate::AuthError;
use crate::handlers::ME_PATH;
use crate::tokens::{
    AccessTokenClaims, token_expiry_calculate, token_hash_sha256, token_with_hash_generate,
};

use super::{TestContext, TestUser};
use crate::AuthBackend;

/// Create an expired access token for testing.
fn create_expired_access_token(user_id: &str, email: &str, config: &crate::AuthConfig) -> String {
    let now = Utc::now();
    let expired_at = now - Duration::hours(1); // Expired 1 hour ago

    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        iat: (now - Duration::hours(2)).timestamp(),
        exp: expired_at.timestamp(),
        iss: config.jwt_issuer.clone(),
        aud: config.jwt_audience.clone(),
        role: "authenticated".to_string(),
        email: email.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .expect("encode expired token")
}

/// Protected route should silently refresh and succeed when refresh token is valid.
pub async fn protected_route_accepts_valid_refresh_token<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    let response = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}",
                auth_config.cookie_refresh_token_name, user.refresh_token
            ),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Middleware should emit a fresh access token.
    let set_cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .collect();
    assert!(
        set_cookies.iter().any(|value| {
            Cookie::parse(value.to_str().unwrap().to_string())
                .map(|cookie| cookie.name() == auth_config.cookie_access_token_name)
                .unwrap_or(false)
        }),
        "expected access token refresh"
    );

    let body = response.bytes().await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["email"], user.email);
}

/// Expired access token + valid refresh token should silently refresh.
pub async fn protected_route_refreshes_expired_access_token<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    // Decode the valid access token to get user_id
    let mut validation = jsonwebtoken::Validation::default();
    validation.set_issuer(&[&auth_config.jwt_issuer]);
    validation.set_audience(&[&auth_config.jwt_audience]);
    let token_data = jsonwebtoken::decode::<AccessTokenClaims>(
        &user.access_token,
        &jsonwebtoken::DecodingKey::from_secret(auth_config.jwt_secret.as_bytes()),
        &validation,
    )
    .expect("decode valid token");
    let user_id = &token_data.claims.sub;

    // Create an expired access token (valid signature, but exp in the past)
    let expired_access_token = create_expired_access_token(user_id, &user.email, auth_config);

    // Send BOTH cookies: expired access token + valid refresh token
    let response = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                auth_config.cookie_access_token_name,
                expired_access_token,
                auth_config.cookie_refresh_token_name,
                user.refresh_token
            ),
        )
        .send()
        .await
        .unwrap();

    // Should succeed - middleware should detect expired JWT and use refresh token
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "expired access token + valid refresh should succeed"
    );

    // Should emit a fresh access token
    let set_cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .collect();
    assert!(
        set_cookies.iter().any(|value| {
            Cookie::parse(value.to_str().unwrap().to_string())
                .map(|cookie| cookie.name() == auth_config.cookie_access_token_name)
                .unwrap_or(false)
        }),
        "expected new access token cookie"
    );

    let body = response.bytes().await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["email"], user.email);
}

/// Expired refresh tokens must not authenticate or issue new cookies.
pub async fn protected_route_rejects_expired_refresh_token<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let refresh_token_hash = token_hash_sha256(&user.refresh_token);

    // Expire the token
    ctx.refresh_token_expire(&refresh_token_hash).await;

    let response = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}",
                auth_config.cookie_refresh_token_name, user.refresh_token
            ),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "expired refresh should not emit cookies"
    );
}

/// Revoked refresh tokens must be rejected without emitting cookies.
pub async fn protected_route_rejects_revoked_refresh_token<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let refresh_token_hash = token_hash_sha256(&user.refresh_token);

    // Revoke the token via AuthBackend
    ctx.backend()
        .session_revoke_by_refresh_token_hash(&refresh_token_hash)
        .await
        .expect("revoke token");

    let response = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}",
                auth_config.cookie_refresh_token_name, user.refresh_token
            ),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "revoked refresh should not emit cookies"
    );
}

/// Silent refresh should rotate refresh token and reject replay of the old token.
pub async fn protected_route_rotates_refresh_token_and_rejects_replay<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let old_refresh_token = user.refresh_token.clone();

    let response = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}",
                auth_config.cookie_refresh_token_name, old_refresh_token
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let set_cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .collect();
    let new_refresh_token = set_cookies
        .iter()
        .find_map(|value| {
            Cookie::parse(value.to_str().ok()?.to_string())
                .ok()
                .filter(|cookie| cookie.name() == auth_config.cookie_refresh_token_name)
                .map(|cookie| cookie.value().to_string())
        })
        .expect("expected rotated refresh token cookie");
    assert_ne!(new_refresh_token, old_refresh_token);

    let replay = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}",
                auth_config.cookie_refresh_token_name, old_refresh_token
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let with_new = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}",
                auth_config.cookie_refresh_token_name, new_refresh_token
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(with_new.status(), StatusCode::OK);
}

/// Two concurrent refresh attempts with one token should have a single winner.
pub async fn protected_route_refresh_replay_race_has_single_winner<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    let request_a = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}",
                auth_config.cookie_refresh_token_name, user.refresh_token
            ),
        )
        .send();
    let request_b = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}",
                auth_config.cookie_refresh_token_name, user.refresh_token
            ),
        )
        .send();

    let (resp_a, resp_b) = tokio::join!(request_a, request_b);
    let status_a = resp_a.expect("first refresh request").status();
    let status_b = resp_b.expect("second refresh request").status();

    let success_count = [status_a, status_b]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();
    let unauthorized_count = [status_a, status_b]
        .into_iter()
        .filter(|status| *status == StatusCode::UNAUTHORIZED)
        .count();

    assert_eq!(success_count, 1, "exactly one refresh should win");
    assert_eq!(unauthorized_count, 1, "replay refresh must be rejected");

    let old_hash = token_hash_sha256(&user.refresh_token);
    let old_token = ctx
        .refresh_token_get(&old_hash)
        .await
        .expect("old refresh token row");
    assert!(
        old_token.revoked_at.is_some(),
        "old refresh token must be revoked after race",
    );
}

/// Backend exchange contract should allow only one winner for same token hash.
pub async fn session_exchange_race_has_single_winner<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let current_hash = token_hash_sha256(&user.refresh_token);

    let (_, next_hash_a) = token_with_hash_generate();
    let (_, next_hash_b) = token_with_hash_generate();
    let next_expires_at = token_expiry_calculate(auth_config.refresh_token_expiry);

    let exchange_a = async {
        ctx.backend()
            .session_exchange(&current_hash, &next_hash_a, next_expires_at)
            .await
    };
    let exchange_b = async {
        ctx.backend()
            .session_exchange(&current_hash, &next_hash_b, next_expires_at)
            .await
    };

    let (outcome_a, outcome_b) = tokio::join!(exchange_a, exchange_b);
    let outcomes = [&outcome_a, &outcome_b];

    let exchanged_count = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    let invalid_count = outcomes
        .iter()
        .filter(|outcome| {
            outcome
                .as_ref()
                .err()
                .is_some_and(|error| matches!(error.auth_error(), AuthError::RefreshTokenInvalid))
        })
        .count();

    assert_eq!(exchanged_count, 1, "exactly one exchange should succeed");
    assert_eq!(invalid_count, 1, "replay exchange must be rejected");
}
