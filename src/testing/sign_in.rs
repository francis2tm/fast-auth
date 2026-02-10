//! Sign-in test functions.

use axum_extra::extract::cookie::Cookie;
use reqwest::{StatusCode, header};
use serde_json::json;

use crate::AuthBackendError;
use crate::AuthCookieResponse;
use crate::AuthError;
use crate::AuthUser;
use crate::handlers::{ME_PATH, SIGN_IN_PATH};
use crate::password::password_hash;
use crate::tokens::{token_expiry_calculate, token_hash_sha256, token_with_hash_generate};
use chrono::Utc;

use super::{TestContext, TestUser};
use crate::AuthBackend;

/// Successful sign-in should set cookies and update `last_sign_in_at`.
pub async fn sign_in_returns_tokens_for_valid_credentials<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    let response = client
        .post(format!("{}{}", base_url, SIGN_IN_PATH))
        .json(&json!({
            "email": user.email,
            "password": user.password,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .collect();
    assert_eq!(cookies.len(), 2, "expected auth cookies on sign-in");

    assert!(cookies.iter().any(|value| {
        Cookie::parse(value.to_str().unwrap().to_string())
            .map(|cookie| cookie.name() == auth_config.cookie_access_token_name)
            .unwrap_or(false)
    }));
    assert!(cookies.iter().any(|value| {
        Cookie::parse(value.to_str().unwrap().to_string())
            .map(|cookie| cookie.name() == auth_config.cookie_refresh_token_name)
            .unwrap_or(false)
    }));

    let body = response.bytes().await.unwrap();
    let parsed: AuthCookieResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.user.email, user.email);

    let stored = ctx
        .backend()
        .user_find_by_email(&user.email)
        .await
        .expect("db query")
        .expect("user present after sign-in");
    assert!(
        stored.last_sign_in_at().is_some(),
        "handler should set last_sign_in_at"
    );
}

/// Invalid passwords must produce 401 without cookies.
pub async fn sign_in_rejects_invalid_passwords<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    let response = client
        .post(format!("{}{}", base_url, SIGN_IN_PATH))
        .json(&json!({
            "email": user.email,
            "password": "TotallyWrong123",
        }))
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
        "no cookies should be set on failure"
    );
}

/// Issuing a new refresh token should revoke every previous active token for the same user.
pub async fn sign_in_revokes_existing_refresh_tokens<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();

    let test_user = TestUser::new(&base_url, &client, auth_config).await;
    let refresh_token_hash = token_hash_sha256(&test_user.refresh_token);

    let refresh_token = ctx
        .refresh_token_get(&refresh_token_hash)
        .await
        .expect("token exists");

    assert!(
        refresh_token.revoked_at.is_none(),
        "fresh tokens must start active"
    );

    let response = client
        .post(format!("{}{}", base_url, SIGN_IN_PATH))
        .json(&json!({
            "email": test_user.email,
            "password": "SecurePass123",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let revoked = ctx.refresh_token_get(&refresh_token_hash).await.unwrap();
    assert!(
        revoked.revoked_at.is_some(),
        "new sign-ins must revoke prior refresh tokens",
    );
}

/// Expired refresh tokens should force the user to sign in again.
pub async fn sign_in_expired_refresh_token_requires_sign_in<C: TestContext>() {
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
        "expired refresh should not emit new cookies"
    );
}

/// Session issuance should reject stale password hashes.
pub async fn session_issue_rejects_stale_password_hash<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    let stored_user = ctx
        .backend()
        .user_find_by_email(&user.email)
        .await
        .expect("db query")
        .expect("user exists");
    let stale_password_hash = stored_user.password_hash().to_string();

    let replacement_hash = password_hash("ReplacementPass987").expect("hash password");
    ctx.user_password_hash_set(stored_user.id(), &replacement_hash)
        .await;

    let (_, next_refresh_hash) = token_with_hash_generate();
    let next_expires_at = token_expiry_calculate(auth_config.refresh_token_expiry);
    assert!(next_expires_at > Utc::now());

    let error = ctx
        .backend()
        .session_issue_if_password_hash(
            stored_user.id(),
            &stale_password_hash,
            &next_refresh_hash,
            next_expires_at,
        )
        .await
        .expect_err("stale password hash must fail");

    assert!(
        matches!(error.auth_error(), AuthError::InvalidCredentials),
        "stale password hash must reject session issuance",
    );
}
