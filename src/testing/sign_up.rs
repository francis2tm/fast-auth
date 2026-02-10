//! Sign-up test functions.

use axum_extra::extract::cookie::Cookie;
use reqwest::{StatusCode, header};
use serde_json::json;
use uuid::Uuid;

use crate::AuthCookieResponse;
use crate::AuthUser;
use crate::handlers::SIGN_UP_PATH;

use super::TestContext;
use crate::AuthBackend;

/// Verifies that sign-up persists a new user and emits auth cookies.
pub async fn sign_up_creates_user_and_sets_cookies<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();

    let email = format!("user+{}@example.com", Uuid::new_v4());
    let password = "SecurePass123";

    let response = client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("sign-up request");

    // Verify cookies were set
    let cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .collect();
    assert_eq!(cookies.len(), 2, "expected access and refresh cookies");

    // Verify access token cookie was set
    assert!(cookies.iter().any(|value| {
        Cookie::parse(value.to_str().unwrap().to_string())
            .map(|cookie| cookie.name() == auth_config.cookie_access_token_name)
            .unwrap_or(false)
    }));

    // Verify refresh token cookie was set
    assert!(cookies.iter().any(|value| {
        Cookie::parse(value.to_str().unwrap().to_string())
            .map(|cookie| cookie.name() == auth_config.cookie_refresh_token_name)
            .unwrap_or(false)
    }));

    // Verify response body contains user email
    let body = response.bytes().await.unwrap();
    let parsed: AuthCookieResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.user.email, email);

    // Verify user was persisted
    let stored_user = ctx
        .backend()
        .user_find_by_email(&email)
        .await
        .expect("db query")
        .expect("user persisted");
    assert_eq!(stored_user.email(), email);
}

/// Ensures duplicate sign-ups return 409 Conflict.
pub async fn sign_up_rejects_duplicate_email<C: TestContext>() {
    let (base_url, client, _ctx) = C::spawn().await;

    let email = format!("user+{}@example.com", Uuid::new_v4());
    let password = "SecurePass123";

    let first = client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let response = client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// Rejects malformed emails so bogus identities are never persisted.
pub async fn sign_up_rejects_invalid_email<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;

    let response = client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": "not-an-email", "password": "SecurePass123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "failing validation must not emit cookies",
    );

    assert!(
        ctx.backend()
            .user_find_by_email("not-an-email")
            .await
            .unwrap()
            .is_none(),
        "failed requests must not create users",
    );
}

/// Enforces password complexity to keep weak credentials from being accepted.
pub async fn sign_up_enforces_password_complexity_rules<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let email = format!("user+{}@example.com", Uuid::new_v4());
    let password = "OnlyLettersHere";

    let response = client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "weak passwords must not issue cookies",
    );

    assert!(
        ctx.backend()
            .user_find_by_email(&email)
            .await
            .unwrap()
            .is_none(),
        "password checks must run before inserting the user",
    );
}

/// Concurrent duplicate sign-ups should produce exactly one success.
pub async fn sign_up_handles_concurrent_duplicate_requests<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let email = format!("race-user+{}@example.com", Uuid::new_v4());
    let password = "SecurePass123";

    let request_a = client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send();
    let request_b = client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send();

    let (resp_a, resp_b) = tokio::join!(request_a, request_b);
    let status_a = resp_a.expect("first sign-up request").status();
    let status_b = resp_b.expect("second sign-up request").status();

    let success_count = [status_a, status_b]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();
    let conflict_count = [status_a, status_b]
        .into_iter()
        .filter(|status| *status == StatusCode::CONFLICT)
        .count();

    assert_eq!(success_count, 1, "expected exactly one successful sign-up");
    assert_eq!(
        conflict_count, 1,
        "expected exactly one duplicate-email conflict",
    );

    let stored = ctx
        .backend()
        .user_find_by_email(&email)
        .await
        .expect("db query");
    assert!(stored.is_some(), "one user must be persisted");
}
