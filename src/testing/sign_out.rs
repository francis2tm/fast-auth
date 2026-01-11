//! Sign-out test functions.

use reqwest::{StatusCode, header};

use crate::SignOutResponse;
use crate::handlers::SIGN_OUT_PATH;
use crate::tokens::refresh_token_hash;

use super::{TestContext, TestUser};

/// Signing out should revoke the refresh token and clear cookies.
pub async fn sign_out_revokes_refresh_token_and_clears_cookies<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();

    let user = TestUser::new(&base_url, &client, auth_config).await;
    let cookie_header = user.cookie_header(auth_config);

    let response = client
        .post(format!("{}{}", base_url, SIGN_OUT_PATH))
        .header(header::COOKIE, cookie_header)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let cleared: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .collect();
    assert_eq!(cleared.len(), 2, "both cookies must be cleared");

    let body = response.bytes().await.unwrap();
    let payload: SignOutResponse = serde_json::from_slice(&body).unwrap();
    assert!(payload.success);

    let token_hash = refresh_token_hash(&user.refresh_token);
    let revoked = ctx
        .refresh_token_get(&token_hash)
        .await
        .expect("token in db");
    assert!(
        revoked.revoked_at.is_some(),
        "refresh token must be revoked"
    );
}

/// Requests that omit the refresh token cookie must be rejected.
pub async fn sign_out_requires_refresh_cookie<C: TestContext>() {
    let (base_url, client, _ctx) = C::spawn().await;

    let response = client
        .post(format!("{}{}", base_url, SIGN_OUT_PATH))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Tampering with the refresh cookie must not revoke the legitimate token.
pub async fn sign_out_rejects_unknown_refresh_token_without_leaking_state<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();

    let user = TestUser::new(&base_url, &client, auth_config).await;
    let forged_refresh = "ff".repeat(32);

    // Manually construct forged header
    let forged_header = format!(
        "{}={}; {}={}",
        auth_config.cookie_access_token_name,
        user.access_token,
        auth_config.cookie_refresh_token_name,
        forged_refresh
    );

    let response = client
        .post(format!("{}{}", base_url, SIGN_OUT_PATH))
        .header(header::COOKIE, forged_header)
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
        "failed revocations must not emit Set-Cookie headers",
    );

    let token_hash = refresh_token_hash(&user.refresh_token);
    let stored = ctx
        .refresh_token_get(&token_hash)
        .await
        .expect("token in db");
    assert!(
        stored.revoked_at.is_none(),
        "legitimate token should stay active after tampering",
    );
}

/// Refresh tokens must be single-use so replayed logout attempts fail.
pub async fn sign_out_cannot_be_replayed_with_same_refresh_token<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();

    let user = TestUser::new(&base_url, &client, auth_config).await;
    let cookie_header = user.cookie_header(auth_config);

    let first = client
        .post(format!("{}{}", base_url, SIGN_OUT_PATH))
        .header(header::COOKIE, cookie_header.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(first.status(), StatusCode::OK);

    let token_hash = refresh_token_hash(&user.refresh_token);
    let revoked = ctx
        .refresh_token_get(&token_hash)
        .await
        .expect("token in db");
    assert!(revoked.revoked_at.is_some());

    let second = client
        .post(format!("{}{}", base_url, SIGN_OUT_PATH))
        .header(header::COOKIE, cookie_header)
        .send()
        .await
        .unwrap();

    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        second.headers().get_all(header::SET_COOKIE).iter().count(),
        0,
        "replayed attempts must not leak cookie operations",
    );
}
