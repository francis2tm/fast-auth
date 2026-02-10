//! Email confirmation and password reset test functions.

use chrono::{Duration as ChronoDuration, Utc};
use reqwest::{StatusCode, header};
use serde_json::{Value, json};

use crate::handlers::{
    EMAIL_CONFIRM_PATH, ME_PATH, PASSWORD_RESET_PATH, SIGN_IN_PATH, SIGN_UP_PATH,
};
use crate::tokens::{token_generate, token_hash_sha256};
use crate::verification::VerificationTokenType;
use crate::{AuthBackend, AuthUser};

use super::{TestContext, TestUser};

/// Email confirmation should consume token and mark the user as confirmed.
pub async fn email_confirm_marks_user_confirmed<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    let stored_user = ctx
        .backend()
        .user_find_by_email(&user.email)
        .await
        .expect("db query")
        .expect("user exists");

    let token = token_generate();
    let token_hash = token_hash_sha256(&token);
    let expires_at = Utc::now() + ChronoDuration::hours(1);
    ctx.backend()
        .verification_token_issue(
            stored_user.id(),
            &token_hash,
            VerificationTokenType::EmailConfirm,
            expires_at,
        )
        .await
        .expect("create verification token");

    let response = client
        .get(format!(
            "{}{}?token={}",
            base_url, EMAIL_CONFIRM_PATH, token
        ))
        .send()
        .await
        .expect("email confirm request");

    assert_eq!(response.status(), StatusCode::OK);

    let refreshed_user = ctx
        .backend()
        .user_find_by_email(&user.email)
        .await
        .expect("db query")
        .expect("user exists");
    assert!(
        refreshed_user.email_confirmed_at().is_some(),
        "email_confirmed_at should be set after successful verification"
    );
}

/// Browser verification link (`GET /auth/email/confirm?token=...`) should confirm email.
pub async fn email_confirm_supports_get_link_flow<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    let stored_user = ctx
        .backend()
        .user_find_by_email(&user.email)
        .await
        .expect("db query")
        .expect("user exists");

    let token = token_generate();
    let token_hash = token_hash_sha256(&token);
    let expires_at = Utc::now() + ChronoDuration::hours(1);
    ctx.backend()
        .verification_token_issue(
            stored_user.id(),
            &token_hash,
            VerificationTokenType::EmailConfirm,
            expires_at,
        )
        .await
        .expect("create verification token");

    let response = client
        .get(format!(
            "{}{}?token={}",
            base_url, EMAIL_CONFIRM_PATH, token
        ))
        .send()
        .await
        .expect("email confirm get request");

    assert_eq!(response.status(), StatusCode::OK);

    let refreshed_user = ctx
        .backend()
        .user_find_by_email(&user.email)
        .await
        .expect("db query")
        .expect("user exists");
    assert!(
        refreshed_user.email_confirmed_at().is_some(),
        "email_confirmed_at should be set after GET verification flow"
    );
}

/// Password reset should update credentials and revoke existing refresh sessions.
pub async fn password_reset_updates_password_and_revokes_sessions<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    let stored_user = ctx
        .backend()
        .user_find_by_email(&user.email)
        .await
        .expect("db query")
        .expect("user exists");

    let token = token_generate();
    let token_hash = token_hash_sha256(&token);
    let expires_at = Utc::now() + ChronoDuration::hours(1);
    ctx.backend()
        .verification_token_issue(
            stored_user.id(),
            &token_hash,
            VerificationTokenType::PasswordReset,
            expires_at,
        )
        .await
        .expect("create verification token");

    let new_password = "NewSecurePass456";
    let reset_response = client
        .post(format!("{}{}", base_url, PASSWORD_RESET_PATH))
        .json(&json!({ "token": token, "password": new_password }))
        .send()
        .await
        .expect("password reset request");
    assert_eq!(reset_response.status(), StatusCode::OK);

    let old_password_sign_in = client
        .post(format!("{}{}", base_url, SIGN_IN_PATH))
        .json(&json!({ "email": user.email, "password": user.password }))
        .send()
        .await
        .expect("sign-in request with old password");
    assert_eq!(old_password_sign_in.status(), StatusCode::UNAUTHORIZED);

    let new_password_sign_in = client
        .post(format!("{}{}", base_url, SIGN_IN_PATH))
        .json(&json!({ "email": user.email, "password": new_password }))
        .send()
        .await
        .expect("sign-in request with new password");
    assert_eq!(new_password_sign_in.status(), StatusCode::OK);

    let refresh_only_response = client
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
        .expect("me request with old refresh token");
    assert_eq!(
        refresh_only_response.status(),
        StatusCode::UNAUTHORIZED,
        "password reset should revoke previous refresh sessions"
    );
}

/// Expired email-confirm tokens must be rejected on GET link flow.
pub async fn email_confirm_rejects_expired_token_get<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let user_id = user_id_find_by_email(&ctx, &user.email).await;

    let token = verification_token_seed(
        &ctx,
        user_id,
        VerificationTokenType::EmailConfirm,
        Utc::now() - ChronoDuration::minutes(1),
    )
    .await;

    let response = client
        .get(format!(
            "{}{}?token={}",
            base_url, EMAIL_CONFIRM_PATH, token
        ))
        .send()
        .await
        .expect("email confirm get request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let payload: Value = response.json().await.expect("error payload");
    assert_eq!(payload["error"], "Invalid token");
}

/// Expired password reset tokens must be rejected and leave credentials unchanged.
pub async fn password_reset_rejects_expired_token<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let user_id = user_id_find_by_email(&ctx, &user.email).await;

    let token = verification_token_seed(
        &ctx,
        user_id,
        VerificationTokenType::PasswordReset,
        Utc::now() - ChronoDuration::minutes(1),
    )
    .await;

    let new_password = "NewSecurePass456";
    let response = client
        .post(format!("{}{}", base_url, PASSWORD_RESET_PATH))
        .json(&json!({ "token": token, "password": new_password }))
        .send()
        .await
        .expect("password reset request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let payload: Value = response.json().await.expect("error payload");
    assert_eq!(payload["error"], "Invalid token");

    assert_eq!(
        sign_in_status(&base_url, &client, &user.email, &user.password).await,
        StatusCode::OK,
        "expired reset token must not invalidate current password",
    );
    assert_eq!(
        sign_in_status(&base_url, &client, &user.email, new_password).await,
        StatusCode::UNAUTHORIZED,
        "expired reset token must not apply new password",
    );
}

/// Email confirmation tokens must be single-use.
pub async fn email_confirm_token_is_single_use<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let user_id = user_id_find_by_email(&ctx, &user.email).await;

    let token = verification_token_seed(
        &ctx,
        user_id,
        VerificationTokenType::EmailConfirm,
        Utc::now() + ChronoDuration::hours(1),
    )
    .await;

    let first = client
        .get(format!(
            "{}{}?token={}",
            base_url, EMAIL_CONFIRM_PATH, token
        ))
        .send()
        .await
        .expect("first email confirm request");
    assert_eq!(first.status(), StatusCode::OK);

    let second = client
        .get(format!(
            "{}{}?token={}",
            base_url, EMAIL_CONFIRM_PATH, token
        ))
        .send()
        .await
        .expect("second email confirm request");
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    let payload: Value = second.json().await.expect("error payload");
    assert_eq!(payload["error"], "Invalid token");
}

/// Password reset tokens must be single-use.
pub async fn password_reset_token_is_single_use<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let user_id = user_id_find_by_email(&ctx, &user.email).await;

    let token = verification_token_seed(
        &ctx,
        user_id,
        VerificationTokenType::PasswordReset,
        Utc::now() + ChronoDuration::hours(1),
    )
    .await;

    let first_password = "SingleUsePass456";
    let first = client
        .post(format!("{}{}", base_url, PASSWORD_RESET_PATH))
        .json(&json!({ "token": token, "password": first_password }))
        .send()
        .await
        .expect("first password reset request");
    assert_eq!(first.status(), StatusCode::OK);

    let second_password = "SingleUsePass789";
    let second = client
        .post(format!("{}{}", base_url, PASSWORD_RESET_PATH))
        .json(&json!({ "token": token, "password": second_password }))
        .send()
        .await
        .expect("second password reset request");
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    let payload: Value = second.json().await.expect("error payload");
    assert_eq!(payload["error"], "Invalid token");

    assert_eq!(
        sign_in_status(&base_url, &client, &user.email, first_password).await,
        StatusCode::OK,
        "first successful reset must be preserved",
    );
    assert_eq!(
        sign_in_status(&base_url, &client, &user.email, second_password).await,
        StatusCode::UNAUTHORIZED,
        "second replayed reset must not overwrite password",
    );
}

/// Tokens must be rejected when used against the wrong verification flow.
pub async fn verification_token_type_mismatch_is_rejected<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let user_id = user_id_find_by_email(&ctx, &user.email).await;

    let password_reset_token = verification_token_seed(
        &ctx,
        user_id,
        VerificationTokenType::PasswordReset,
        Utc::now() + ChronoDuration::hours(1),
    )
    .await;
    let email_confirm_token = verification_token_seed(
        &ctx,
        user_id,
        VerificationTokenType::EmailConfirm,
        Utc::now() + ChronoDuration::hours(1),
    )
    .await;

    let confirm_with_reset_token = client
        .get(format!(
            "{}{}?token={}",
            base_url, EMAIL_CONFIRM_PATH, password_reset_token
        ))
        .send()
        .await
        .expect("email confirm with reset token request");
    assert_eq!(confirm_with_reset_token.status(), StatusCode::UNAUTHORIZED);

    let reset_with_confirm_token = client
        .post(format!("{}{}", base_url, PASSWORD_RESET_PATH))
        .json(&json!({ "token": email_confirm_token, "password": "ValidPass123" }))
        .send()
        .await
        .expect("password reset with confirm token request");
    assert_eq!(reset_with_confirm_token.status(), StatusCode::UNAUTHORIZED);
}

/// Malformed verification tokens should be rejected cleanly.
pub async fn verification_rejects_malformed_token<C: TestContext>() {
    let (base_url, client, _ctx) = C::spawn().await;
    let malformed = "%%%not-a-valid-token%%%";

    let confirm = client
        .get(format!(
            "{}{}?token={}",
            base_url, EMAIL_CONFIRM_PATH, malformed
        ))
        .send()
        .await
        .expect("email confirm malformed token request");
    assert_eq!(confirm.status(), StatusCode::UNAUTHORIZED);

    let reset = client
        .post(format!("{}{}", base_url, PASSWORD_RESET_PATH))
        .json(&json!({ "token": malformed, "password": "ValidPass123" }))
        .send()
        .await
        .expect("password reset malformed token request");
    assert_eq!(reset.status(), StatusCode::UNAUTHORIZED);
}

/// Invalid reset tokens must not change credentials.
pub async fn password_reset_does_not_change_password_on_invalid_token<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;
    let new_password = "ShouldNeverApply123";

    let response = client
        .post(format!("{}{}", base_url, PASSWORD_RESET_PATH))
        .json(&json!({ "token": token_generate(), "password": new_password }))
        .send()
        .await
        .expect("password reset with invalid token request");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    assert_eq!(
        sign_in_status(&base_url, &client, &user.email, &user.password).await,
        StatusCode::OK,
        "invalid token must keep existing password valid",
    );
    assert_eq!(
        sign_in_status(&base_url, &client, &user.email, new_password).await,
        StatusCode::UNAUTHORIZED,
        "invalid token must not apply replacement password",
    );
}

/// Sign-in should reject unconfirmed users when email confirmation is required.
pub async fn sign_in_rejects_unconfirmed_user_when_confirmation_required<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn_require_email_confirmation().await;
    assert!(
        ctx.auth_config().require_email_confirmation,
        "TestContext::spawn_require_email_confirmation must enable require_email_confirmation",
    );

    let email = format!("require-confirm+{}@example.com", uuid::Uuid::new_v4());
    let password = "SecurePass123";
    client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("sign-up request");

    let response = client
        .post(format!("{}{}", base_url, SIGN_IN_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("sign-in request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "sign-in failure must not set auth cookies",
    );

    let payload: Value = response.json().await.expect("error payload");
    assert_eq!(payload["error"], "Email not confirmed");
}

/// Sign-up should not issue auth cookies when confirmation is required.
pub async fn sign_up_skips_cookie_issuance_when_confirmation_required<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn_require_email_confirmation().await;
    assert!(
        ctx.auth_config().require_email_confirmation,
        "TestContext::spawn_require_email_confirmation must enable require_email_confirmation",
    );

    let email = format!("require-confirm+{}@example.com", uuid::Uuid::new_v4());
    let response = client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": email, "password": "SecurePass123" }))
        .send()
        .await
        .expect("sign-up request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "sign-up should not set auth cookies before email confirmation",
    );
}

/// Protected route refresh should fail for unconfirmed users when confirmation is required.
pub async fn protected_route_rejects_unconfirmed_user_when_confirmation_required<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn_require_email_confirmation().await;
    let auth_config = ctx.auth_config();
    assert!(
        auth_config.require_email_confirmation,
        "TestContext::spawn_require_email_confirmation must enable require_email_confirmation",
    );

    let email = format!("require-confirm+{}@example.com", uuid::Uuid::new_v4());
    let password = "SecurePass123";
    client
        .post(format!("{}{}", base_url, SIGN_UP_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("sign-up request");

    let user = ctx
        .backend()
        .user_find_by_email(&email)
        .await
        .expect("db query")
        .expect("user exists");

    let refresh_token = token_generate();
    let refresh_token_hash = token_hash_sha256(&refresh_token);
    let expires_at = Utc::now() + ChronoDuration::days(7);
    ctx.backend()
        .session_issue(user.id(), &refresh_token_hash, expires_at)
        .await
        .expect("create refresh token");

    let response = client
        .get(format!("{}{}", base_url, ME_PATH))
        .header(
            header::COOKIE,
            format!(
                "{}={}",
                auth_config.cookie_refresh_token_name, refresh_token
            ),
        )
        .send()
        .await
        .expect("me request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "failed refresh should not emit new cookies",
    );
}

async fn user_id_find_by_email<C: TestContext>(ctx: &C, email: &str) -> uuid::Uuid {
    ctx.backend()
        .user_find_by_email(email)
        .await
        .expect("db query")
        .expect("user exists")
        .id()
}

async fn verification_token_seed<C: TestContext>(
    ctx: &C,
    user_id: uuid::Uuid,
    token_type: VerificationTokenType,
    expires_at: chrono::DateTime<Utc>,
) -> String {
    let token = token_generate();
    let token_hash = token_hash_sha256(&token);
    ctx.backend()
        .verification_token_issue(user_id, &token_hash, token_type, expires_at)
        .await
        .expect("create verification token");
    token
}

async fn sign_in_status(
    base_url: &str,
    client: &reqwest::Client,
    email: &str,
    password: &str,
) -> StatusCode {
    client
        .post(format!("{}{}", base_url, SIGN_IN_PATH))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("sign-in request")
        .status()
}
