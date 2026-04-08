//! Test suite for verifying fast-auth integration.
//!
//! This module provides a reusable test suite that users can invoke to verify
//! their [`AuthBackend`] implementations work correctly with the auth endpoints.
//!
//! # Usage
//!
//! Implement the [`TestContext`] trait for your test infrastructure, then use
//! the [`Suite`] to run all tests:
//!
//! ```ignore
//! use fast_auth::testing::{Suite, TestContext, TestUser, RefreshTokenInfo};
//! use fast_auth::AuthConfig;
//! use reqwest::Client;
//!
//! struct MyContext { /* your app state */ }
//!
//! impl TestContext for MyContext {
//!     async fn spawn() -> (String, Client, Self) {
//!         // Start your app, return (base_url, client, context)
//!     }
//!
//!     fn auth_config(&self) -> &AuthConfig { /* ... */ }
//!     // ... other required methods
//! }
//!
//! #[tokio::test]
//! async fn run_auth_suite() {
//!     Suite::<MyContext>::test_all().await;
//! }
//! ```
//!
//! [`AuthBackend`]: crate::AuthBackend

pub mod access_and_refresh;
pub mod api_keys;
pub mod organizations;
pub mod sign_in;
pub mod sign_out;
pub mod sign_up;
pub mod verification;

use axum_extra::extract::cookie::Cookie;
use chrono::{DateTime, Utc};
use reqwest::Client;
use reqwest::header;
use serde_json::json;
use std::future::Future;
use uuid::Uuid;

use crate::AuthBackend;
use crate::handlers::{API_KEYS_PATH, ME_PATH, SIGN_UP_PATH};
use crate::{AuthConfig, AuthResponse, AuthUser};

/// Refresh token information for test assertions.
#[derive(Debug, Clone)]
pub struct RefreshTokenInfo {
    /// User ID that owns this token.
    pub user_id: Uuid,
    /// When the token expires.
    pub expires_at: DateTime<Utc>,
    /// When the token was revoked, if ever.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Test user with credentials and tokens.
#[derive(Debug, Clone)]
pub struct TestUser {
    /// User's email address.
    pub email: String,
    /// User's password (plaintext for testing).
    pub password: String,
    /// Access token cookie value.
    pub access_token: String,
    /// Refresh token cookie value.
    pub refresh_token: String,
    /// API key returned by the create endpoint, when requested.
    pub api_key: Option<String>,
}

impl TestUser {
    /// Create a new test user via sign-up and return with extracted tokens.
    pub async fn new(base_url: &str, client: &Client, config: &AuthConfig) -> Self {
        let email = format!("user+{}@example.com", Uuid::new_v4());
        let password = "SecurePass123";

        let resp = client
            .post(format!("{}{}", base_url, SIGN_UP_PATH))
            .json(&json!({ "email": email, "password": password }))
            .send()
            .await
            .expect("sign-up request");

        let access_token = Self::extract_cookie(resp.headers(), &config.cookie_access_token_name)
            .expect("sign-up should set access token cookie");
        let refresh_token = Self::extract_cookie(resp.headers(), &config.cookie_refresh_token_name)
            .expect("sign-up should set refresh token cookie");

        Self {
            email,
            password: password.to_string(),
            access_token,
            refresh_token,
            api_key: None,
        }
    }

    /// Find a cookie value in response headers.
    pub fn extract_cookie(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
        headers.get_all(header::SET_COOKIE).iter().find_map(|v| {
            let c = Cookie::parse(v.to_str().ok()?.to_string()).ok()?;
            (c.name() == name).then(|| c.value().to_string())
        })
    }

    /// Build the cookie header for authenticated requests.
    pub fn cookie_header(&self, config: &AuthConfig) -> String {
        format!(
            "{}={}; {}={}",
            config.cookie_access_token_name,
            self.access_token,
            config.cookie_refresh_token_name,
            self.refresh_token
        )
    }

    /// Create one API key for this user and store it on the test user.
    pub async fn api_key_create(
        &mut self,
        base_url: &str,
        client: &Client,
        config: &AuthConfig,
        name: &str,
    ) -> String {
        let response = client
            .post(format!("{base_url}{API_KEYS_PATH}"))
            .header(header::COOKIE, self.cookie_header(config))
            .json(&json!({ "name": name }))
            .send()
            .await
            .expect("api key request");
        assert!(
            response.status().is_success(),
            "api key request failed with status {}",
            response.status()
        );

        let payload: serde_json::Value = response.json().await.expect("api key json");
        let api_key = payload["key"]
            .as_str()
            .expect("api key response should contain key")
            .to_string();
        self.api_key = Some(api_key.clone());
        api_key
    }

    /// Build the Authorization header for bearer API key requests.
    pub fn api_key_auth_header(&self) -> String {
        format!(
            "Bearer {}",
            self.api_key.as_deref().expect("api key should be present")
        )
    }

    /// Replace the stored auth cookies from one response header set.
    pub fn auth_cookies_replace(
        &mut self,
        headers: &reqwest::header::HeaderMap,
        config: &AuthConfig,
    ) {
        self.access_token = Self::extract_cookie(headers, &config.cookie_access_token_name)
            .expect("response should set access token cookie");
        self.refresh_token = Self::extract_cookie(headers, &config.cookie_refresh_token_name)
            .expect("response should set refresh token cookie");
    }
}

/// Assert one authenticated auth response shape.
pub fn auth_response_assert(
    payload: &crate::AuthResponse,
    expected_email: &str,
    expected_organization_role: crate::OrganizationRole,
) {
    assert!(
        !payload.user.id.is_empty(),
        "auth response must include user id"
    );
    assert_eq!(payload.user.email, expected_email);
    assert!(
        !payload.organization.id.is_empty(),
        "auth response must include organization id",
    );
    assert!(
        !payload.organization.name.trim().is_empty(),
        "auth response must include organization name",
    );
    assert_eq!(payload.organization.role, expected_organization_role);
    assert_eq!(payload.auth_role, "authenticated");
}

/// Load the authenticated `/auth/me` response for one test user.
pub async fn me_get(
    base_url: &str,
    client: &Client,
    user: &TestUser,
    config: &AuthConfig,
) -> AuthResponse {
    let response = client
        .get(format!("{base_url}{ME_PATH}"))
        .header(header::COOKIE, user.cookie_header(config))
        .send()
        .await
        .expect("me request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    response.json().await.expect("me json")
}

/// Context trait that test implementations must provide.
///
/// This abstracts away the concrete app infrastructure, allowing the test suite
/// to run against any backend that implements [`crate::AuthBackend`].
pub trait TestContext: Sized + Send + Sync {
    /// The user type from your backend.
    type User: AuthUser;

    /// Spawn the test app and return (base_url, http_client, context).
    fn spawn() -> impl Future<Output = (String, Client, Self)> + Send;

    /// Spawn the test app with email confirmation required for authentication.
    ///
    /// Default implementation falls back to `spawn()`. Integrations should override this
    /// when they need to validate `require_email_confirmation = true` behavior.
    fn spawn_require_email_confirmation() -> impl Future<Output = (String, Client, Self)> + Send {
        Self::spawn()
    }

    /// Get the auth configuration.
    fn auth_config(&self) -> &AuthConfig;

    /// Get a reference to the auth backend for direct database operations.
    fn backend(&self) -> &impl AuthBackend;

    /// Get a refresh token by its hash (for test assertions).
    fn refresh_token_get(
        &self,
        refresh_token_hash: &str,
    ) -> impl Future<Output = Option<RefreshTokenInfo>> + Send;

    /// Manually expire a refresh token by its hash (for testing expiration).
    fn refresh_token_expire(&self, refresh_token_hash: &str) -> impl Future<Output = ()> + Send;

    /// Update a user's password hash directly in storage.
    ///
    /// Used by race/concurrency tests to simulate stale sign-in state.
    fn user_password_hash_set(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> impl Future<Output = ()> + Send;
}

/// Test suite for fast-auth.
///
/// Run all tests with `Suite::<YourContext>::test_all()`.
pub struct Suite<C: TestContext> {
    _marker: std::marker::PhantomData<C>,
}

impl<C: TestContext> Suite<C> {
    /// Run all auth tests.
    pub async fn test_all() {
        // Sign-up tests
        sign_up::sign_up_creates_user_and_sets_cookies::<C>().await;
        sign_up::sign_up_rejects_duplicate_email::<C>().await;
        sign_up::sign_up_rejects_invalid_email::<C>().await;
        sign_up::sign_up_rejects_sql_injection_email_payload::<C>().await;
        sign_up::sign_up_allows_single_quote_email_as_literal::<C>().await;
        sign_up::sign_up_enforces_password_complexity_rules::<C>().await;
        sign_up::sign_up_handles_concurrent_duplicate_requests::<C>().await;

        // Sign-in tests
        sign_in::sign_in_returns_tokens_for_valid_credentials::<C>().await;
        sign_in::sign_in_rejects_invalid_passwords::<C>().await;
        sign_in::sign_in_rejects_sql_injection_email_payload::<C>().await;
        sign_in::sign_in_treats_sql_like_password_as_literal::<C>().await;
        sign_in::sign_in_revokes_existing_refresh_tokens::<C>().await;
        sign_in::session_issue_rejects_stale_password_hash::<C>().await;

        // Sign-out tests
        sign_out::sign_out_revokes_refresh_token_and_clears_cookies::<C>().await;
        sign_out::sign_out_requires_refresh_cookie::<C>().await;
        sign_out::sign_out_rejects_unknown_refresh_token_without_leaking_state::<C>().await;
        sign_out::sign_out_cannot_be_replayed_with_same_refresh_token::<C>().await;

        // Access-token and refresh tests
        access_and_refresh::protected_route_requires_access_token::<C>().await;
        access_and_refresh::protected_route_rejects_expired_access_token::<C>().await;
        access_and_refresh::refresh_endpoint_accepts_valid_refresh_token::<C>().await;
        access_and_refresh::refresh_endpoint_rejects_expired_refresh_token::<C>().await;
        access_and_refresh::refresh_endpoint_rejects_revoked_refresh_token::<C>().await;
        access_and_refresh::refresh_endpoint_rotates_refresh_token_and_rejects_replay::<C>().await;
        access_and_refresh::refresh_endpoint_race_has_single_winner::<C>().await;
        access_and_refresh::session_exchange_race_has_single_winner::<C>().await;

        // API key tests
        api_keys::api_key_create_list_use_delete_flow::<C>().await;
        api_keys::api_keys_are_scoped_to_active_organization::<C>().await;
        api_keys::bearer_api_key_takes_precedence_over_cookie::<C>().await;
        api_keys::invalid_api_key_returns_unauthorized::<C>().await;

        // Organization tests
        organizations::organizations_include_default_membership_and_support_crud::<C>().await;
        organizations::organization_switch_updates_active_auth_context::<C>().await;
        organizations::organization_invite_accept_adds_membership_and_switches_context::<C>().await;
        organizations::organization_invite_revoke_prevents_acceptance::<C>().await;
        organizations::organization_invite_accept_rejects_wrong_email::<C>().await;
        organizations::organization_invite_accept_rejects_reuse::<C>().await;
        organizations::organization_member_role_gates_admin_routes::<C>().await;
        organizations::organization_member_role_update_requires_owner::<C>().await;
        organizations::organization_cross_org_admin_routes_return_not_found::<C>().await;
        organizations::organization_admin_can_manage_members_and_invites::<C>().await;

        // Verification tests
        verification::sign_in_rejects_unconfirmed_user_when_confirmation_required::<C>().await;
        verification::sign_up_skips_cookie_issuance_when_confirmation_required::<C>().await;
        verification::refresh_rejects_unconfirmed_user_when_confirmation_required::<C>().await;
        verification::email_confirm_marks_user_confirmed::<C>().await;
        verification::email_confirm_supports_get_link_flow::<C>().await;
        verification::email_confirm_rejects_expired_token_get::<C>().await;
        verification::email_confirm_token_is_single_use::<C>().await;
        verification::password_reset_updates_password_and_revokes_sessions::<C>().await;
        verification::password_reset_rejects_expired_token::<C>().await;
        verification::password_reset_token_is_single_use::<C>().await;
        verification::verification_token_type_mismatch_is_rejected::<C>().await;
        verification::verification_rejects_malformed_token::<C>().await;
        verification::password_reset_does_not_change_password_on_invalid_token::<C>().await;
    }
}

/// Generates individual test functions for the auth suite.
///
/// This macro creates a `#[tokio::test]` function for each test case in the suite,
/// ensuring they run individually and report separate results.
///
/// # Example
///
/// ```rust,ignore
/// fast_auth::test_suite!(MyContext);
/// ```
#[macro_export]
macro_rules! test_suite {
    ($context:ty) => {
        #[tokio::test]
        async fn sign_up_creates_user_and_sets_cookies() {
            $crate::testing::sign_up::sign_up_creates_user_and_sets_cookies::<$context>().await;
        }

        #[tokio::test]
        async fn sign_up_rejects_duplicate_email() {
            $crate::testing::sign_up::sign_up_rejects_duplicate_email::<$context>().await;
        }

        #[tokio::test]
        async fn sign_up_rejects_invalid_email() {
            $crate::testing::sign_up::sign_up_rejects_invalid_email::<$context>().await;
        }

        #[tokio::test]
        async fn sign_up_rejects_sql_injection_email_payload() {
            $crate::testing::sign_up::sign_up_rejects_sql_injection_email_payload::<$context>().await;
        }

        #[tokio::test]
        async fn sign_up_allows_single_quote_email_as_literal() {
            $crate::testing::sign_up::sign_up_allows_single_quote_email_as_literal::<$context>()
                .await;
        }

        #[tokio::test]
        async fn sign_up_enforces_password_complexity_rules() {
            $crate::testing::sign_up::sign_up_enforces_password_complexity_rules::<$context>().await;
        }

        #[tokio::test]
        async fn sign_up_handles_concurrent_duplicate_requests() {
            $crate::testing::sign_up::sign_up_handles_concurrent_duplicate_requests::<$context>().await;
        }

        #[tokio::test]
        async fn sign_in_returns_tokens_for_valid_credentials() {
            $crate::testing::sign_in::sign_in_returns_tokens_for_valid_credentials::<$context>().await;
        }

        #[tokio::test]
        async fn sign_in_rejects_invalid_passwords() {
            $crate::testing::sign_in::sign_in_rejects_invalid_passwords::<$context>().await;
        }

        #[tokio::test]
        async fn sign_in_rejects_sql_injection_email_payload() {
            $crate::testing::sign_in::sign_in_rejects_sql_injection_email_payload::<$context>()
                .await;
        }

        #[tokio::test]
        async fn sign_in_treats_sql_like_password_as_literal() {
            $crate::testing::sign_in::sign_in_treats_sql_like_password_as_literal::<$context>()
                .await;
        }

        #[tokio::test]
        async fn sign_in_revokes_existing_refresh_tokens() {
            $crate::testing::sign_in::sign_in_revokes_existing_refresh_tokens::<$context>().await;
        }

        #[tokio::test]
        async fn session_issue_rejects_stale_password_hash() {
            $crate::testing::sign_in::session_issue_rejects_stale_password_hash::<$context>().await;
        }

        #[tokio::test]
        async fn sign_out_revokes_refresh_token_and_clears_cookies() {
            $crate::testing::sign_out::sign_out_revokes_refresh_token_and_clears_cookies::<$context>().await;
        }

        #[tokio::test]
        async fn sign_out_requires_refresh_cookie() {
            $crate::testing::sign_out::sign_out_requires_refresh_cookie::<$context>().await;
        }

        #[tokio::test]
        async fn sign_out_rejects_unknown_refresh_token_without_leaking_state() {
            $crate::testing::sign_out::sign_out_rejects_unknown_refresh_token_without_leaking_state::<$context>().await;
        }

        #[tokio::test]
        async fn sign_out_cannot_be_replayed_with_same_refresh_token() {
            $crate::testing::sign_out::sign_out_cannot_be_replayed_with_same_refresh_token::<$context>().await;
        }

        #[tokio::test]
        async fn protected_route_requires_access_token() {
            $crate::testing::access_and_refresh::protected_route_requires_access_token::<$context>().await;
        }

        #[tokio::test]
        async fn protected_route_rejects_expired_access_token() {
            $crate::testing::access_and_refresh::protected_route_rejects_expired_access_token::<$context>().await;
        }

        #[tokio::test]
        async fn refresh_endpoint_accepts_valid_refresh_token() {
            $crate::testing::access_and_refresh::refresh_endpoint_accepts_valid_refresh_token::<$context>().await;
        }

        #[tokio::test]
        async fn refresh_endpoint_rejects_expired_refresh_token() {
            $crate::testing::access_and_refresh::refresh_endpoint_rejects_expired_refresh_token::<$context>().await;
        }

        #[tokio::test]
        async fn refresh_endpoint_rejects_revoked_refresh_token() {
            $crate::testing::access_and_refresh::refresh_endpoint_rejects_revoked_refresh_token::<$context>().await;
        }

        #[tokio::test]
        async fn refresh_endpoint_rotates_refresh_token_and_rejects_replay() {
            $crate::testing::access_and_refresh::refresh_endpoint_rotates_refresh_token_and_rejects_replay::<$context>().await;
        }

        #[tokio::test]
        async fn refresh_endpoint_race_has_single_winner() {
            $crate::testing::access_and_refresh::refresh_endpoint_race_has_single_winner::<$context>().await;
        }

        #[tokio::test]
        async fn session_exchange_race_has_single_winner() {
            $crate::testing::access_and_refresh::session_exchange_race_has_single_winner::<$context>().await;
        }

        #[tokio::test]
        async fn api_key_create_list_use_delete_flow() {
            $crate::testing::api_keys::api_key_create_list_use_delete_flow::<$context>().await;
        }

        #[tokio::test]
        async fn api_keys_are_scoped_to_active_organization() {
            $crate::testing::api_keys::api_keys_are_scoped_to_active_organization::<$context>()
                .await;
        }

        #[tokio::test]
        async fn bearer_api_key_takes_precedence_over_cookie() {
            $crate::testing::api_keys::bearer_api_key_takes_precedence_over_cookie::<$context>()
                .await;
        }

        #[tokio::test]
        async fn invalid_api_key_returns_unauthorized() {
            $crate::testing::api_keys::invalid_api_key_returns_unauthorized::<$context>().await;
        }

        #[tokio::test]
        async fn organizations_include_default_membership_and_support_crud() {
            $crate::testing::organizations::organizations_include_default_membership_and_support_crud::<$context>().await;
        }

        #[tokio::test]
        async fn organization_switch_updates_active_auth_context() {
            $crate::testing::organizations::organization_switch_updates_active_auth_context::<$context>().await;
        }

        #[tokio::test]
        async fn organization_invite_accept_adds_membership_and_switches_context() {
            $crate::testing::organizations::organization_invite_accept_adds_membership_and_switches_context::<$context>().await;
        }

        #[tokio::test]
        async fn organization_invite_revoke_prevents_acceptance() {
            $crate::testing::organizations::organization_invite_revoke_prevents_acceptance::<$context>().await;
        }

        #[tokio::test]
        async fn organization_invite_accept_rejects_wrong_email() {
            $crate::testing::organizations::organization_invite_accept_rejects_wrong_email::<$context>().await;
        }

        #[tokio::test]
        async fn organization_invite_accept_rejects_reuse() {
            $crate::testing::organizations::organization_invite_accept_rejects_reuse::<$context>().await;
        }

        #[tokio::test]
        async fn organization_member_role_gates_admin_routes() {
            $crate::testing::organizations::organization_member_role_gates_admin_routes::<$context>().await;
        }

        #[tokio::test]
        async fn organization_member_role_update_requires_owner() {
            $crate::testing::organizations::organization_member_role_update_requires_owner::<$context>().await;
        }

        #[tokio::test]
        async fn organization_cross_org_admin_routes_return_not_found() {
            $crate::testing::organizations::organization_cross_org_admin_routes_return_not_found::<$context>().await;
        }

        #[tokio::test]
        async fn organization_admin_can_manage_members_and_invites() {
            $crate::testing::organizations::organization_admin_can_manage_members_and_invites::<$context>().await;
        }

        #[tokio::test]
        async fn sign_in_rejects_unconfirmed_user_when_confirmation_required() {
            $crate::testing::verification::sign_in_rejects_unconfirmed_user_when_confirmation_required::<$context>().await;
        }

        #[tokio::test]
        async fn sign_up_skips_cookie_issuance_when_confirmation_required() {
            $crate::testing::verification::sign_up_skips_cookie_issuance_when_confirmation_required::<$context>().await;
        }

        #[tokio::test]
        async fn refresh_rejects_unconfirmed_user_when_confirmation_required() {
            $crate::testing::verification::refresh_rejects_unconfirmed_user_when_confirmation_required::<$context>().await;
        }

        #[tokio::test]
        async fn email_confirm_marks_user_confirmed() {
            $crate::testing::verification::email_confirm_marks_user_confirmed::<$context>().await;
        }

        #[tokio::test]
        async fn email_confirm_supports_get_link_flow() {
            $crate::testing::verification::email_confirm_supports_get_link_flow::<$context>().await;
        }

        #[tokio::test]
        async fn email_confirm_rejects_expired_token_get() {
            $crate::testing::verification::email_confirm_rejects_expired_token_get::<$context>().await;
        }

        #[tokio::test]
        async fn email_confirm_token_is_single_use() {
            $crate::testing::verification::email_confirm_token_is_single_use::<$context>().await;
        }

        #[tokio::test]
        async fn password_reset_updates_password_and_revokes_sessions() {
            $crate::testing::verification::password_reset_updates_password_and_revokes_sessions::<$context>().await;
        }

        #[tokio::test]
        async fn password_reset_rejects_expired_token() {
            $crate::testing::verification::password_reset_rejects_expired_token::<$context>().await;
        }

        #[tokio::test]
        async fn password_reset_token_is_single_use() {
            $crate::testing::verification::password_reset_token_is_single_use::<$context>().await;
        }

        #[tokio::test]
        async fn verification_token_type_mismatch_is_rejected() {
            $crate::testing::verification::verification_token_type_mismatch_is_rejected::<$context>().await;
        }

        #[tokio::test]
        async fn verification_rejects_malformed_token() {
            $crate::testing::verification::verification_rejects_malformed_token::<$context>().await;
        }

        #[tokio::test]
        async fn password_reset_does_not_change_password_on_invalid_token() {
            $crate::testing::verification::password_reset_does_not_change_password_on_invalid_token::<$context>().await;
        }
    };
}
