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

pub mod protected_route;
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
use crate::handlers::SIGN_UP_PATH;
use crate::{AuthConfig, AuthUser};

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

        let access_token = Self::extract_cookie(resp.headers(), &config.cookie_access_token_name);
        let refresh_token = Self::extract_cookie(resp.headers(), &config.cookie_refresh_token_name);

        Self {
            email,
            password: password.to_string(),
            access_token,
            refresh_token,
        }
    }

    /// Extract a cookie value from response headers.
    pub fn extract_cookie(headers: &reqwest::header::HeaderMap, name: &str) -> String {
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let c = Cookie::parse(v.to_str().ok()?.to_string()).ok()?;
                (c.name() == name).then(|| c.value().to_string())
            })
            .unwrap_or_default()
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
        sign_up::sign_up_enforces_password_complexity_rules::<C>().await;

        // Sign-in tests
        sign_in::sign_in_returns_tokens_for_valid_credentials::<C>().await;
        sign_in::sign_in_rejects_invalid_passwords::<C>().await;
        sign_in::sign_in_revokes_existing_refresh_tokens::<C>().await;
        sign_in::sign_in_expired_refresh_token_requires_sign_in::<C>().await;

        // Sign-out tests
        sign_out::sign_out_revokes_refresh_token_and_clears_cookies::<C>().await;
        sign_out::sign_out_requires_refresh_cookie::<C>().await;
        sign_out::sign_out_rejects_unknown_refresh_token_without_leaking_state::<C>().await;
        sign_out::sign_out_cannot_be_replayed_with_same_refresh_token::<C>().await;

        // Protected route tests
        protected_route::protected_route_accepts_valid_refresh_token::<C>().await;
        protected_route::protected_route_refreshes_expired_access_token::<C>().await;
        protected_route::protected_route_rejects_expired_refresh_token::<C>().await;
        protected_route::protected_route_rejects_revoked_refresh_token::<C>().await;
        protected_route::protected_route_rotates_refresh_token_and_rejects_replay::<C>().await;

        // Verification tests
        verification::sign_in_rejects_unconfirmed_user_when_confirmation_required::<C>().await;
        verification::sign_up_skips_cookie_issuance_when_confirmation_required::<C>().await;
        verification::protected_route_rejects_unconfirmed_user_when_confirmation_required::<C>()
            .await;
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
        async fn sign_up_enforces_password_complexity_rules() {
            $crate::testing::sign_up::sign_up_enforces_password_complexity_rules::<$context>().await;
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
        async fn sign_in_revokes_existing_refresh_tokens() {
            $crate::testing::sign_in::sign_in_revokes_existing_refresh_tokens::<$context>().await;
        }

        #[tokio::test]
        async fn sign_in_expired_refresh_token_requires_sign_in() {
            $crate::testing::sign_in::sign_in_expired_refresh_token_requires_sign_in::<$context>().await;
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
        async fn protected_route_accepts_valid_refresh_token() {
            $crate::testing::protected_route::protected_route_accepts_valid_refresh_token::<$context>().await;
        }

        #[tokio::test]
        async fn protected_route_refreshes_expired_access_token() {
            $crate::testing::protected_route::protected_route_refreshes_expired_access_token::<$context>().await;
        }

        #[tokio::test]
        async fn protected_route_rejects_expired_refresh_token() {
            $crate::testing::protected_route::protected_route_rejects_expired_refresh_token::<$context>().await;
        }

        #[tokio::test]
        async fn protected_route_rejects_revoked_refresh_token() {
            $crate::testing::protected_route::protected_route_rejects_revoked_refresh_token::<$context>().await;
        }

        #[tokio::test]
        async fn protected_route_rotates_refresh_token_and_rejects_replay() {
            $crate::testing::protected_route::protected_route_rotates_refresh_token_and_rejects_replay::<$context>().await;
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
        async fn protected_route_rejects_unconfirmed_user_when_confirmation_required() {
            $crate::testing::verification::protected_route_rejects_unconfirmed_user_when_confirmation_required::<$context>().await;
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
