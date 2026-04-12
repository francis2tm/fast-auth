//! Fast, extensible authentication library for Axum with JWT, refresh tokens,
//! and user API keys.
//!
//! This crate provides email/password authentication with:
//! - JWT access tokens (short-lived)
//! - Refresh tokens (long-lived, stored in database)
//! - Explicit session refresh via `/auth/refresh`
//! - Bearer API keys for non-browser integrations
//! - API key management routes under `/auth/api-keys`
//! - Lifecycle hooks for sign-up/sign-in events
//! - Storage-agnostic design via [`AuthBackend`] trait
//! - Reusable integration test suite (via `testing` feature)
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use fast_auth::{Auth, AuthConfig};
//!
//! # fn app_build<B: fast_auth::AuthBackend>(backend: B) -> Result<(), fast_auth::AuthConfigError> {
//! let mut config = AuthConfig::default();
//! config.jwt_secret = "your-secret-key-at-least-32-characters-long".to_string();
//! let auth = Auth::new(config, backend)?;
//!
//! let app: axum::Router = auth.routes::<Auth<B>>().with_state(auth);
//! # let _ = app;
//! # Ok(())
//! # }
//! ```

pub mod api_key;
mod backend;
mod config;
mod cookies;
mod email;
mod email_sender;
mod error;
mod extractors;
pub mod handlers;
pub mod middleware;
pub mod openapi;
mod password;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tokens;
pub mod verification;
mod verification_email;

pub use api_key::{api_key_generate, api_key_hash, api_key_issue, api_key_prefix_extract};
use axum::{
    Json, Router,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
pub use backend::{
    ApiKey, ApiKeyCreateParams, ApiKeyListSortBy, ApiKeyWithSecret, AuthBackend, AuthBackendError,
    AuthBackendErrorKind, AuthUser, HydratedUser, Organization, OrganizationInvite,
    OrganizationInviteWithSecret, OrganizationMember, OrganizationRole, SessionExchangeParams,
    SessionIssueIfPasswordHashParams, UserCreateParams, UserCreated, VerificationTokenIssueParams,
};
pub use config::{AuthConfig, AuthConfigError, CookieSameSite, config_toml_parse};
pub use email_sender::{EmailSendError, EmailSender};
pub use error::AuthError;
pub use extractors::{RequestAdmin, RequestOwner, RequestUser};
pub use handlers::api_keys::{
    ApiKeyCreateRequest, ApiKeyCreateResponse, ApiKeyListQuery, ApiKeySummary,
};
pub use handlers::organizations::{
    OrganizationCreateRequest, OrganizationInviteAcceptRequest, OrganizationInviteCreateRequest,
    OrganizationRoleUpdateRequest, OrganizationSwitchRequest, OrganizationUpdateRequest,
};
pub use handlers::sign_in::SignInRequest;
pub use handlers::sign_out::SignOutResponse;
pub use handlers::sign_up::SignUpRequest;
pub use password::password_verify;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::Arc;
use utoipa::ToSchema;

/// User data returned in auth responses.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub email_confirmed_at: Option<String>,
}

/// Active organization returned in auth responses.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub role: OrganizationRole,
}

/// Auth response body. Tokens are set as httpOnly cookies.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub organization: OrganizationResponse,
    pub auth_role: String,
}

/// Build one public authenticated-user response.
pub fn auth_response_build(hydrated_user: &HydratedUser) -> AuthResponse {
    AuthResponse {
        user: UserResponse {
            id: hydrated_user.user_id.to_string(),
            email: hydrated_user.email.clone(),
            email_confirmed_at: hydrated_user.email_confirmed_at.map(|dt| dt.to_rfc3339()),
        },
        organization: OrganizationResponse {
            id: hydrated_user.organization_id.to_string(),
            name: hydrated_user.organization_name.clone(),
            role: hydrated_user.organization_role,
        },
        auth_role: hydrated_user.role.clone(),
    }
}

/// Build one auth response with updated cookies.
pub fn auth_response_with_cookies_build(jar: CookieJar, hydrated_user: &HydratedUser) -> Response {
    (jar, Json(auth_response_build(hydrated_user))).into_response()
}

/// Hooks for auth lifecycle events (sign-up, sign-in).
///
/// Implement this trait to receive callbacks when authenticated users sign up or sign in.
///
/// # Example
///
/// ```rust,no_run
/// use fast_auth::{AuthHooks, HydratedUser};
///
/// #[derive(Clone)]
/// struct MyHooks;
///
/// impl AuthHooks for MyHooks {
///     fn on_sign_up(&self, hydrated_user: &HydratedUser) -> impl std::future::Future<Output = ()> + Send {
///         let organization_id = hydrated_user.organization_id;
///         async move { println!("Provisioned org {organization_id}!"); }
///     }
/// }
/// ```
pub trait AuthHooks: Send + Sync + Clone + 'static {
    /// Called after an authenticated user is created.
    fn on_sign_up(&self, _hydrated_user: &HydratedUser) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Called after an authenticated user signs in.
    fn on_sign_in(&self, _hydrated_user: &HydratedUser) -> impl Future<Output = ()> + Send {
        async {}
    }
}

impl AuthHooks for () {}

/// Email/password auth with JWT tokens. Cheap to clone.
///
/// Generic over:
/// - `B`: The storage backend implementing [`AuthBackend`]
/// - `H`: Optional lifecycle hooks implementing [`AuthHooks`]
/// - `E`: Optional email sender implementing [`EmailSender`]
///
/// # Example
///
/// ```rust,no_run
/// use fast_auth::{Auth, AuthConfig};
///
/// # fn auth_build<B: fast_auth::AuthBackend>(backend: B) -> Result<(), fast_auth::AuthConfigError> {
/// let mut config = AuthConfig::default();
/// config.jwt_secret = "your-secret-key-at-least-32-characters-long".to_string();
/// let auth = Auth::new(config, backend)?;
/// # let _ = auth;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Auth<B: AuthBackend, H: AuthHooks = (), E: EmailSender = ()> {
    config: Arc<AuthConfig>,
    backend: B,
    hooks: H,
    email_sender: E,
}

impl<B: AuthBackend> Auth<B, (), ()> {
    /// Create an auth instance with default (no-op) hooks and email sender.
    pub fn new(config: AuthConfig, backend: B) -> Result<Self, AuthConfigError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            backend,
            hooks: (),
            email_sender: (),
        })
    }
}

impl<B: AuthBackend, H: AuthHooks, E: EmailSender> Auth<B, H, E> {
    /// Attach custom lifecycle hooks.
    pub fn with_hooks<NewH: AuthHooks>(self, hooks: NewH) -> Auth<B, NewH, E> {
        Auth {
            config: self.config,
            backend: self.backend,
            hooks,
            email_sender: self.email_sender,
        }
    }

    /// Attach a custom email sender.
    pub fn with_email_sender<NewE: EmailSender>(self, email_sender: NewE) -> Auth<B, H, NewE> {
        Auth {
            config: self.config,
            backend: self.backend,
            hooks: self.hooks,
            email_sender,
        }
    }

    /// Returns a router with all auth endpoints.
    pub fn routes<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
        Auth<B, H, E>: axum::extract::FromRef<S>,
    {
        Router::new()
            .merge(handlers::sign_up_routes::<B, H, E>())
            .merge(handlers::sign_in_routes::<B, H, E>())
            .merge(handlers::refresh_routes::<B, H, E>())
            .merge(handlers::sign_out_routes::<B, H, E>())
            .merge(handlers::api_key_routes::<B, H, E>())
            .merge(handlers::me_routes::<B, H, E>())
            .merge(handlers::organization_routes::<B, H, E>())
            .merge(handlers::email_confirm_routes::<B, H, E>())
            .merge(handlers::password_reset_routes::<B, H, E>())
            .with_state(self.clone())
    }

    /// Returns a reference to the auth configuration.
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Returns a reference to the storage backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Returns a reference to the lifecycle hooks.
    pub(crate) fn hooks(&self) -> &H {
        &self.hooks
    }

    /// Returns a reference to the email sender.
    pub fn email_sender(&self) -> &E {
        &self.email_sender
    }
}
