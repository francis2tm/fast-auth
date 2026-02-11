//! Fast, extensible authentication library for Axum with JWT and refresh tokens.
//!
//! This crate provides email/password authentication with:
//! - JWT access tokens (short-lived)
//! - Refresh tokens (long-lived, stored in database)
//! - Automatic token refresh via middleware
//! - Lifecycle hooks for sign-up/sign-in events
//! - Storage-agnostic design via [`AuthBackend`] trait
//! - Reusable integration test suite (via `testing` feature)
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fast_auth::{Auth, AuthConfig};
//! use axum::{Router, extract::FromRef};
//!
//! let backend = /* your AuthBackend implementation */;
//! let secret = "your-secret-key-at-least-32-characters-long".to_string();
//! let auth = Auth::new(AuthConfig { jwt_secret: secret, ..Default::default() }, backend).unwrap();
//!
//! let app = Router::new()
//!     .merge(auth.routes())
//!     .with_state(auth);
//! ```

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

use axum::Router;
pub use backend::{AuthBackend, AuthBackendError, AuthUser};
pub use config::{AuthConfig, AuthConfigError, CookieSameSite, config_toml_parse};
pub use email_sender::{EmailSendError, EmailSender};
pub use error::AuthError;
pub use extractors::CurrentUser;
pub use handlers::sign_in::SignInRequest;
pub use handlers::sign_out::SignOutResponse;
pub use handlers::sign_up::SignUpRequest;
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
    pub created_at: String,
}

/// Auth response body. Tokens are set as httpOnly cookies.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthCookieResponse {
    pub user: UserResponse,
}

/// Hooks for auth lifecycle events (sign-up, sign-in).
///
/// Implement this trait to receive callbacks when users sign up or sign in.
/// The user parameter uses your backend's user type via [`AuthBackend::User`].
///
/// # Example
///
/// ```rust,no_run
/// use fast_auth::{AuthHooks, AuthUser};
///
/// #[derive(Clone)]
/// struct MyHooks;
///
/// impl<U: AuthUser> AuthHooks<U> for MyHooks {
///     fn on_sign_up(&self, user: &U) -> impl std::future::Future<Output = ()> + Send {
///         let user_id = user.id();
///         async move { println!("User {user_id} signed up!"); }
///     }
/// }
/// ```
pub trait AuthHooks<U: AuthUser>: Send + Sync + Clone + 'static {
    /// Called after a user is created.
    fn on_sign_up(&self, _user: &U) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Called after a user signs in.
    fn on_sign_in(&self, _user: &U) -> impl Future<Output = ()> + Send {
        async {}
    }
}

impl<U: AuthUser> AuthHooks<U> for () {}

/// Email/password auth with JWT tokens. Cheap to clone.
///
/// Generic over:
/// - `B`: The storage backend implementing [`AuthBackend`]
/// - `H`: Optional lifecycle hooks implementing [`AuthHooks`]
/// - `E`: Optional email sender implementing [`EmailSender`]
///
/// # Example
///
/// ```rust,ignore
/// use fast_auth::{Auth, AuthConfig, AuthBackend};
///
/// let backend: impl AuthBackend = /* ... */;
/// let secret = "your-secret-key-at-least-32-characters-long".to_string();
/// let auth = Auth::new(AuthConfig { jwt_secret: secret, ..Default::default() }, backend).unwrap();
/// ```
#[derive(Clone)]
pub struct Auth<B: AuthBackend, H: AuthHooks<B::User> = (), E: EmailSender = ()> {
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

impl<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender> Auth<B, H, E> {
    /// Attach custom lifecycle hooks.
    pub fn with_hooks<NewH: AuthHooks<B::User>>(self, hooks: NewH) -> Auth<B, NewH, E> {
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
            .merge(handlers::sign_out_routes::<B, H, E>())
            .merge(handlers::me_routes::<B, H, E>())
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
