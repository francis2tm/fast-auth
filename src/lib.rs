//! # fast-auth
//!
//! A simple, extensible authentication library for Axum with JWT and refresh tokens.
//!
//! ## Features
//!
//! - **JWT access tokens** with configurable expiry
//! - **Refresh tokens** with automatic rotation and revocation
//! - **HttpOnly cookies** for secure token storage
//! - **Extensible backend trait** for any database
//! - **Lifecycle hooks** for sign-up/sign-in events
//! - **Axum middleware** for transparent token validation and refresh
//!
//! ## Quick Start
//!
//! First, implement the [`AuthBackend`] trait for your database:
//!
//! ```rust,ignore
//! use fast_auth::{AuthBackend, AuthUser, AuthRefreshToken};
//!
//! #[derive(Clone)]
//! struct MyBackend { /* your db pool */ }
//!
//! impl AuthBackend for MyBackend {
//!     type User = MyUser;
//!     type RefreshToken = MyRefreshToken;
//!     type Error = MyError;
//!
//!     // ... implement methods
//! }
//! ```
//!
//! Then create an `Auth` instance and add routes:
//!
//! ```rust,ignore
//! use fast_auth::{Auth, AuthConfig};
//! use axum::{Router, extract::FromRef, middleware};
//!
//! let backend = MyBackend::new();
//! let auth = Auth::new(AuthConfig::from_env()?, backend)?;
//!
//! #[derive(Clone)]
//! struct AppState {
//!     auth: Auth<MyBackend>,
//! }
//!
//! impl FromRef<AppState> for Auth<MyBackend> {
//!     fn from_ref(s: &AppState) -> Self { s.auth.clone() }
//! }
//!
//! let state = AppState { auth: auth.clone() };
//!
//! let app = Router::new()
//!     .merge(auth.routes::<AppState>())
//!     .layer(middleware::from_fn_with_state(
//!         auth.clone(),
//!         fast_auth::middleware::base::<MyBackend, ()>,
//!     ))
//!     .with_state(state);
//! ```
//!
//! ## Endpoints
//!
//! - `POST /v1/auth/sign-up` - Create new user
//! - `POST /v1/auth/sign-in` - Authenticate user
//! - `POST /v1/auth/sign-out` - Sign out (revokes tokens)
//! - `GET /v1/auth/me` - Get current user (requires auth)
//!
//! ## Hooks
//!
//! Use hooks to run custom logic after authentication events:
//!
//! ```rust,ignore
//! use fast_auth::{Auth, AuthConfig, AuthHooks, AuthUser};
//!
//! #[derive(Clone)]
//! struct MyHooks;
//!
//! impl<U: AuthUser> AuthHooks<U> for MyHooks {
//!     fn on_sign_up(&self, user: &U) -> impl std::future::Future<Output = ()> + Send {
//!         let user_id = user.id();
//!         async move {
//!             // Send welcome email, create Stripe customer, etc.
//!             println!("New user signed up: {user_id}");
//!         }
//!     }
//! }
//!
//! let auth = Auth::new(config, backend)?
//!     .with_hooks(MyHooks);
//! ```

mod backend;
mod config;
mod cookies;
mod email;
mod error;
mod extractors;
pub mod handlers;
pub mod middleware;
mod password;
pub mod tokens;

use axum::Router;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::Arc;

pub use backend::{AuthBackend, AuthRefreshToken, AuthUser};
pub use config::{AuthConfig, AuthConfigError, CookieSameSite};
pub use error::AuthError;
pub use extractors::AuthUserExtractor;
pub use handlers::{SignInRequest, SignOutResponse, SignUpRequest};

/// User data returned in auth responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    /// User ID.
    pub id: String,
    /// User email.
    pub email: String,
    /// When email was confirmed (ISO 8601), if ever.
    pub email_confirmed_at: Option<String>,
    /// When user was created (ISO 8601).
    pub created_at: String,
}

/// Auth response body. Tokens are set as httpOnly cookies.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCookieResponse {
    /// User data.
    pub user: UserResponse,
}

/// Hooks for auth lifecycle events (sign-up, sign-in).
///
/// Implement this trait to run custom logic after authentication events,
/// such as sending welcome emails or creating related resources.
///
/// # Example
///
/// ```rust,ignore
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
/// # Type Parameters
///
/// - `B`: The backend implementing [`AuthBackend`]
/// - `H`: Optional hooks implementing [`AuthHooks`] (defaults to `()`)
///
/// # Example
///
/// ```rust,ignore
/// use fast_auth::{Auth, AuthConfig};
///
/// let auth = Auth::new(AuthConfig::from_env()?, backend)?;
///
/// // With hooks
/// let auth = Auth::new(config, backend)?
///     .with_hooks(MyHooks);
/// ```
#[derive(Clone)]
pub struct Auth<B: AuthBackend, H: AuthHooks<B::User> = ()> {
    config: Arc<AuthConfig>,
    backend: B,
    hooks: H,
}

impl<B: AuthBackend> Auth<B, ()> {
    /// Create an auth instance with default (no-op) hooks.
    pub fn new(config: AuthConfig, backend: B) -> Result<Self, AuthConfigError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            backend,
            hooks: (),
        })
    }
}

impl<B: AuthBackend, H: AuthHooks<B::User>> Auth<B, H> {
    /// Attach custom lifecycle hooks.
    pub fn with_hooks<NewH: AuthHooks<B::User>>(self, hooks: NewH) -> Auth<B, NewH> {
        Auth {
            config: self.config,
            backend: self.backend,
            hooks,
        }
    }

    /// Returns a router with all auth endpoints.
    ///
    /// Endpoints:
    /// - `POST /v1/auth/sign-up`
    /// - `POST /v1/auth/sign-in`
    /// - `POST /v1/auth/sign-out`
    /// - `GET /v1/auth/me`
    pub fn routes<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
        Auth<B, H>: axum::extract::FromRef<S>,
    {
        Router::new()
            .merge(handlers::sign_up_routes::<B, H>())
            .merge(handlers::sign_in_routes::<B, H>())
            .merge(handlers::sign_out_routes::<B, H>())
            .merge(handlers::me_routes::<B, H>())
            .with_state(self.clone())
    }

    /// Returns a reference to the auth configuration.
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Returns a reference to the backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub(crate) fn hooks(&self) -> &H {
        &self.hooks
    }
}
