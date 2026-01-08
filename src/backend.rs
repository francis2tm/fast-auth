//! Backend trait for database operations.
//!
//! This module defines the traits that abstract database operations,
//! allowing `fast-auth` to work with any database backend.

use chrono::{DateTime, Utc};
use std::future::Future;
use uuid::Uuid;

/// User data required by the auth system.
///
/// Implement this trait for your user model to use with `fast-auth`.
///
/// # Example
///
/// ```rust
/// use fast_auth::AuthUser;
/// use uuid::Uuid;
/// use chrono::{DateTime, Utc};
///
/// #[derive(Clone)]
/// struct MyUser {
///     id: Uuid,
///     email: String,
///     password_hash: String,
///     email_confirmed_at: Option<DateTime<Utc>>,
///     created_at: DateTime<Utc>,
/// }
///
/// impl AuthUser for MyUser {
///     fn id(&self) -> Uuid { self.id }
///     fn email(&self) -> &str { &self.email }
///     fn password_hash(&self) -> &str { &self.password_hash }
///     fn email_confirmed_at(&self) -> Option<DateTime<Utc>> { self.email_confirmed_at }
///     fn created_at(&self) -> DateTime<Utc> { self.created_at }
/// }
/// ```
pub trait AuthUser: Clone + Send + Sync + 'static {
    /// Returns the user's unique identifier.
    fn id(&self) -> Uuid;

    /// Returns the user's email address.
    fn email(&self) -> &str;

    /// Returns the user's password hash (for verification).
    fn password_hash(&self) -> &str;

    /// Returns when the user's email was confirmed, if ever.
    fn email_confirmed_at(&self) -> Option<DateTime<Utc>>;

    /// Returns when the user was created.
    fn created_at(&self) -> DateTime<Utc>;
}

/// Refresh token data required by the auth system.
///
/// Implement this trait for your refresh token model.
pub trait AuthRefreshToken: Send + Sync {
    /// Returns the user ID this token belongs to.
    fn user_id(&self) -> Uuid;

    /// Returns when this token expires.
    fn expires_at(&self) -> DateTime<Utc>;

    /// Returns when this token was revoked, if ever.
    fn revoked_at(&self) -> Option<DateTime<Utc>>;
}

/// Backend trait for auth database operations.
///
/// Implement this trait to provide database operations for the auth system.
/// All operations should use a service role (bypassing RLS) internally.
///
/// # Example
///
/// ```rust,ignore
/// use fast_auth::{AuthBackend, AuthUser, AuthRefreshToken};
///
/// #[derive(Clone)]
/// struct MyDbPool { /* ... */ }
///
/// impl AuthBackend for MyDbPool {
///     type User = MyUser;
///     type RefreshToken = MyRefreshToken;
///     type Error = MyError;
///
///     async fn user_find_by_email(&self, email: &str) -> Result<Option<Self::User>, Self::Error> {
///         // Query your database...
///         Ok(None)
///     }
///
///     // ... implement other methods
/// }
/// ```
pub trait AuthBackend: Clone + Send + Sync + 'static {
    /// The user type returned by this backend.
    type User: AuthUser;

    /// The refresh token type returned by this backend.
    type RefreshToken: AuthRefreshToken;

    /// The error type for database operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find a user by their email address.
    ///
    /// Returns `Ok(None)` if no user with that email exists.
    fn user_find_by_email(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;

    /// Create a new user with the given details.
    ///
    /// Should check for existing users atomically to prevent race conditions.
    /// Returns the created user on success.
    fn user_create(
        &self,
        id: Uuid,
        email: String,
        password_hash: String,
    ) -> impl Future<Output = Result<Self::User, Self::Error>> + Send;

    /// Update the user's last sign-in timestamp.
    fn user_update_last_sign_in(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Find a user by their ID.
    ///
    /// Returns `Ok(None)` if no user with that ID exists.
    fn user_find_by_id(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;

    /// Store a new refresh token.
    ///
    /// This should also revoke all existing refresh tokens for the user
    /// to enforce single-session semantics.
    fn refresh_token_create(
        &self,
        hash: String,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Find a valid (non-revoked, non-expired) refresh token by its hash.
    ///
    /// Returns `Ok(None)` if no valid token with that hash exists.
    fn refresh_token_find_valid(
        &self,
        hash: &str,
    ) -> impl Future<Output = Result<Option<Self::RefreshToken>, Self::Error>> + Send;

    /// Revoke all refresh tokens for a user.
    fn refresh_tokens_revoke_all(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
