//! Backend trait abstraction for storage-agnostic authentication.
//!
//! This module defines the core traits that allow `fast-auth` to work with
//! any database or storage backend.

use chrono::{DateTime, Utc};
use std::future::Future;
use uuid::Uuid;

/// Minimal user interface required by fast-auth.
///
/// Implement this trait for your user type to use with [`AuthBackend`].
/// This decouples the auth library from any specific user schema.
///
/// # Example
///
/// ```rust,ignore
/// use fast_auth::AuthUser;
/// use chrono::{DateTime, Utc};
/// use uuid::Uuid;
///
/// #[derive(Clone)]
/// struct MyUser {
///     id: Uuid,
///     email: String,
///     password_hash: String,
///     // ... your custom fields
/// }
///
/// impl AuthUser for MyUser {
///     fn id(&self) -> Uuid { self.id }
///     fn email(&self) -> &str { &self.email }
///     fn password_hash(&self) -> &str { &self.password_hash }
///     fn email_confirmed_at(&self) -> Option<DateTime<Utc>> { None }
///     fn last_sign_in_at(&self) -> Option<DateTime<Utc>> { None }
///     fn created_at(&self) -> DateTime<Utc> { Utc::now() }
/// }
/// ```
pub trait AuthUser: Send + Sync + Clone {
    /// Returns the user's unique identifier.
    fn id(&self) -> Uuid;

    /// Returns the user's email address.
    fn email(&self) -> &str;

    /// Returns the user's hashed password.
    fn password_hash(&self) -> &str;

    /// Returns when the email was confirmed, if ever.
    fn email_confirmed_at(&self) -> Option<DateTime<Utc>>;

    /// Returns when the user last signed in, if ever.
    fn last_sign_in_at(&self) -> Option<DateTime<Utc>>;

    /// Returns when the user was created.
    fn created_at(&self) -> DateTime<Utc>;
}

/// Backend storage trait for authentication operations.
///
/// Implement this trait to use any database or storage system with fast-auth.
/// All operations should be atomic where applicable (e.g., user creation with
/// duplicate check should use transactions).
///
/// # Type Parameters
///
/// * `User` - Your user type implementing [`AuthUser`]
/// * `Error` - Your error type for storage operations
///
/// # Example
///
/// ```rust,ignore
/// use fast_auth::{AuthBackend, AuthUser};
/// use chrono::{DateTime, Utc};
/// use uuid::Uuid;
///
/// #[derive(Clone)]
/// struct MyBackend { /* your pool/connection */ }
///
/// impl AuthBackend for MyBackend {
///     type User = MyUser;
///     type Error = MyError;
///
///     async fn user_find_by_email(&self, email: &str)
///         -> Result<Option<Self::User>, Self::Error> {
///         // Query your database
///         Ok(None)
///     }
///     // ... implement other methods
/// }
/// ```
pub trait AuthBackend: Clone + Send + Sync + 'static {
    /// The user type stored in this backend.
    type User: AuthUser;

    /// Error type for storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find a user by email address.
    ///
    /// Returns `None` if no user exists with the given email.
    fn user_find_by_email(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;

    /// Find a user by their unique ID.
    ///
    /// Returns `None` if no user exists with the given ID.
    fn user_get_by_id(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;

    /// Atomically create a new user with the given email and password hash.
    ///
    /// This must check for existing users and create the new user within a single
    /// transaction to prevent race conditions. Returns `Err` if a user with this
    /// email already exists.
    fn user_create_atomic(
        &self,
        email: &str,
        password_hash: &str,
    ) -> impl Future<Output = Result<Self::User, Self::Error>> + Send;

    /// Update the last sign-in timestamp for a user.
    fn user_last_sign_in_update(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Atomically revoke all existing refresh tokens for a user and create a new one.
    ///
    /// This must be implemented atomically (e.g. in a database transaction) to prevent
    /// race conditions where concurrent sign-ins could result in multiple valid sessions.
    fn refresh_token_rotate_atomic(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Revoke a specific refresh token by its hash.
    ///
    /// Returns `true` if a token was revoked, `false` if not found or already revoked.
    fn refresh_token_revoke(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Validate a refresh token and return the associated user ID.
    ///
    /// Returns `None` if the token is invalid, expired, or revoked.
    fn refresh_token_validate(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = Result<Option<Uuid>, Self::Error>> + Send;
}
