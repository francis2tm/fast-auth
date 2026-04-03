//! Backend trait abstractions for storage-agnostic authentication.
//!
//! This module defines the minimal contracts `fast-auth` needs from your user model
//! and persistence layer.

use chrono::{DateTime, Utc};
use common::list::{ListPageResult, ListQuery};
use serde::{Deserialize, Serialize};
use std::future::Future;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::AuthError;
use crate::verification::VerificationTokenType;

/// Minimal user interface required by `fast-auth`.
///
/// Implement this trait for your user type so handlers and middleware can build
/// auth responses without depending on a concrete schema.
///
/// # Example
///
/// ```rust,ignore
/// use chrono::{DateTime, Utc};
/// use fast_auth::AuthUser;
/// use uuid::Uuid;
///
/// #[derive(Clone)]
/// struct MyUser {
///     id: Uuid,
///     email: String,
///     password_hash: String,
///     email_confirmed_at: Option<DateTime<Utc>>,
///     last_sign_in_at: Option<DateTime<Utc>>,
///     created_at: DateTime<Utc>,
/// }
///
/// impl AuthUser for MyUser {
///     fn id(&self) -> Uuid { self.id }
///     fn email(&self) -> &str { &self.email }
///     fn password_hash(&self) -> &str { &self.password_hash }
///     fn email_confirmed_at(&self) -> Option<DateTime<Utc>> { self.email_confirmed_at }
///     fn last_sign_in_at(&self) -> Option<DateTime<Utc>> { self.last_sign_in_at }
///     fn created_at(&self) -> DateTime<Utc> { self.created_at }
/// }
/// ```
pub trait AuthUser: Send + Sync + Clone {
    /// Returns the user's unique identifier.
    fn id(&self) -> Uuid;
    /// Returns the user's email address.
    fn email(&self) -> &str;
    /// Returns the stored password hash.
    fn password_hash(&self) -> &str;
    /// Returns the email confirmation timestamp, if confirmed.
    fn email_confirmed_at(&self) -> Option<DateTime<Utc>>;
    /// Returns the latest sign-in timestamp, if available.
    fn last_sign_in_at(&self) -> Option<DateTime<Utc>>;
    /// Returns the account creation timestamp.
    fn created_at(&self) -> DateTime<Utc>;
}

/// Backend error contract for `fast-auth`.
///
/// Implement this for your backend error type so handlers can make consistent
/// decisions without parsing error messages.
pub trait AuthBackendError: std::error::Error + Send + Sync + 'static {
    /// Maps this backend error to the public auth error type.
    fn auth_error(&self) -> AuthError {
        AuthError::Backend(self.to_string())
    }
}

/// Stored API key metadata exposed by auth backends.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthApiKey {
    /// API key identifier.
    pub id: Uuid,
    /// User-defined display name.
    pub name: String,
    /// Stable visible key prefix.
    pub key_prefix: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Sortable columns for API-key listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthApiKeyListSortBy {
    /// Sort by API-key creation timestamp.
    #[default]
    CreatedAt,
    /// Sort by API-key display name.
    Name,
    /// Sort by the most recent successful use timestamp.
    LastUsedAt,
}

/// API key creation result returned only at creation time.
///
/// The plaintext `key` is included here because API keys are stored hashed at
/// rest and cannot be shown again after creation. List/read flows should use
/// [`AuthApiKey`] instead, which exposes metadata only.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthApiKeyWithSecret {
    /// API key identifier.
    pub id: Uuid,
    /// User-defined display name.
    pub name: String,
    /// Plaintext key material returned once.
    pub key: String,
    /// Stable visible key prefix.
    pub key_prefix: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Storage backend contract for authentication operations.
///
/// Session and token mutation methods must be implemented as single race-safe
/// operations (typically one SQL statement or one transaction).
///
/// # Example
///
/// ```rust,ignore
/// use chrono::{DateTime, Utc};
/// use fast_auth::{AuthBackend, AuthUser};
/// use uuid::Uuid;
///
/// #[derive(Clone)]
/// struct MyBackend;
/// #[derive(Clone)]
/// struct MyUser;
/// #[derive(Debug)]
/// struct MyError;
///
/// impl std::fmt::Display for MyError {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "error") }
/// }
/// impl std::error::Error for MyError {}
/// impl fast_auth::AuthBackendError for MyError {}
///
/// impl AuthUser for MyUser {
///     fn id(&self) -> Uuid { Uuid::nil() }
///     fn email(&self) -> &str { "" }
///     fn password_hash(&self) -> &str { "" }
///     fn email_confirmed_at(&self) -> Option<DateTime<Utc>> { None }
///     fn last_sign_in_at(&self) -> Option<DateTime<Utc>> { None }
///     fn created_at(&self) -> DateTime<Utc> { Utc::now() }
/// }
///
/// impl AuthBackend for MyBackend {
///     type User = MyUser;
///     type Error = MyError;
///     async fn user_find_by_email(&self, _: &str) -> Result<Option<Self::User>, Self::Error> { Ok(None) }
///     async fn user_get_by_id(&self, _: Uuid) -> Result<Option<Self::User>, Self::Error> { Ok(None) }
///     async fn user_create(&self, _: &str, _: &str) -> Result<Self::User, Self::Error> { Err(MyError) }
///     async fn session_issue(&self, _: Uuid, _: &str, _: DateTime<Utc>) -> Result<(), Self::Error> { Ok(()) }
///     async fn session_issue_if_password_hash(&self, _: Uuid, _: &str, _: &str, _: DateTime<Utc>) -> Result<(), Self::Error> { Ok(()) }
///     async fn session_revoke_by_refresh_token_hash(&self, _: &str) -> Result<(), Self::Error> { Ok(()) }
///     async fn session_exchange(&self, _: &str, _: &str, _: DateTime<Utc>) -> Result<Uuid, Self::Error> { Ok(Uuid::nil()) }
///     async fn verification_token_issue(&self, _: Uuid, _: &str, _: fast_auth::verification::VerificationTokenType, _: DateTime<Utc>) -> Result<(), Self::Error> { Ok(()) }
///     async fn email_confirm_apply(&self, _: &str) -> Result<(), Self::Error> { Ok(()) }
///     async fn password_reset_apply(&self, _: &str, _: &str) -> Result<(), Self::Error> { Ok(()) }
/// }
/// ```
pub trait AuthBackend: Clone + Send + Sync + 'static {
    /// User record type.
    type User: AuthUser;
    /// Backend error type.
    type Error: AuthBackendError;

    /// Finds a user by normalized email.
    fn user_find_by_email(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;

    /// Finds a user by id.
    fn user_get_by_id(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;

    /// Creates a new user.
    ///
    /// Must be race-safe for concurrent sign-ups with the same email.
    /// Return [`AuthError::UserAlreadyExists`] when email already exists.
    fn user_create(
        &self,
        email: &str,
        password_hash: &str,
    ) -> impl Future<Output = Result<Self::User, Self::Error>> + Send;

    /// Creates one API key for a user.
    fn api_key_create(
        &self,
        user_id: Uuid,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
    ) -> impl Future<Output = Result<AuthApiKey, Self::Error>> + Send;

    /// Lists one paginated API-key window owned by a user.
    fn api_keys_list(
        &self,
        user_id: Uuid,
        query: ListQuery<AuthApiKeyListSortBy>,
    ) -> impl Future<Output = Result<ListPageResult<AuthApiKey>, Self::Error>> + Send;

    /// Deletes one owned API key.
    fn api_key_delete(
        &self,
        user_id: Uuid,
        api_key_id: Uuid,
    ) -> impl Future<Output = Result<AuthApiKey, Self::Error>> + Send;

    /// Authenticates one bearer API key and updates its last-used timestamp.
    fn api_key_authenticate(
        &self,
        api_key: &str,
        used_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;

    /// Revokes all active refresh tokens for `user_id` and inserts a new one.
    ///
    /// Must be atomic to preserve single-session refresh-token semantics.
    fn session_issue(
        &self,
        user_id: Uuid,
        refresh_token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Finalizes sign-in only if the password hash still matches the current one.
    ///
    /// Required behavior:
    /// - lock/verify current password hash against `current_password_hash`
    /// - set `last_sign_in_at` for the user
    /// - revoke all active refresh tokens for that user
    /// - insert the new refresh token (`refresh_token_hash`, `expires_at`)
    ///
    /// Must be atomic.
    ///
    /// Return [`AuthError::InvalidCredentials`] when user is missing or
    /// password changed concurrently.
    fn session_issue_if_password_hash(
        &self,
        user_id: Uuid,
        current_password_hash: &str,
        refresh_token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Revokes a refresh token by hash.
    ///
    /// Must be atomic.
    /// Return [`AuthError::RefreshTokenInvalid`] when token is missing or
    /// already revoked.
    fn session_revoke_by_refresh_token_hash(
        &self,
        refresh_token_hash: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Consumes a valid refresh token and issues a replacement token atomically.
    ///
    /// Required behavior:
    /// - consume/revoke `current_refresh_token_hash` only if active and not expired
    /// - revoke any other active refresh tokens for the same user
    /// - insert `next_refresh_token_hash` with `next_expires_at`
    ///
    /// Returns the owner user id when successful.
    /// Returns [`AuthError::RefreshTokenInvalid`] when token is invalid,
    /// expired, or revoked.
    fn session_exchange(
        &self,
        current_refresh_token_hash: &str,
        next_refresh_token_hash: &str,
        next_expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<Uuid, Self::Error>> + Send;

    /// Creates a verification token and invalidates previous active token of same type.
    ///
    /// Must atomically invalidate existing active `(user_id, token_type)` token before insert.
    fn verification_token_issue(
        &self,
        user_id: Uuid,
        token_hash: &str,
        token_type: VerificationTokenType,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Atomically confirms email by consuming the given token hash.
    ///
    /// Required behavior:
    /// - consume `token_hash` only when type is `EmailConfirm`, unexpired, and unused
    /// - set `email_confirmed_at`
    ///
    /// Returns [`AuthError::InvalidToken`] when token is invalid, expired, or
    /// already used.
    fn email_confirm_apply(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Atomically applies password reset by consuming token hash and updating credentials.
    ///
    /// Required behavior:
    /// - consume `token_hash` only when type is `PasswordReset`, unexpired, and unused
    /// - update password hash
    /// - revoke all active refresh tokens for the user
    ///
    /// Returns [`AuthError::InvalidToken`] when token is invalid, expired, or
    /// already used.
    fn password_reset_apply(
        &self,
        token_hash: &str,
        password_hash: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
