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
use crate::extractors::RequestUser;
use crate::verification::VerificationTokenType;

/// Minimal user interface required by `fast-auth`.
///
/// Implement this trait for your user type so handlers and middleware can build
/// auth responses without depending on a concrete schema.
///
/// # Example
///
/// ```rust,no_run
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

/// Fully resolved authenticated user context.
///
/// Unlike [`RequestUser`], this shape is hydrated from backend storage and is
/// safe to use for auth responses, hooks, and token generation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HydratedUser {
    /// Stable authenticated user identifier.
    pub user_id: Uuid,
    /// Normalized user email address.
    pub email: String,
    /// SQL auth role applied to database connections.
    pub role: String,
    /// Email confirmation timestamp, if confirmed.
    pub email_confirmed_at: Option<DateTime<Utc>>,
    /// Active organization identifier.
    pub organization_id: Uuid,
    /// Active organization role.
    pub organization_role: OrganizationRole,
    /// Active organization display name.
    pub organization_name: String,
}

/// Result of creating one new user account.
#[derive(Debug, Clone)]
pub struct UserCreated<U> {
    /// Newly persisted user record.
    pub user: U,
    /// Fully resolved auth context for that new user.
    pub hydrated_user: HydratedUser,
}

/// Backend error kinds that map to stable public auth errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthBackendErrorKind {
    /// Backend rejected invalid credentials.
    InvalidCredentials,
    /// Backend detected a duplicate user.
    UserAlreadyExists,
    /// Backend rejected an invalid or revoked refresh token.
    RefreshTokenInvalid,
    /// Backend rejected an invalid verification or API token.
    InvalidToken,
    /// Backend could not find the requested API key.
    ApiKeyNotFound,
    /// Backend could not find the requested organization or membership.
    OrganizationNotFound,
    /// Backend could not find the requested organization invite.
    OrganizationInviteNotFound,
    /// Backend denied the requested action.
    Forbidden,
    /// Backend could not find the requested user.
    UserNotFound,
    /// Backend hit one unexpected internal failure.
    Backend,
}

/// Parameters for creating one new user.
#[derive(Debug, Clone, Copy)]
pub struct UserCreateParams<'a> {
    /// Normalized email address to persist.
    pub email: &'a str,
    /// Password hash to store at rest.
    pub password_hash: &'a str,
}

/// Parameters for creating one API key.
#[derive(Debug, Clone, Copy)]
pub struct ApiKeyCreateParams<'a> {
    /// Owning organization identifier.
    pub organization_id: Uuid,
    /// User that created the key.
    pub created_by_user_id: Uuid,
    /// Caller-visible API key name.
    pub name: &'a str,
    /// Stable visible key prefix.
    pub key_prefix: &'a str,
    /// Hashed key material stored at rest.
    pub key_hash: &'a str,
}

/// Parameters for issuing one refresh token after password verification.
#[derive(Debug, Clone, Copy)]
pub struct SessionIssueIfPasswordHashParams<'a> {
    /// User that is signing in.
    pub user_id: Uuid,
    /// Password hash observed before the sign-in transaction.
    pub current_password_hash: &'a str,
    /// Hashed refresh token stored at rest.
    pub refresh_token_hash: &'a str,
    /// Refresh token expiry timestamp.
    pub expires_at: DateTime<Utc>,
}

/// Parameters for rotating one refresh token.
#[derive(Debug, Clone, Copy)]
pub struct SessionExchangeParams<'a> {
    /// Currently active refresh token hash that must be consumed.
    pub current_refresh_token_hash: &'a str,
    /// Replacement refresh token hash to insert.
    pub next_refresh_token_hash: &'a str,
    /// Expiry timestamp for the replacement refresh token.
    pub next_expires_at: DateTime<Utc>,
}

/// Parameters for issuing one verification token.
#[derive(Debug, Clone, Copy)]
pub struct VerificationTokenIssueParams<'a> {
    /// User that owns the token.
    pub user_id: Uuid,
    /// Hashed token stored at rest.
    pub token_hash: &'a str,
    /// Verification token kind.
    pub token_type: VerificationTokenType,
    /// Expiry timestamp for the token.
    pub expires_at: DateTime<Utc>,
}

/// Organization membership role exposed by auth.
///
/// This role is embedded in [`RequestUser`] and [`HydratedUser`],
/// organization membership responses,
/// and invitations so backends and HTTP handlers can share one stable
/// authorization vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    /// Full control over the organization.
    Owner,
    /// Administrative organization access.
    Admin,
    /// Regular workspace member access.
    Member,
}

/// Organization summary exposed by auth.
///
/// This is the storage-agnostic organization shape returned by backend methods
/// and exposed by organization endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Organization {
    /// Stable organization identifier.
    pub id: Uuid,
    /// Human-readable organization name.
    pub name: String,
    /// Organization creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent organization update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Organization membership summary exposed by auth.
///
/// Backends return this when listing memberships or members so handlers can
/// expose both the organization metadata and the caller-visible membership role
/// in one payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrganizationMember {
    /// Organization visible through this membership.
    pub organization: Organization,
    /// Member user identifier.
    pub user_id: Uuid,
    /// Member email address.
    pub email: String,
    /// Role granted inside the organization.
    pub role: OrganizationRole,
    /// Membership creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Organization invitation metadata.
///
/// This is the persisted invitation state returned by list, revoke, and accept
/// flows. The plaintext invite token is intentionally excluded here and is only
/// available through [`OrganizationInviteWithSecret`] at creation time.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrganizationInvite {
    /// Stable invitation identifier.
    pub id: Uuid,
    /// Target organization identifier.
    pub organization_id: Uuid,
    /// Human-readable target organization name.
    pub organization_name: String,
    /// Email address the invitation targets.
    pub email: String,
    /// Role that will be granted if the invite is accepted.
    pub role: OrganizationRole,
    /// User identifier of the inviter.
    pub invited_by_user_id: Uuid,
    /// Invitation creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Revocation timestamp, when the invite has been revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Acceptance timestamp, when the invite has been accepted.
    pub accepted_at: Option<DateTime<Utc>>,
}

/// Invitation creation result that includes the one-time plaintext token.
///
/// The plaintext `token` is returned only once so callers can deliver it to
/// the invited user. Later reads should use [`OrganizationInvite`] instead.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrganizationInviteWithSecret {
    /// Persisted invitation metadata.
    #[serde(flatten)]
    pub invite: OrganizationInvite,
    /// Plaintext invitation token returned once at creation time.
    pub token: String,
}

/// Backend error contract for `fast-auth`.
///
/// Implement this for your backend error type so handlers can make consistent
/// decisions without parsing error messages.
pub trait AuthBackendError: std::error::Error + Send + Sync + 'static {
    /// Returns the stable public error kind for this backend error.
    fn kind(&self) -> AuthBackendErrorKind;

    /// Maps this backend error to the public auth error type.
    fn auth_error(&self) -> AuthError {
        match self.kind() {
            AuthBackendErrorKind::InvalidCredentials => AuthError::InvalidCredentials,
            AuthBackendErrorKind::UserAlreadyExists => AuthError::UserAlreadyExists,
            AuthBackendErrorKind::RefreshTokenInvalid => AuthError::RefreshTokenInvalid,
            AuthBackendErrorKind::InvalidToken => AuthError::InvalidToken,
            AuthBackendErrorKind::ApiKeyNotFound => AuthError::ApiKeyNotFound,
            AuthBackendErrorKind::OrganizationNotFound => AuthError::OrganizationNotFound,
            AuthBackendErrorKind::OrganizationInviteNotFound => {
                AuthError::OrganizationInviteNotFound
            }
            AuthBackendErrorKind::Forbidden => AuthError::Forbidden,
            AuthBackendErrorKind::UserNotFound => AuthError::UserNotFound,
            AuthBackendErrorKind::Backend => AuthError::Backend(self.to_string()),
        }
    }
}

/// Stored API key metadata exposed by auth backends.
///
/// This shape intentionally excludes the plaintext API key secret. It is used
/// for list and delete responses after the key has been created and persisted.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKey {
    /// Stable API key identifier.
    pub id: Uuid,
    /// Organization that owns this API key.
    pub organization_id: Uuid,
    /// User-defined display name.
    pub name: String,
    /// User identifier that created the key.
    pub created_by_user_id: Uuid,
    /// Stable visible key prefix.
    pub key_prefix: String,
    /// API key creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent successful authentication timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Sortable columns for API-key listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyListSortBy {
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
/// [`ApiKey`] instead, which exposes metadata only.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyWithSecret {
    /// Stable API key identifier.
    pub id: Uuid,
    /// Organization that owns this API key.
    pub organization_id: Uuid,
    /// User-defined display name.
    pub name: String,
    /// User identifier that created the key.
    pub created_by_user_id: Uuid,
    /// Plaintext key material returned once at creation time.
    pub key: String,
    /// Stable visible key prefix.
    pub key_prefix: String,
    /// API key creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent successful authentication timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Storage backend contract for authentication and organization operations.
///
/// Session and token mutation methods must be implemented as single race-safe
/// operations (typically one SQL statement or one transaction).
///
/// # Example
///
/// ```rust,no_run
/// use chrono::{DateTime, Utc};
/// use fast_auth::{
///     ApiKeyCreateParams, AuthBackend, AuthBackendError, AuthBackendErrorKind, RequestUser,
///     AuthUser, OrganizationRole, HydratedUser, SessionExchangeParams,
///     SessionIssueIfPasswordHashParams, UserCreateParams, UserCreated,
///     VerificationTokenIssueParams,
/// };
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
/// impl AuthBackendError for MyError {
///     fn kind(&self) -> AuthBackendErrorKind {
///         AuthBackendErrorKind::Backend
///     }
/// }
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
/// fn hydrated_user() -> HydratedUser {
///     HydratedUser {
///         user_id: Uuid::nil(),
///         email: String::new(),
///         role: "authenticated".to_string(),
///         email_confirmed_at: Some(Utc::now()),
///         organization_id: Uuid::nil(),
///         organization_role: OrganizationRole::Owner,
///         organization_name: String::new(),
///     }
/// }
///
/// impl AuthBackend for MyBackend {
///     type User = MyUser;
///     type Error = MyError;
///
///     async fn user_find_by_email(&self, _: &str) -> Result<Option<Self::User>, Self::Error> { Ok(None) }
///     async fn user_create(&self, _: UserCreateParams<'_>) -> Result<UserCreated<Self::User>, Self::Error> { Err(MyError) }
///     async fn hydrated_user_get(&self, _: &RequestUser) -> Result<Option<HydratedUser>, Self::Error> { Ok(Some(hydrated_user())) }
///     async fn api_key_create(&self, _: ApiKeyCreateParams<'_>) -> Result<fast_auth::ApiKey, Self::Error> { Err(MyError) }
///     async fn api_keys_list(&self, _: Uuid, _: common::list::ListQuery<fast_auth::ApiKeyListSortBy>) -> Result<common::list::ListPageResult<fast_auth::ApiKey>, Self::Error> { Err(MyError) }
///     async fn api_key_delete(&self, _: Uuid, _: Uuid) -> Result<fast_auth::ApiKey, Self::Error> { Err(MyError) }
///     async fn api_key_authenticate(&self, _: &str, _: DateTime<Utc>) -> Result<Option<RequestUser>, Self::Error> { Ok(None) }
///     async fn session_issue(&self, _: Uuid, _: &str, _: DateTime<Utc>) -> Result<(), Self::Error> { Ok(()) }
///     async fn session_issue_if_password_hash(&self, _: SessionIssueIfPasswordHashParams<'_>) -> Result<HydratedUser, Self::Error> { Ok(hydrated_user()) }
///     async fn session_revoke_by_refresh_token_hash(&self, _: &str) -> Result<(), Self::Error> { Ok(()) }
///     async fn session_exchange(&self, _: SessionExchangeParams<'_>) -> Result<HydratedUser, Self::Error> { Ok(hydrated_user()) }
///     async fn verification_token_issue(&self, _: VerificationTokenIssueParams<'_>) -> Result<(), Self::Error> { Ok(()) }
///     async fn email_confirm_apply(&self, _: &str) -> Result<(), Self::Error> { Ok(()) }
///     async fn password_reset_apply(&self, _: &str, _: &str) -> Result<(), Self::Error> { Ok(()) }
///     async fn organizations_list(&self, _: Uuid) -> Result<Vec<fast_auth::OrganizationMember>, Self::Error> { Ok(vec![]) }
///     async fn organization_create(&self, _: Uuid, _: &str) -> Result<fast_auth::OrganizationMember, Self::Error> { Err(MyError) }
///     async fn organization_get(&self, _: Uuid, _: Uuid) -> Result<Option<fast_auth::OrganizationMember>, Self::Error> { Ok(None) }
///     async fn organization_update(&self, _: Uuid, _: Uuid, _: &str) -> Result<fast_auth::OrganizationMember, Self::Error> { Err(MyError) }
///     async fn organization_delete(&self, _: Uuid, _: Uuid) -> Result<fast_auth::Organization, Self::Error> { Err(MyError) }
///     async fn organization_switch(&self, _: Uuid, _: Uuid) -> Result<HydratedUser, Self::Error> { Ok(hydrated_user()) }
///     async fn organization_members_list(&self, _: Uuid, _: Uuid) -> Result<Vec<fast_auth::OrganizationMember>, Self::Error> { Ok(vec![]) }
///     async fn organization_member_update_role(&self, _: Uuid, _: Uuid, _: Uuid, _: OrganizationRole) -> Result<fast_auth::OrganizationMember, Self::Error> { Err(MyError) }
///     async fn organization_member_delete(&self, _: Uuid, _: Uuid, _: Uuid) -> Result<fast_auth::OrganizationMember, Self::Error> { Err(MyError) }
///     async fn organization_invite_create(&self, _: Uuid, _: Uuid, _: &str, _: OrganizationRole) -> Result<fast_auth::OrganizationInviteWithSecret, Self::Error> { Err(MyError) }
///     async fn organization_invites_list(&self, _: Uuid, _: Uuid) -> Result<Vec<fast_auth::OrganizationInvite>, Self::Error> { Ok(vec![]) }
///     async fn organization_invite_revoke(&self, _: Uuid, _: Uuid, _: Uuid) -> Result<fast_auth::OrganizationInvite, Self::Error> { Err(MyError) }
///     async fn organization_invite_accept(&self, _: Uuid, _: &str) -> Result<HydratedUser, Self::Error> { Ok(hydrated_user()) }
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

    /// Creates a new user and provisions its default personal organization state.
    ///
    /// Must be race-safe for concurrent sign-ups with the same email.
    /// Return [`AuthError::UserAlreadyExists`] when email already exists.
    fn user_create(
        &self,
        params: UserCreateParams<'_>,
    ) -> impl Future<Output = Result<UserCreated<Self::User>, Self::Error>> + Send;

    /// Resolves one fully hydrated auth context for one authenticated subject.
    ///
    /// This should return the fully hydrated auth context used by handlers and
    /// responses, including the selected organization and organization name.
    fn hydrated_user_get(
        &self,
        request_user: &RequestUser,
    ) -> impl Future<Output = Result<Option<HydratedUser>, Self::Error>> + Send;

    /// Creates one API key for the active organization.
    ///
    /// `key_hash` is the hashed API-key secret that should be stored at rest.
    /// Backends should associate the record with both `organization_id` and
    /// `created_by_user_id`, and return only metadata via [`ApiKey`].
    fn api_key_create(
        &self,
        params: ApiKeyCreateParams<'_>,
    ) -> impl Future<Output = Result<ApiKey, Self::Error>> + Send;

    /// Lists one paginated API-key window owned by the active organization.
    ///
    /// The returned page must contain only keys owned by `organization_id` and
    /// apply the requested pagination and sorting consistently.
    fn api_keys_list(
        &self,
        organization_id: Uuid,
        query: ListQuery<ApiKeyListSortBy>,
    ) -> impl Future<Output = Result<ListPageResult<ApiKey>, Self::Error>> + Send;

    /// Deletes one owned API key.
    ///
    /// Return the deleted key metadata when successful.
    /// Return [`AuthError::ApiKeyNotFound`] when `api_key_id` is unknown or not
    /// owned by `organization_id`.
    fn api_key_delete(
        &self,
        organization_id: Uuid,
        api_key_id: Uuid,
    ) -> impl Future<Output = Result<ApiKey, Self::Error>> + Send;

    /// Authenticates one bearer API key and updates its last-used timestamp.
    ///
    /// This should return the org-scoped request subject for the API key
    /// without mutating the user's stored active organization.
    fn api_key_authenticate(
        &self,
        api_key: &str,
        used_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<RequestUser>, Self::Error>> + Send;

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
        params: SessionIssueIfPasswordHashParams<'_>,
    ) -> impl Future<Output = Result<HydratedUser, Self::Error>> + Send;

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
    /// Returns the refreshed hydrated user context when successful.
    /// Returns [`AuthError::RefreshTokenInvalid`] when token is invalid,
    /// expired, or revoked.
    fn session_exchange(
        &self,
        params: SessionExchangeParams<'_>,
    ) -> impl Future<Output = Result<HydratedUser, Self::Error>> + Send;

    /// Creates a verification token and invalidates previous active token of same type.
    ///
    /// Must atomically invalidate existing active `(user_id, token_type)` token before insert.
    fn verification_token_issue(
        &self,
        params: VerificationTokenIssueParams<'_>,
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

    /// Lists every organization membership for one user.
    ///
    /// The result should contain every organization the user belongs to,
    /// including the role held in each organization.
    fn organizations_list(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Vec<OrganizationMember>, Self::Error>> + Send;

    /// Creates one organization and owner membership for one user.
    ///
    /// The creating user must become the initial [`OrganizationRole::Owner`].
    fn organization_create(
        &self,
        owner_user_id: Uuid,
        name: &str,
    ) -> impl Future<Output = Result<OrganizationMember, Self::Error>> + Send;

    /// Loads one organization membership visible to one user.
    ///
    /// Return `Ok(None)` when the user is not a member of `organization_id`.
    fn organization_get(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> impl Future<Output = Result<Option<OrganizationMember>, Self::Error>> + Send;

    /// Updates one organization name.
    ///
    /// Backends should enforce that `user_id` is allowed to manage the
    /// organization before applying the update.
    fn organization_update(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
        name: &str,
    ) -> impl Future<Output = Result<OrganizationMember, Self::Error>> + Send;

    /// Deletes one organization owned by one user.
    ///
    /// Backends should require owner-level access, reject deletion of the
    /// user's default personal organization, and return the deleted
    /// organization snapshot.
    fn organization_delete(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> impl Future<Output = Result<Organization, Self::Error>> + Send;

    /// Switches the active organization for one user.
    ///
    /// This should return the refreshed [`HydratedUser`] payload that
    /// reflects the newly active organization.
    fn organization_switch(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> impl Future<Output = Result<HydratedUser, Self::Error>> + Send;

    /// Lists organization members visible to one user.
    ///
    /// Backends should enforce membership visibility before returning the
    /// organization roster.
    fn organization_members_list(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> impl Future<Output = Result<Vec<OrganizationMember>, Self::Error>> + Send;

    /// Updates one member role inside one organization.
    ///
    /// Backends should require owner-level access, reject demoting a user out
    /// of ownership in their default personal organization, and return the
    /// updated membership row after the role change.
    fn organization_member_update_role(
        &self,
        actor_user_id: Uuid,
        organization_id: Uuid,
        member_user_id: Uuid,
        role: OrganizationRole,
    ) -> impl Future<Output = Result<OrganizationMember, Self::Error>> + Send;

    /// Removes one member from one organization.
    ///
    /// Backends should enforce actor permissions, reject removing a user from
    /// their default personal organization, and return the removed membership
    /// row.
    fn organization_member_delete(
        &self,
        actor_user_id: Uuid,
        organization_id: Uuid,
        member_user_id: Uuid,
    ) -> impl Future<Output = Result<OrganizationMember, Self::Error>> + Send;

    /// Creates one organization invitation and returns its one-time token.
    ///
    /// The plaintext token should be returned only once through
    /// [`OrganizationInviteWithSecret`]. Backends should normalize the target
    /// email, allow at most one active invite per `(organization_id, email)`,
    /// and replace any older active invite for the same target. Backends should
    /// also enforce that the actor can invite members into the organization.
    fn organization_invite_create(
        &self,
        actor_user_id: Uuid,
        organization_id: Uuid,
        email: &str,
        role: OrganizationRole,
    ) -> impl Future<Output = Result<OrganizationInviteWithSecret, Self::Error>> + Send;

    /// Lists every invite for one organization visible to one user.
    ///
    /// Backends should return the persisted invite metadata for invites the
    /// caller is authorized to inspect.
    fn organization_invites_list(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> impl Future<Output = Result<Vec<OrganizationInvite>, Self::Error>> + Send;

    /// Revokes one organization invitation.
    ///
    /// Backends should mark the invite as revoked and return the updated invite
    /// metadata.
    fn organization_invite_revoke(
        &self,
        actor_user_id: Uuid,
        organization_id: Uuid,
        invite_id: Uuid,
    ) -> impl Future<Output = Result<OrganizationInvite, Self::Error>> + Send;

    /// Accepts one organization invitation for an authenticated user.
    ///
    /// This should validate the invite token, create the membership, invalidate
    /// any sibling active invites for the same `(organization_id, email)`, and
    /// return the refreshed [`HydratedUser`] payload for the user after
    /// acceptance. This mutation must be race-safe.
    fn organization_invite_accept(
        &self,
        user_id: Uuid,
        token: &str,
    ) -> impl Future<Output = Result<HydratedUser, Self::Error>> + Send;
}
