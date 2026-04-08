//! Axum extractors for authentication.

use crate::{OrganizationRole, error::AuthError, middleware::UserContext};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use utoipa::ToSchema;
use uuid::Uuid;

/// Authenticated current-user extractor.
///
/// Extracts the active organization-scoped user from the `UserContext`
/// injected by the base middleware.
///
/// **Requires**: The `auth::middleware::base` middleware must be applied to the route.
///
/// **Does not** fetch user or organization data from the database. It relies on
/// the org-aware auth context already resolved by `fast-auth`.
///
/// # Example
///
/// ```rust,ignore
/// use fast_auth::CurrentUser;
/// use axum::Json;
///
/// async fn protected_route(user: CurrentUser) -> Json<String> {
///     Json(format!("Hello, {}!", user.email))
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CurrentUser {
    /// User ID from JWT claims.
    pub user_id: Uuid,
    /// User email from JWT claims.
    pub email: String,
    /// SQL auth role from JWT claims.
    pub role: String,
    /// Email confirmation timestamp, when the backend resolved it.
    pub email_confirmed_at: Option<DateTime<Utc>>,
    /// Active organization id from JWT claims.
    pub organization_id: Uuid,
    /// Active organization role from JWT claims.
    pub organization_role: OrganizationRole,
    /// Active organization name, when the backend resolved it.
    pub organization_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CurrentAdmin(pub CurrentUser);

#[derive(Debug, Clone)]
pub struct CurrentOwner(pub CurrentUser);

impl Deref for CurrentAdmin {
    type Target = CurrentUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for CurrentOwner {
    type Target = CurrentUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn current_user_build(context: &UserContext) -> Result<CurrentUser, AuthError> {
    match (
        &context.user_id,
        &context.organization_id,
        &context.email,
        &context.organization_role,
    ) {
        (Some(user_id), Some(organization_id), Some(email), Some(organization_role)) => {
            Ok(CurrentUser {
                user_id: *user_id,
                email: email.clone(),
                role: context.role.clone(),
                email_confirmed_at: None,
                organization_id: *organization_id,
                organization_role: *organization_role,
                organization_name: None,
            })
        }
        _ => Err(AuthError::InvalidToken),
    }
}

impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract UserContext from request extensions
        let context = parts
            .extensions
            .get::<UserContext>()
            .ok_or(AuthError::InvalidToken)?;

        current_user_build(context)
    }
}

impl<S> FromRequestParts<S> for CurrentAdmin
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        match user.organization_role {
            OrganizationRole::Owner | OrganizationRole::Admin => Ok(Self(user)),
            OrganizationRole::Member => Err(AuthError::Forbidden),
        }
    }
}

impl<S> FromRequestParts<S> for CurrentOwner
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        match user.organization_role {
            OrganizationRole::Owner => Ok(Self(user)),
            OrganizationRole::Admin | OrganizationRole::Member => Err(AuthError::Forbidden),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn user_context(role: OrganizationRole) -> UserContext {
        UserContext {
            user_id: Some(Uuid::new_v4()),
            organization_id: Some(Uuid::new_v4()),
            email: Some("user@example.com".to_string()),
            organization_role: Some(role),
            role: "authenticated".to_string(),
        }
    }

    fn request_parts_with_context(context: UserContext) -> Parts {
        let mut parts = Request::builder()
            .uri("/")
            .body(())
            .expect("request")
            .into_parts()
            .0;
        parts.extensions.insert(context);
        parts
    }

    #[tokio::test]
    async fn current_user_extracts_authenticated_context() {
        let context = user_context(OrganizationRole::Member);
        let mut parts = request_parts_with_context(context.clone());

        let user = CurrentUser::from_request_parts(&mut parts, &())
            .await
            .expect("current user");

        assert_eq!(user.user_id, context.user_id.expect("user id"));
        assert_eq!(
            user.organization_id,
            context.organization_id.expect("organization id")
        );
        assert_eq!(user.email, context.email.expect("email"));
        assert_eq!(user.organization_role, OrganizationRole::Member);
        assert_eq!(user.role, "authenticated");
    }

    #[tokio::test]
    async fn current_admin_allows_admin_and_owner() {
        for role in [OrganizationRole::Admin, OrganizationRole::Owner] {
            let mut parts = request_parts_with_context(user_context(role));
            CurrentAdmin::from_request_parts(&mut parts, &())
                .await
                .expect("admin or owner should pass");
        }
    }

    #[tokio::test]
    async fn current_admin_rejects_member() {
        let mut parts = request_parts_with_context(user_context(OrganizationRole::Member));

        let error = CurrentAdmin::from_request_parts(&mut parts, &())
            .await
            .expect_err("member should fail");

        assert!(matches!(error, AuthError::Forbidden));
    }

    #[tokio::test]
    async fn current_owner_allows_only_owner() {
        let mut owner_parts = request_parts_with_context(user_context(OrganizationRole::Owner));
        CurrentOwner::from_request_parts(&mut owner_parts, &())
            .await
            .expect("owner should pass");

        for role in [OrganizationRole::Admin, OrganizationRole::Member] {
            let mut parts = request_parts_with_context(user_context(role));
            let error = CurrentOwner::from_request_parts(&mut parts, &())
                .await
                .expect_err("non-owner should fail");
            assert!(matches!(error, AuthError::Forbidden));
        }
    }

    #[tokio::test]
    async fn current_user_rejects_missing_context() {
        let mut parts = Request::builder()
            .uri("/")
            .body(())
            .expect("request")
            .into_parts()
            .0;

        let error = CurrentUser::from_request_parts(&mut parts, &())
            .await
            .expect_err("missing context should fail");

        assert!(matches!(error, AuthError::InvalidToken));
    }
}
