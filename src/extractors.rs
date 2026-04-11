//! Axum extractors for authentication.

use crate::{OrganizationRole, error::AuthError, middleware::UserContext};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use utoipa::ToSchema;
use uuid::Uuid;

/// Authenticated request-user extractor.
///
/// Extracts the active organization-scoped user from the `UserContext`
/// injected by the base middleware.
///
/// **Requires**: The `auth::middleware::base` middleware must be applied to the route.
///
/// **Does not** fetch user or organization data from the database. Use
/// [`crate::HydratedUser`] when you need one fully hydrated auth
/// response or hook payload.
///
/// # Example
///
/// ```rust,no_run
/// use fast_auth::RequestUser;
/// use axum::Json;
///
/// async fn protected_route(request_user: RequestUser) -> Json<String> {
///     Json(format!("Hello, {}!", request_user.email))
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestUser {
    /// User ID from JWT claims.
    pub user_id: Uuid,
    /// User email from JWT claims.
    pub email: String,
    /// SQL auth role from JWT claims.
    pub role: String,
    /// Active organization id from JWT claims.
    pub organization_id: Uuid,
    /// Active organization role from JWT claims.
    pub organization_role: OrganizationRole,
}

#[derive(Debug, Clone)]
pub struct CurrentAdmin(pub RequestUser);

#[derive(Debug, Clone)]
pub struct CurrentOwner(pub RequestUser);

impl Deref for CurrentAdmin {
    type Target = RequestUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for CurrentOwner {
    type Target = RequestUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn request_user_build(context: &UserContext) -> Result<RequestUser, AuthError> {
    match (
        &context.user_id,
        &context.organization_id,
        &context.email,
        &context.organization_role,
    ) {
        (Some(user_id), Some(organization_id), Some(email), Some(organization_role)) => {
            Ok(RequestUser {
                user_id: *user_id,
                email: email.clone(),
                role: context.role.clone(),
                organization_id: *organization_id,
                organization_role: *organization_role,
            })
        }
        _ => Err(AuthError::InvalidToken),
    }
}

impl<S> FromRequestParts<S> for RequestUser
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

        request_user_build(context)
    }
}

impl<S> FromRequestParts<S> for CurrentAdmin
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let request_user = RequestUser::from_request_parts(parts, state).await?;
        match request_user.organization_role {
            OrganizationRole::Owner | OrganizationRole::Admin => Ok(Self(request_user)),
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
        let request_user = RequestUser::from_request_parts(parts, state).await?;
        match request_user.organization_role {
            OrganizationRole::Owner => Ok(Self(request_user)),
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
    async fn request_user_extracts_authenticated_context() {
        let context = user_context(OrganizationRole::Member);
        let mut parts = request_parts_with_context(context.clone());

        let request_user = RequestUser::from_request_parts(&mut parts, &())
            .await
            .expect("request user");

        assert_eq!(request_user.user_id, context.user_id.expect("user id"));
        assert_eq!(
            request_user.organization_id,
            context.organization_id.expect("organization id")
        );
        assert_eq!(request_user.email, context.email.expect("email"));
        assert_eq!(request_user.organization_role, OrganizationRole::Member);
        assert_eq!(request_user.role, "authenticated");
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
    async fn request_user_rejects_missing_context() {
        let mut parts = Request::builder()
            .uri("/")
            .body(())
            .expect("request")
            .into_parts()
            .0;

        let error = RequestUser::from_request_parts(&mut parts, &())
            .await
            .expect_err("missing context should fail");

        assert!(matches!(error, AuthError::InvalidToken));
    }
}
