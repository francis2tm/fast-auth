//! Request extractors for authentication.

use crate::{error::AuthError, middleware::UserContext};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

/// Authenticated user extractor.
///
/// Extracts authenticated user from the UserContext injected by the base middleware.
/// This extractor will return an error if the user is not authenticated.
///
/// **Requires**: The `fast_auth::middleware::base` middleware must be applied to the route.
///
/// **Does not** fetch user from database - this is a stateless authentication check.
/// If you need the full user record, query the database in your handler using the user_id.
///
/// # Example
///
/// ```rust,ignore
/// use fast_auth::AuthUserExtractor;
/// use axum::Json;
///
/// async fn protected_route(auth: AuthUserExtractor) -> Json<String> {
///     Json(format!("Hello, {}!", auth.email))
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthUserExtractor {
    /// User ID from JWT claims.
    pub user_id: Uuid,
    /// User email from JWT claims.
    pub email: String,
    /// User role from JWT claims.
    pub role: String,
}

impl<S> FromRequestParts<S> for AuthUserExtractor
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

        // Check if user is authenticated
        match (&context.user_id, &context.email) {
            (Some(user_id), Some(email)) => Ok(AuthUserExtractor {
                user_id: *user_id,
                email: email.clone(),
                role: context.role.clone(),
            }),
            _ => Err(AuthError::InvalidToken),
        }
    }
}
