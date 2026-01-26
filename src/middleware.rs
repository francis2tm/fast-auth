//! Authentication middleware for Axum.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthUser, EmailSender,
    cookies::{access_token_cookie_clear, access_token_cookie_create, refresh_token_cookie_clear},
    error::AuthError,
    tokens::{access_token_generate, access_token_validate, token_hash_sha256},
};
use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

/// Internal user context carried through request extensions.
///
/// Populated by `base` and consumed by crate extractors; not part of the
/// public API.
#[derive(Debug, Clone)]
pub(crate) struct UserContext {
    /// User ID if authenticated, None if anonymous.
    pub user_id: Option<Uuid>,
    /// User email if authenticated, None if anonymous.
    pub email: Option<String>,
    /// User role: "authenticated" or "anon".
    pub role: String,
}

impl Default for UserContext {
    fn default() -> Self {
        Self {
            user_id: None,
            email: None,
            role: "anon".to_string(),
        }
    }
}

/// Base authentication middleware.
///
/// This middleware handles JWT validation and automatic token refresh.
/// It should be applied to all routes that may need authentication.
///
/// # Behavior
/// - **JWT present**: Validates JWT and injects authenticated UserContext
/// - **JWT invalid**: Clears auth cookies (potential tampering)
/// - **No JWT but refresh token present**: Silently generates new JWT and injects authenticated UserContext
/// - **No auth cookies**: Injects anonymous UserContext
///
/// # Silent Authentication
/// If a request arrives without a JWT but with a valid refresh token, the middleware
/// will automatically generate a new JWT and add it to the response cookies. This
/// happens transparently without redirects, working for all request types (GET, POST, etc.).
pub async fn base<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    State(auth): State<Auth<B, H, E>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let mut jar = CookieJar::from_headers(request.headers());
    let mut context = UserContext::default();
    let config = auth.config();

    // Try JWT first
    if let Some(jwt_cookie) = jar.get(&config.cookie_access_token_name) {
        match access_token_validate(jwt_cookie.value(), config) {
            Ok(claims) => {
                if let Ok(user_id) = Uuid::parse_str(&claims.sub) {
                    context.user_id = Some(user_id);
                    context.email = Some(claims.email);
                    context.role = claims.role;
                }
            }
            Err(AuthError::TokenExpired) => {
                // Token expired - will try refresh below
            }
            Err(_) => {
                // Invalid JWT (tampered or wrong secret) - clear cookies
                jar = jar
                    .add(access_token_cookie_clear(config))
                    .add(refresh_token_cookie_clear(config));
            }
        }
    }

    // Try refresh token if not authenticated
    if context.user_id.is_none()
        && let Some(refresh_cookie) = jar.get(&config.cookie_refresh_token_name)
        && let Ok((access_token, user_id, email)) =
            try_refresh_token(&auth, refresh_cookie.value()).await
    {
        context.user_id = Some(user_id);
        context.email = Some(email);
        context.role = "authenticated".to_string();

        // Add new JWT cookie to response
        let access_cookie = access_token_cookie_create(access_token, config);
        jar = jar.add(access_cookie);
    }

    // Inject context into request extensions
    request.extensions_mut().insert(context);

    let response = next.run(request).await;

    // Merge cookie updates with response
    (jar, response).into_response()
}

/// Try to refresh access token using refresh token.
///
/// Returns (access_token, user_id, email) if successful.
async fn try_refresh_token<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    auth: &Auth<B, H, E>,
    refresh_token: &str,
) -> Result<(String, Uuid, String), AuthError> {
    let refresh_token_hash = token_hash_sha256(refresh_token);

    // Validate refresh token and get user_id
    let user_id = auth
        .backend()
        .refresh_token_validate(&refresh_token_hash)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .ok_or(AuthError::RefreshTokenInvalid)?;

    // Get user data
    let user = auth
        .backend()
        .user_get_by_id(user_id)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .ok_or(AuthError::UserNotFound)?;

    // Generate new access token
    let access_token = access_token_generate(user.id(), user.email().to_owned(), auth.config())?;

    Ok((access_token, user.id(), user.email().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use std::sync::Arc;
    use tower::util::ServiceExt;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn app_with_context(ctx: UserContext) -> Router {
        let ctx = Arc::new(ctx);

        let inject = {
            let ctx = ctx.clone();
            move |mut req: Request<Body>, next: Next| {
                let ctx = ctx.clone();
                async move {
                    req.extensions_mut().insert((*ctx).clone());
                    next.run(req).await
                }
            }
        };

        Router::new()
            .route("/", get(ok_handler))
            .layer(middleware::from_fn(inject))
    }

    #[tokio::test]
    async fn authenticated_users_pass_through() {
        let app = app_with_context(UserContext {
            user_id: Some(Uuid::new_v4()),
            email: Some("user@example.com".into()),
            role: "authenticated".into(),
        });

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
