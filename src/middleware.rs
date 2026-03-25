//! Authentication middleware for Axum.

use crate::{
    Auth, AuthBackend, AuthHooks, EmailSender,
    cookies::{access_token_cookie_clear, refresh_token_cookie_clear},
    error::AuthError,
    tokens::access_token_validate,
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
/// This middleware handles JWT validation for protected routes.
/// It should be applied to all routes that may need authentication.
///
/// # Behavior
/// - **JWT present**: Validates JWT and injects authenticated UserContext
/// - **JWT invalid**: Clears auth cookies (potential tampering)
/// - **JWT expired or missing**: Injects anonymous UserContext
/// - **No auth cookies**: Injects anonymous UserContext
///
/// Refresh-token rotation is handled explicitly by `/auth/refresh`.
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
                // Expired access tokens require an explicit refresh request.
            }
            Err(_) => {
                // Invalid JWT (tampered or wrong secret) - clear cookies
                jar = jar
                    .add(access_token_cookie_clear(config))
                    .add(refresh_token_cookie_clear(config));
            }
        }
    }

    // Inject context into request extensions
    request.extensions_mut().insert(context);

    let response = next.run(request).await;

    // Merge cookie updates with response
    (jar, response).into_response()
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
