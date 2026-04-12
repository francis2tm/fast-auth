# fast-auth

An authentication library for Axum with JWT access tokens, rotating refresh tokens, organizations and RBAC, API keys, and pluggable storage.

## Features

- Frontend Ready: ready to use SDKs in `fast-auth/sdk/*`
- Backend-agnostic `AuthBackend`
- Error-first backend contract with `thiserror`
- JWT access tokens with configurable expiry
- Refresh token rotation and replay protection
- Explicit session refresh via `/auth/refresh`
- HttpOnly cookie transport
- Organizations and RBAC
- Bearer API key authentication for protected routes
- API key management endpoints with one-time secret reveal
- Sign-up/sign-in hooks
- Reusable auth conformance test suite

## Quick Start

### 1. Implement `AuthUser`, one typed backend error, and `AuthBackend`

`RequestUser` is the request-scoped auth principal extracted from middleware.
`HydratedUser` is the fully hydrated auth context used for responses,
hooks, and token issuance.

The compile-checked rustdoc on `AuthBackend` shows the full backend contract,
including the small set of grouped input structs that remain part of the API:

- `UserCreateParams`
- `ApiKeyCreateParams`
- `SessionIssueIfPasswordHashParams`
- `SessionExchangeParams`
- `VerificationTokenIssueParams`

### 2. Build auth and mount routes + middleware

```rust,no_run
use axum::{extract::FromRef, middleware, Router};
use fast_auth::{Auth, AuthBackend, AuthConfig};

# #[derive(Clone)]
# struct AppState<B: AuthBackend> {
#     auth: Auth<B>,
# }
# impl<B: AuthBackend> FromRef<AppState<B>> for Auth<B> {
#     fn from_ref(state: &AppState<B>) -> Self {
#         state.auth.clone()
#     }
# }
# fn app_build<B: AuthBackend>(backend: B) -> Result<(), fast_auth::AuthConfigError> {
let mut config = AuthConfig::default();
config.jwt_secret = "your-secret-key-at-least-32-characters-long".to_string();
let auth = Auth::new(config, backend)?;
let app_state = AppState { auth: auth.clone() };

let app: Router = Router::new()
    .merge(auth.routes::<AppState<B>>())
    .layer(middleware::from_fn_with_state(
        auth.clone(),
        fast_auth::middleware::base::<B, (), ()>,
    ))
    .with_state(app_state);
# let _ = app;
# Ok(())
# }
```

### 3. Add the conformance test suite

```rust,no_run
use fast_auth::testing::{Suite, TestContext};

# async fn auth_suite_run<C: TestContext>() {
Suite::<C>::test_all().await;
# }
```

The compile-checked docs on `fast_auth::testing::test_suite!` show a minimal
`TestContext` implementation shape.

## Endpoints

| Method | Path                                                         |
| ------ | ------------------------------------------------------------ |
| POST   | `/auth/sign-up`                                              |
| POST   | `/auth/sign-in`                                              |
| POST   | `/auth/refresh`                                              |
| POST   | `/auth/sign-out`                                             |
| GET    | `/auth/me`                                                   |
| POST   | `/auth/api-keys`                                             |
| GET    | `/auth/api-keys`                                             |
| DELETE | `/auth/api-keys/{id}`                                        |
| GET    | `/auth/organizations`                                        |
| POST   | `/auth/organizations`                                        |
| GET    | `/auth/organizations/{organization_id}`                      |
| PATCH  | `/auth/organizations/{organization_id}`                      |
| DELETE | `/auth/organizations/{organization_id}`                      |
| POST   | `/auth/organizations/current`                                |
| GET    | `/auth/organizations/{organization_id}/members`              |
| PATCH  | `/auth/organizations/{organization_id}/members/{member_user_id}`  |
| DELETE | `/auth/organizations/{organization_id}/members/{member_user_id}`  |
| GET    | `/auth/organizations/{organization_id}/invites`              |
| POST   | `/auth/organizations/{organization_id}/invites`              |
| DELETE | `/auth/organizations/{organization_id}/invites/{invite_id}`  |
| POST   | `/auth/organizations/invites/accept`                         |
| POST   | `/auth/email/confirm/send`                                   |
| GET    | `/auth/email/confirm`                                        |
| POST   | `/auth/password/forgot`                                      |
| POST   | `/auth/password/reset`                                       |

## Protected routes

Protected routes accept either:

- a valid access-token cookie, or
- `Authorization: Bearer <api_key>`

Cookie-backed browser sessions still use `POST /auth/refresh` when the access
token expires. API keys are long-lived credentials managed explicitly through
the API-key endpoints and are not refreshed.

```rust,no_run
use axum::Json;
use fast_auth::{RequestAdmin, RequestOwner, RequestUser};

async fn user_protected_route(request_user: RequestUser) -> Json<String> {
    Json(format!("Hello, {}", request_user.email))
}

async fn admin_protected_route(admin: RequestAdmin) -> Json<String> {
    Json(format!("Hello, {}", admin.email))
}

async fn owner_protected_route(owner: RequestOwner) -> Json<String> {
    Json(format!("Hello, {}", owner.email))
}
```

## API keys

Users can create API keys through the auth API:

- `POST /auth/api-keys` creates a key and returns the plaintext secret once
- `GET /auth/api-keys` lists key metadata
- `DELETE /auth/api-keys/{id}` deletes a key

Keys are stored hashed at rest. The returned plaintext secret is only available
at creation time, so callers should persist it immediately.

API keys authenticate into the organization that owns the key. They do not
mutate the user's stored active organization for cookie-backed sessions.

Use API keys on protected routes with:

```http
Authorization: Bearer sk-<secret>
```

If both a bearer API key and auth cookies are present, `fast-auth` prefers the
bearer API key.

## Refresh flow

`fast-auth` does not silently refresh tokens inside arbitrary protected routes.
The expected browser flow is:

1. Call a protected endpoint with the access-token cookie.
2. If the server returns `401 Unauthorized` because the access token expired,
   call `POST /auth/refresh`.
3. Apply the rotated auth cookies from the refresh response.
4. Retry the original protected request once.

This refresh flow applies only to cookie-backed sessions, not API keys.

## Testing

Enable testing feature:

```toml
[dev-dependencies]
fast-auth = { version = "0.1", features = ["testing"] }
```

Implement `TestContext` and use macro:

```rust,no_run
use fast_auth::testing::TestContext;

# async fn auth_suite_run<C: TestContext>() {
fast_auth::testing::Suite::<C>::test_all().await;
# }
```

## OpenAPI

Generate `fast-auth/docs/openapi.yml`:

```bash
cargo run -p fast-auth --bin openapi
```

## TypeScript SDK

The TypeScript SDK lives at `fast-auth/sdk` and is generated from
`fast-auth/docs/openapi.yml` using `@hey-api/openapi-ts`.
