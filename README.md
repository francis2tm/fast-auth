# fast-auth

A simple authentication library for Axum with JWT access tokens, rotating refresh tokens, user API keys, and pluggable storage.

## Features

- Frontend Ready: ready to use SDKs in `fast-auth/sdk/*`
- Backend-agnostic `AuthBackend`
- Error-first backend contract with `thiserror`
- JWT access tokens with configurable expiry
- Refresh token rotation and replay protection
- Explicit session refresh via `/auth/refresh`
- HttpOnly cookie transport
- Bearer API key authentication for protected routes
- API key management endpoints with one-time secret reveal
- Sign-up/sign-in hooks
- Reusable auth conformance test suite

## Quick Start

### 1. Implement `AuthUser`, backend error, and `AuthBackend`

```rust,ignore
use chrono::{DateTime, Utc};
use common::list::{ListPageResult, ListQuery};
use fast_auth::{AuthBackend, AuthBackendError, AuthError, AuthUser};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone)]
struct MyUser {
    id: Uuid,
    email: String,
    password_hash: String,
    email_confirmed_at: Option<DateTime<Utc>>,
    last_sign_in_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl AuthUser for MyUser {
    fn id(&self) -> Uuid { self.id }
    fn email(&self) -> &str { &self.email }
    fn password_hash(&self) -> &str { &self.password_hash }
    fn email_confirmed_at(&self) -> Option<DateTime<Utc>> { self.email_confirmed_at }
    fn last_sign_in_at(&self) -> Option<DateTime<Utc>> { self.last_sign_in_at }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
}

#[derive(Debug, Error)]
enum MyError {
    #[error("user already exists")]
    UserAlreadyExists,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("refresh token invalid")]
    RefreshTokenInvalid,
    #[error("verification token invalid")]
    InvalidToken,
    #[error("unexpected: {0}")]
    Unexpected(String),
}

impl AuthBackendError for MyError {
    fn auth_error(&self) -> AuthError {
        match self {
            MyError::UserAlreadyExists => AuthError::UserAlreadyExists,
            MyError::InvalidCredentials => AuthError::InvalidCredentials,
            MyError::RefreshTokenInvalid => AuthError::RefreshTokenInvalid,
            MyError::InvalidToken => AuthError::InvalidToken,
            MyError::Unexpected(message) => AuthError::Backend(message.clone()),
        }
    }
}

#[derive(Clone)]
struct MyBackend;

impl AuthBackend for MyBackend {
    type User = MyUser;
    type Error = MyError;

    async fn user_find_by_email(&self, _email: &str) -> Result<Option<Self::User>, Self::Error> {
        Ok(None)
    }

    async fn user_get_by_id(&self, _id: Uuid) -> Result<Option<Self::User>, Self::Error> {
        Ok(None)
    }

    async fn user_create(&self, _email: &str, _password_hash: &str) -> Result<Self::User, Self::Error> {
        Err(MyError::UserAlreadyExists)
    }

    async fn api_key_create(
        &self,
        _user_id: Uuid,
        _name: &str,
        _key_prefix: &str,
        _key_hash: &str,
    ) -> Result<fast_auth::AuthApiKey, Self::Error> {
        Err(MyError::Unexpected("not implemented".to_string()))
    }

    async fn api_keys_list(
        &self,
        _user_id: Uuid,
        query: ListQuery<fast_auth::AuthApiKeyListSortBy>,
    ) -> Result<ListPageResult<fast_auth::AuthApiKey>, Self::Error> {
        Ok(query.result_build(Vec::new(), 0))
    }

    async fn api_key_delete(
        &self,
        _user_id: Uuid,
        _api_key_id: Uuid,
    ) -> Result<fast_auth::AuthApiKey, Self::Error> {
        Err(MyError::Unexpected("not implemented".to_string()))
    }

    async fn api_key_authenticate(
        &self,
        _api_key: &str,
        _used_at: DateTime<Utc>,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(None)
    }

    async fn session_issue(&self, _user_id: Uuid, _refresh_token_hash: &str, _expires_at: DateTime<Utc>) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn session_issue_if_password_hash(&self, _user_id: Uuid, _current_password_hash: &str, _refresh_token_hash: &str, _expires_at: DateTime<Utc>) -> Result<(), Self::Error> {
        Err(MyError::InvalidCredentials)
    }

    async fn session_revoke_by_refresh_token_hash(&self, _refresh_token_hash: &str) -> Result<(), Self::Error> {
        Err(MyError::RefreshTokenInvalid)
    }

    async fn session_exchange(&self, _current_refresh_token_hash: &str, _next_refresh_token_hash: &str, _next_expires_at: DateTime<Utc>) -> Result<Uuid, Self::Error> {
        Err(MyError::RefreshTokenInvalid)
    }

    async fn verification_token_issue(&self, _user_id: Uuid, _token_hash: &str, _token_type: fast_auth::verification::VerificationTokenType, _expires_at: DateTime<Utc>) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn email_confirm_apply(&self, _token_hash: &str) -> Result<(), Self::Error> {
        Err(MyError::InvalidToken)
    }

    async fn password_reset_apply(&self, _token_hash: &str, _password_hash: &str) -> Result<(), Self::Error> {
        Err(MyError::InvalidToken)
    }
}
```

### 2. Build auth and mount routes + middleware

```rust,ignore
use axum::{extract::FromRef, middleware, Router};
use fast_auth::{Auth, AuthConfig};

let backend = MyBackend;
let mut config = AuthConfig::default();
config.jwt_secret = "your-secret-key-at-least-32-characters-long".to_string();
let auth = Auth::new(config, backend)?;

#[derive(Clone)]
struct AppState {
    auth: Auth<MyBackend>,
}

impl FromRef<AppState> for Auth<MyBackend> {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

let app_state = AppState { auth: auth.clone() };

let app = Router::new()
    .merge(auth.routes::<AppState>())
    .layer(middleware::from_fn_with_state(
        auth.clone(),
        fast_auth::middleware::base::<MyBackend, (), ()>,
    ))
    .with_state(app_state);
```

## Endpoints

| Method | Path                       |
| ------ | -------------------------- |
| POST   | `/auth/api-keys`           |
| GET    | `/auth/api-keys`           |
| DELETE | `/auth/api-keys/{id}`      |
| POST   | `/auth/sign-up`            |
| POST   | `/auth/sign-in`            |
| POST   | `/auth/refresh`            |
| POST   | `/auth/sign-out`           |
| GET    | `/auth/me`                 |
| POST   | `/auth/email/confirm/send` |
| GET    | `/auth/email/confirm`      |
| POST   | `/auth/password/forgot`    |
| POST   | `/auth/password/reset`     |

## Protected routes

Protected routes accept either:

- a valid access-token cookie, or
- `Authorization: Bearer <api_key>`

Cookie-backed browser sessions still use `POST /auth/refresh` when the access
token expires. API keys are long-lived credentials managed explicitly through
the API-key endpoints and are not refreshed.

```rust,ignore
use axum::Json;
use fast_auth::CurrentUser;

async fn protected_route(user: CurrentUser) -> Json<String> {
    Json(format!("Hello, {}", user.email))
}
```

## API keys

Users can create API keys through the auth API:

- `POST /auth/api-keys` creates a key and returns the plaintext secret once
- `GET /auth/api-keys` lists key metadata
- `DELETE /auth/api-keys/{id}` deletes a key

Keys are stored hashed at rest. The returned plaintext secret is only available
at creation time, so callers should persist it immediately.

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

```rust,ignore
use fast_auth::testing::TestContext;

struct TestApp;

impl TestContext for TestApp {
    type User = MyUser;

    async fn spawn() -> (String, reqwest::Client, Self) { todo!() }
    fn auth_config(&self) -> &fast_auth::AuthConfig { todo!() }
    fn backend(&self) -> &impl fast_auth::AuthBackend { todo!() }
    async fn refresh_token_get(&self, _hash: &str) -> Option<fast_auth::testing::RefreshTokenInfo> { todo!() }
    async fn refresh_token_expire(&self, _hash: &str) {}
    async fn user_password_hash_set(&self, _user_id: uuid::Uuid, _password_hash: &str) {}
}

fast_auth::test_suite!(TestApp);
```

## OpenAPI

Generate `fast-auth/docs/openapi.yml`:

```bash
cargo run -p fast-auth --bin openapi
```

## TypeScript SDK

The TypeScript SDK lives at `fast-auth/sdk` and is generated from
`fast-auth/docs/openapi.yml` using `@hey-api/openapi-ts`.
