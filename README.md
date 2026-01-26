# fast-auth

A simple, extensible authentication library for Axum with JWT and refresh tokens.

## Features

- **Backend Agnostic** for any database and ORM
- **JWT access tokens** with configurable expiry
- **Refresh tokens** with automatic rotation and revocation
- **HttpOnly cookies** for secure token storage
- **Lifecycle hooks** for sign-up/sign-in events
- **Axum middleware** for transparent token validation and refresh
- **Integration test suite** for verifying backend implementation

## Quick Start

### 1. Implement the Backend Trait

Create your database backend by implementing `AuthBackend`:

```rust
use fast_auth::{AuthBackend, AuthUser, AuthRefreshToken};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone)]
struct MyUser {
    id: Uuid,
    email: String,
    password_hash: String,
    email_confirmed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl AuthUser for MyUser {
    fn id(&self) -> Uuid { self.id }
    fn email(&self) -> &str { &self.email }
    fn password_hash(&self) -> &str { &self.password_hash }
    fn email_confirmed_at(&self) -> Option<DateTime<Utc>> { self.email_confirmed_at }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
}

#[derive(Clone)]
struct MyBackend { /* your db pool */ }

impl AuthBackend for MyBackend {
    type User = MyUser;
    type RefreshToken = MyRefreshToken;
    type Error = MyError;

    async fn user_find_by_email(&self, email: &str) -> Result<Option<Self::User>, Self::Error> {
        // Query your database...
    }

    // ... implement other methods
}
```

### 2. Create the Auth Instance

```rust
use fast_auth::{Auth, AuthConfig};
use axum::{Router, extract::FromRef, middleware};

let backend = MyBackend::new();
let secret = std::env::var("AUTH_JWT_SECRET").expect("AUTH_JWT_SECRET found");
let auth = Auth::new(AuthConfig { jwt_secret: secret, ..Default::default() }, backend)?;

#[derive(Clone)]
struct AppState {
    auth: Auth<MyBackend>,
}

impl FromRef<AppState> for Auth<MyBackend> {
    fn from_ref(s: &AppState) -> Self { s.auth.clone() }
}

let state = AppState { auth: auth.clone() };

let app = Router::new()
    .merge(auth.routes::<AppState>())
    .layer(middleware::from_fn_with_state(
        auth.clone(),
        fast_auth::middleware::base::<MyBackend, ()>,
    ))
    .with_state(state);
```

## Endpoints

| Method | Path                | Description                      |
| ------ | ------------------- | -------------------------------- |
| POST   | `/v1/auth/sign-up`  | Create new user                  |
| POST   | `/v1/auth/sign-in`  | Authenticate user                |
| POST   | `/v1/auth/sign-out` | Sign out (revokes tokens)        |
| GET    | `/v1/auth/me`       | Get current user (requires auth) |

## Configuration

Set the following environment variable:

```bash
AUTH_JWT_SECRET=your-secret-key-at-least-32-characters-long
```

Or configure programmatically:

```rust
use fast_auth::AuthConfig;
use std::time::Duration;

let config = AuthConfig {
    jwt_secret: "your-secret-key-at-least-32-characters-long".to_string(),
    access_token_expiry: Duration::from_secs(15 * 60),  // 15 minutes
    refresh_token_expiry: Duration::from_secs(7 * 24 * 60 * 60),  // 7 days
    cookie_domain: Some("example.com".to_string()),
    cookie_secure: true,
    ..Default::default()
};
```

## Hooks

Use hooks to run custom logic after authentication events:

```rust
use fast_auth::{Auth, AuthHooks, AuthUser};

#[derive(Clone)]
struct MyHooks;

impl<U: AuthUser> AuthHooks<U> for MyHooks {
    fn on_sign_up(&self, user: &U) -> impl std::future::Future<Output = ()> + Send {
        let user_id = user.id();
        async move {
            // Send welcome email, create Stripe customer, etc.
            println!("New user signed up: {user_id}");
        }
    }
}

let auth = Auth::new(config, backend)?
    .with_hooks(MyHooks);
```

## Protected Routes

Use `AuthUserExtractor` to protect routes:

```rust
use fast_auth::AuthUserExtractor;
use axum::Json;

async fn protected_route(auth: AuthUserExtractor) -> Json<String> {
    Json(format!("Hello, {}!", auth.email))
}
```

## Testing

`fast-auth` includes a comprehensive integration test suite that you can run against your own backend implementation.

1. Enable the `testing` feature in `Cargo.toml`:

```toml
[dev-dependencies]
fast-auth = { version = "0.1", features = ["testing"] }
```

2. Implement `fast_auth::testing::TestContext` for your test app:

```rust
use fast_auth::testing::TestContext;

struct TestApp { /* ... */ }

impl TestContext for TestApp {
    type User = MyUser;

    // Helper to spawn a fresh test instance
    async fn spawn() -> (String, reqwest::Client, Self) {
        // ... return base_url, http_client, and app state
    }
}
```

3. Use the `test_suite!` macro to generate tests:

```rust
// tests/auth.rs
use fast_auth::test_suite;

// Generates individual #[tokio::test] functions
test_suite!(TestApp);
```
