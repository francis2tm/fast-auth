# fast-auth React SDK (internal)

Small React SDK for `fast-auth` built from the crate OpenAPI spec.

## Generate client

```bash
pnpm install
pnpm run generate
```

This runs:

1. `cargo run --manifest-path ../../Cargo.toml --bin openapi` to refresh `fast-auth/docs/openapi.yml`
2. `@hey-api/openapi-ts` to regenerate `src/generated`

## Build

```bash
pnpm run build
```

## Usage

```tsx
import { FastAuthProvider, useAuth } from '@internal/fast-auth-react';

function App() {
  return (
    <FastAuthProvider baseUrl="http://localhost:30000">
      <Page />
    </FastAuthProvider>
  );
}

function Page() {
  const { user, loading, signIn, signOut } = useAuth();

  if (loading) return <div>Loading...</div>;

  return user ? (
    <button onClick={() => signOut()}>Sign out</button>
  ) : (
    <button
      onClick={() =>
        signIn({
          email: 'user@example.com',
          password: 'SecurePass123'
        })
      }
    >
      Sign in
    </button>
  );
}
```

## Parse fast-auth TOML config

```ts
import { authConfigParseToml } from '@internal/fast-auth-react';

const tomlText = `
[auth.jwt]
issuer = "fast-auth"
audience = "authenticated"

[auth.token]
access_expiry_secs = 900
refresh_expiry_secs = 604800

[auth.password]
min_length = 12
max_length = 128
require_letter = true
require_number = true

[auth.cookie]
access_token_name = "access_token"
refresh_token_name = "refresh_token"
domain = ""
path = "/"
secure = false
same_site = "lax"

[auth.email]
confirmation_require = false
link_base_url = "http://localhost:3000"
verification_token_expiry_secs = 3600
password_reset_token_expiry_secs = 3600
`;

const config = authConfigParseToml(tomlText);
console.log(config.auth.password.min_length); // 12
```

The parser is intentionally strict:

- unknown sections/keys are rejected
- missing required keys are rejected
- duplicate sections/keys are rejected
- semantic constraints are validated (e.g. `max_length >= min_length`)

## Notes

- Cookies are required for auth; the SDK sets `credentials: "include"` by default.
- Your backend CORS policy must allow credentials and your frontend origin.
