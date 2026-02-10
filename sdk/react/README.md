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

## Notes

- Cookies are required for auth; the SDK sets `credentials: "include"` by default.
- Your backend CORS policy must allow credentials and your frontend origin.
