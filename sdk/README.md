# fast-auth TypeScript SDK (internal)

TypeScript-only SDK for `fast-auth`, generated from the crate OpenAPI spec.

## Generate client

```bash
cargo run -p fast-auth --bin openapi
pnpm install
pnpm run generate
```

This runs:

1. `cargo run -p fast-auth --bin openapi` to regenerate `fast-auth/docs/openapi.yml`
2. `@hey-api/openapi-ts` to regenerate `src/generated` from `fast-auth/docs/openapi.yml`

## Build

```bash
pnpm run build
```

## Parse fast-auth TOML config

```ts
import { authConfigParseToml } from "@fast-auth/sdk";

const config = authConfigParseToml(tomlText);
```

## Parse config/auth.toml from disk (server/build-time)

```ts
import { parseFastAuthToml } from "@fast-auth/sdk/server";

const config = parseFastAuthToml();
```
