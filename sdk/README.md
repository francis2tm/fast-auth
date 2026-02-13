# fast-auth TypeScript SDK (internal)

TypeScript-only SDK for `fast-auth`, generated from the crate OpenAPI spec.

## Generate client

```bash
pnpm install
pnpm run generate
```

This runs:

1. `@hey-api/openapi-ts` to regenerate `src/generated` from `fast-auth/docs/openapi.yml`

## Build

```bash
pnpm run build
```

## Parse fast-auth TOML config

```ts
import { authConfigParseToml } from "@fast-auth/sdk";

const config = authConfigParseToml(tomlText);
```

## Parse fast-auth.toml from disk (server/build-time)

```ts
import { parseFastAuthToml } from "@fast-auth/sdk/server";

const config = parseFastAuthToml();
```
