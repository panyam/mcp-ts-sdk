# scope-challenge — SEP-2350 server-side step-up against a real AS

Provider-neutral system-under-test for the `scope-challenge` conformance
scenario in [panyam/mcpconformance][conf]. Point `ISSUER` at any RFC-compliant
authorization server and the same binary serves the same wire shape.

Not run by `pnpm run:examples` (it needs an external AS). The conformance
scenario is the client, so there is no `client.ts`.

## What it demonstrates

`createMcpHandler` resolves each tool's `scopeChallenge` callback before
invocation or SSE setup, so an under-scoped call gets

```
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="admin-write",
                  resource_metadata="http://localhost:3100/.well-known/oauth-protected-resource/mcp"
```

and the client re-authorizes and retries per RFC 6750 §3.1.

Two tools cover both callback shapes:

| Tool         | Shape                     | Behaviour                                                                                                                                             |
| ------------ | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `admin_call` | OR hierarchy in user code | `admin-write` satisfies the gate, and so does the parent `admin`. The challenge advertises only `admin-write`, keeping the client on least privilege. |
| `read_item`  | argument-dependent        | `visibility: "public"` needs `tools-read`, `visibility: "private"` needs `admin-write`. The required scope is a function of the request.              |

`read_item` is the case a registration-time declaration cannot express: declare
the write scope statically and every read over-asks for it.

## Provider neutrality

Two things vary between authorization servers, and both are handled generically:

- **Endpoints** come from `ISSUER/.well-known/openid-configuration`, so no
  provider-specific paths appear in the SUT.
- **Scope claims** differ. Keycloak emits `scope` as a space-delimited string,
  Okta emits `scp` as an array. `ScopeAwareVerifier` reads `scp`, `scope` or
  `scopes`. A verifier that knows only one of them sees an empty scope set and
  challenges every call, which is a real bug this shape avoids.

## Running

Fixtures, token minting and the interop matrix live in [the conformance
repo][conf]. Provision a provider, then:

```bash
# Keycloak (local docker fixture, http issuer needs the escape hatch)
MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=true \
  ISSUER=http://localhost:8180/realms/mcpkit-test \
  pnpm --filter @mcp-examples/scope-challenge server

# Okta (https issuer, sets aud)
source <mcpconformance>/examples/auth-fixtures/okta/okta.env
ISSUER="$OKTA_ISSUER" AUDIENCE=api://default \
  pnpm --filter @mcp-examples/scope-challenge server
```

Then run the scenario against it:

```bash
MCP_CONFORMANCE_CONTEXT="$(make -s -C <provider> tokens-context)" \
  node dist/index.js server --url http://localhost:3100/mcp --scenario scope-challenge
```

| Env        | Default              | Meaning                                            |
| ---------- | -------------------- | -------------------------------------------------- |
| `ISSUER`   | local Keycloak realm | AS issuer URL                                      |
| `AUDIENCE` | unset                | expected `aud`; unset means `aud` is not validated |
| `PORT`     | `3100`               | listen port                                        |

[conf]: https://github.com/panyam/mcpconformance/tree/feat/sep-2350-server-scope-challenge/examples/auth-fixtures
