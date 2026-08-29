/**
 * Provider-neutral SUT for SEP-2350 server-side scope challenges, driven by the
 * `scope-challenge` scenario in panyam/mcpconformance. Point `ISSUER` at any
 * RFC-compliant authorization server: Keycloak, Okta, Entra, WorkOS.
 *
 * The challenge wire shape (RFC 6750 §3.1 + RFC 9728) is provider-blind, so one
 * binary covers every AS. The two provider-specific bits are handled generically:
 *
 *   - AS endpoints are discovered from `ISSUER/.well-known/openid-configuration`
 *     rather than hardcoded per provider.
 *   - Scopes are read from whichever claim the IdP emits: `scp` (array or string,
 *     Okta / Entra), `scope` (space-delimited string, Keycloak / RFC 6749), or
 *     `scopes` (array).
 *
 * Two tools, covering both halves of the callback API:
 *
 *   - `admin_call` shows an OR hierarchy expressed in the callback. `admin-write`
 *     satisfies it, and so does the parent `admin`, but the challenge advertises
 *     only `admin-write` so the client is guided to least privilege.
 *   - `read_item` shows an argument-dependent challenge, the case that motivated
 *     the callback design. Required scope is a function of the request, not a
 *     property of the tool.
 *
 * Env (this story is operator-driven rather than argv-driven, so it skips
 * `parseExampleArgs`):
 *   ISSUER    AS issuer URL. Default: the local Keycloak fixture realm.
 *   AUDIENCE  expected `aud` claim. Empty means `aud` is not checked.
 *   PORT      listen port. Default 3100.
 *
 * An `http://` issuer (the local Keycloak fixture) additionally needs
 * `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=true`, or `mcpAuthMetadataRouter`
 * rejects the issuer URL. An https issuer needs no such flag.
 *
 * Fixtures, runbook and the interop matrix:
 *   https://github.com/panyam/mcpconformance/tree/feat/sep-2350-server-scope-challenge/examples/auth-fixtures
 */
import type { OAuthTokenVerifier } from '@modelcontextprotocol/express';
import {
    createMcpExpressApp,
    getOAuthProtectedResourceMetadataUrl,
    mcpAuthMetadataRouter,
    requireBearerAuth
} from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import type { AuthInfo, McpServerFactory, ScopeChallengeHandler } from '@modelcontextprotocol/server';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import type { JWTPayload } from 'jose';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import * as z from 'zod/v4';

const PORT = Number.parseInt(process.env.PORT || '3100', 10);
const ISSUER = (process.env.ISSUER || 'http://localhost:8180/realms/mcpkit-test').replace(/\/$/, '');
const AUDIENCE = process.env.AUDIENCE || '';
const RESOURCE_URL = new URL(`http://localhost:${PORT}/mcp`);

interface OidcMetadata {
    issuer: string;
    authorization_endpoint?: string;
    token_endpoint?: string;
    jwks_uri: string;
}

const discoveryResponse = await fetch(`${ISSUER}/.well-known/openid-configuration`);
const meta = (await discoveryResponse.json()) as OidcMetadata;
const JWKS = createRemoteJWKSet(new URL(meta.jwks_uri));

/**
 * Reads scopes from whichever claim the provider emits. Surfacing `scp` was a
 * real finding: Keycloak emits `scope` as a space-delimited string, Okta emits
 * `scp` as an array, and a verifier that knows only one of the two silently
 * sees an empty scope set and challenges every call.
 */
class ScopeAwareVerifier implements OAuthTokenVerifier {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const { payload } = await jwtVerify(token, JWKS, {
            issuer: ISSUER,
            ...(AUDIENCE ? { audience: AUDIENCE } : {})
        });
        const claims = payload as JWTPayload & {
            scp?: string[] | string;
            scope?: string;
            scopes?: string[];
            cid?: string;
            client_id?: string;
            azp?: string;
        };
        let scopes: string[] = [];
        if (Array.isArray(claims.scopes)) {
            scopes = claims.scopes.filter((s): s is string => typeof s === 'string');
        } else if (Array.isArray(claims.scp)) {
            scopes = claims.scp.filter((s): s is string => typeof s === 'string');
        } else if (typeof claims.scp === 'string') {
            scopes = claims.scp.split(/\s+/).filter(Boolean);
        } else if (typeof claims.scope === 'string') {
            scopes = claims.scope.split(/\s+/).filter(Boolean);
        }
        return {
            token,
            clientId: claims.cid ?? claims.client_id ?? claims.azp ?? 'unknown',
            scopes,
            expiresAt: typeof claims.exp === 'number' ? claims.exp : 0
        };
    }
}

/**
 * OR hierarchy in user code. The SDK deliberately infers no hierarchies, so the
 * parent relationship lives here. Note the asymmetry the conformance scenario
 * checks for: `admin` satisfies the gate, but the advertised challenge names
 * only `admin-write`, so a client that has neither is guided to the narrower
 * scope rather than the broader one.
 */
const REQUIRED = 'admin-write';
const ACCEPTED_PARENT = 'admin';

const adminChallenge: ScopeChallengeHandler = ({ authInfo }) => {
    if (authInfo === undefined) return;
    const held = new Set(authInfo.scopes);
    if (held.has(REQUIRED) || held.has(ACCEPTED_PARENT)) return;
    return { scopes: [REQUIRED], errorDescription: `${REQUIRED} is required to call admin_call` };
};

/**
 * Argument-dependent challenge, the case that motivated the redesign. A static
 * per-tool declaration would have to demand the write scope for every call,
 * including the read-only ones, which over-asks on the common path.
 */
const readItemChallenge: ScopeChallengeHandler = ({ request, authInfo }) => {
    const visibility = (request.params as { arguments?: { visibility?: unknown } } | undefined)?.arguments?.visibility;
    if (visibility !== 'public' && visibility !== 'private') return;
    const needed = visibility === 'private' ? 'admin-write' : 'tools-read';
    if (authInfo?.scopes.includes(needed)) return;
    return { scopes: [needed], errorDescription: `${visibility} items require ${needed}` };
};

const buildServer: McpServerFactory = () => {
    const server = new McpServer({ name: 'scope-challenge-sut', version: '0.2.0' });

    server.registerTool(
        'admin_call',
        {
            description: `Requires ${REQUIRED}. The parent scope ${ACCEPTED_PARENT} also satisfies the gate, but the challenge advertises only ${REQUIRED}.`,
            inputSchema: z.object({}),
            scopeChallenge: adminChallenge
        },
        async () => ({ content: [{ type: 'text' as const, text: 'admin_call: ok' }] })
    );

    server.registerTool(
        'read_item',
        {
            description: 'Required scope depends on the visibility argument: public needs tools-read, private needs admin-write.',
            inputSchema: z.object({ visibility: z.enum(['public', 'private']) }),
            scopeChallenge: readItemChallenge
        },
        async ({ visibility }) => ({ content: [{ type: 'text' as const, text: `read_item: ${visibility} ok` }] })
    );

    return server;
};

// The scope challenge is resolved before tool invocation or SSE setup, so the
// 403 and its WWW-Authenticate header still reach the wire. `resourceMetadataUrl`
// is required config here, not an option, which is what puts the RFC 9728 link
// into every challenge.
const handler = createMcpHandler(buildServer, {
    scopeChallenge: { resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(RESOURCE_URL) }
});

const app = createMcpExpressApp({ host: 'localhost' });

app.use(
    mcpAuthMetadataRouter({
        oauthMetadata: {
            issuer: ISSUER,
            authorization_endpoint: meta.authorization_endpoint ?? `${ISSUER}/authorize`,
            token_endpoint: meta.token_endpoint ?? `${ISSUER}/token`,
            jwks_uri: meta.jwks_uri,
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code', 'client_credentials'],
            code_challenge_methods_supported: ['S256']
        },
        resourceServerUrl: RESOURCE_URL,
        scopesSupported: ['tools-read', 'tools-call', 'admin-write', 'admin'],
        resourceName: 'scope-challenge-sut'
    })
);

const auth = requireBearerAuth({
    verifier: new ScopeAwareVerifier(),
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(RESOURCE_URL)
});
const node = toNodeHandler(handler);
app.all('/mcp', auth, (req, res) => void node(req, res, req.body));

app.listen(PORT, () => {
    console.error(`[server] scope-challenge SUT on ${RESOURCE_URL.href}`);
    console.error(`[server]   AS issuer: ${ISSUER}`);
    console.error(`[server]   audience:  ${AUDIENCE || '(unset, aud not validated)'}`);
    console.error(`[server]   jwks_uri:  ${meta.jwks_uri}`);
});
