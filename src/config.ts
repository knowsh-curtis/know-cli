/**
 * know.sh CLI — baked-in public OAuth client configuration.
 *
 * The client_id is a PUBLIC identifier for a Native app (Authorization Code + PKCE,
 * no client secret). It's safe to ship verbatim.
 *
 * Dev and prod share a tenant today; once we split we'll add a --env flag
 * or derive from mcpUrl.
 */
export const DEFAULTS = {
  auth0Domain: 'dev-hcpmhp1w4f2455pb.us.auth0.com',
  auth0ClientId: 'rEsn27jbd8IAD7k1JkRsES3pEKFwyjJd',
  audience: 'https://mcp.know.sh',
  scopes: [
    'openid',
    'profile',
    'email',
    'offline_access',
    'research:read',
    'research:write',
    'findings:read',
    'findings:write',
  ].join(' '),
  /** Where the hosted MCP server lives. */
  mcpUrl: 'https://mcp.know.sh/mcp',
} as const;

/** Build-time overrides from env (useful for dev/local testing). */
export function resolveConfig() {
  return {
    auth0Domain: process.env.KNOWSH_AUTH0_DOMAIN ?? DEFAULTS.auth0Domain,
    auth0ClientId: process.env.KNOWSH_AUTH0_CLIENT_ID ?? DEFAULTS.auth0ClientId,
    audience: process.env.KNOWSH_AUDIENCE ?? DEFAULTS.audience,
    scopes: process.env.KNOWSH_SCOPES ?? DEFAULTS.scopes,
    mcpUrl: process.env.KNOWSH_MCP_URL ?? DEFAULTS.mcpUrl,
  };
}
