/**
 * know.sh CLI — baked-in public OAuth client configuration.
 *
 * The client_id is a PUBLIC identifier for a Native app (Authorization Code + PKCE,
 * no client secret). It's safe to ship verbatim.
 *
 * Defaults name the development realm because it is the only know.sh identity
 * realm that exists; the production realm (https://id.know.sh) is registered in
 * the contract but not deployed. Every value has an environment override.
 */

const IDENTITY_SCOPES = ['openid', 'profile', 'offline_access'];

const MCP_SCOPES = [
  'research:read',
  'research:write',
  'findings:read',
  'findings:write',
  'campaigns:read',
  'campaigns:write',
  'operations:read',
  'operations:write',
];

export const DEFAULTS = {
  issuer: 'https://id.dev.know.sh',
  clientId: 'know-cli-development',
  /** RFC 8707 resource indicator. The trailing slash is part of the identifier. */
  resource: 'https://mcp.dev.know.sh/',
  scopes: [...IDENTITY_SCOPES, ...MCP_SCOPES].join(' '),
  mcpUrl: 'https://mcp.dev.know.sh/mcp',
} as const;

/** Auth0, reachable only through KNOWSH_LEGACY_DEVICE_FLOW until the tenant retires. */
export const LEGACY_DEFAULTS = {
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
  mcpUrl: 'https://mcp.know.sh/mcp',
} as const;

export interface LoopbackConfig {
  mode: 'loopback';
  issuer: string;
  clientId: string;
  resource: string;
  scopes: string;
  mcpUrl: string;
}

export interface DeviceConfig {
  mode: 'device';
  auth0Domain: string;
  auth0ClientId: string;
  audience: string;
  scopes: string;
  mcpUrl: string;
}

export type CliConfig = LoopbackConfig | DeviceConfig;

type Env = Record<string, string | undefined>;

function flagIsSet(value: string | undefined): boolean {
  const normalized = value?.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

export function legacyDeviceFlowRequested(env: Env = process.env): boolean {
  return flagIsSet(env.KNOWSH_LEGACY_DEVICE_FLOW);
}

export function resolveConfig(env: Env = process.env): CliConfig {
  if (legacyDeviceFlowRequested(env)) {
    return {
      mode: 'device',
      auth0Domain: env.KNOWSH_AUTH0_DOMAIN ?? LEGACY_DEFAULTS.auth0Domain,
      auth0ClientId: env.KNOWSH_AUTH0_CLIENT_ID ?? LEGACY_DEFAULTS.auth0ClientId,
      audience: env.KNOWSH_AUDIENCE ?? LEGACY_DEFAULTS.audience,
      scopes: env.KNOWSH_SCOPES ?? LEGACY_DEFAULTS.scopes,
      mcpUrl: env.KNOWSH_MCP_URL ?? LEGACY_DEFAULTS.mcpUrl,
    };
  }
  return {
    mode: 'loopback',
    issuer: env.KNOWSH_ISSUER ?? DEFAULTS.issuer,
    clientId: env.KNOWSH_CLIENT_ID ?? DEFAULTS.clientId,
    resource: env.KNOWSH_RESOURCE ?? DEFAULTS.resource,
    scopes: env.KNOWSH_SCOPES ?? DEFAULTS.scopes,
    mcpUrl: env.KNOWSH_MCP_URL ?? DEFAULTS.mcpUrl,
  };
}

function normalizeDomain(domain: string): string {
  return domain.replace(/^https?:\/\//, '').replace(/\/+$/, '');
}

/** The `iss` value tokens from this configuration carry. */
export function issuerFor(config: CliConfig): string {
  return config.mode === 'loopback'
    ? config.issuer.replace(/\/+$/, '')
    : `https://${normalizeDomain(config.auth0Domain)}/`;
}

export function identityEndpoints(issuer: string) {
  const base = issuer.replace(/\/+$/, '');
  return {
    authorize: `${base}/connect/authorize`,
    token: `${base}/connect/token`,
    revocation: `${base}/connect/revocation`,
  };
}

export function legacyEndpoints(auth0Domain: string) {
  const base = `https://${normalizeDomain(auth0Domain)}`;
  return {
    deviceCode: `${base}/oauth/device/code`,
    token: `${base}/oauth/token`,
  };
}
