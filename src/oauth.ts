/**
 * Authorization code with PKCE against the know.sh identity host, over a
 * loopback redirect (RFC 8252 §7.3), as the client `src/registration.ts`
 * resolves. Every token request names the MCP resource with RFC 8707
 * `resource`, which is what gives the access token its single audience.
 *
 * The device flow the CLI used against Auth0 is kept for the legacy
 * KNOWSH_LEGACY_DEVICE_FLOW path only: the identity host serves no device
 * authorization endpoint.
 */
import open from 'open';
import {
  identityEndpoints,
  issuerFor,
  legacyEndpoints,
  type CliConfig,
  type DeviceConfig,
  type LoopbackConfig,
} from './config.js';
import { isTimeout, postForm, timedOut } from './http.js';
import { startLoopbackReceiver, type LoopbackReceiver } from './loopback.js';
import { codeChallenge, generateCodeVerifier, randomNonce, randomState } from './pkce.js';
import { clearRegistration, resolveClient } from './registration.js';
import type { TokenSet } from './tokens.js';

export class InvalidGrantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidGrantError';
  }
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
  token_type: 'Bearer';
  scope?: string;
}

interface ErrorResponse {
  error?: string;
  error_description?: string;
}

export interface LoginOptions {
  /** Injected by the tests; production opens the system browser. */
  openBrowser?: (url: string) => Promise<unknown>;
  timeoutMs?: number;
  /** Prompts default to stderr because stdout is the mcp-proxy's JSON-RPC channel. */
  log?: (line: string) => void;
}

function parseExpiresAt(expiresInSec: number): number {
  return Math.floor(Date.now() / 1000) + Math.max(0, expiresInSec - 30);
}

function toStderr(line: string): void {
  process.stderr.write(`${line}\n`);
}

async function readError(res: Response): Promise<ErrorResponse & { text: string }> {
  const text = await res.text().catch(() => '');
  try {
    return { ...(JSON.parse(text) as ErrorResponse), text };
  } catch {
    return { text };
  }
}

async function postTokenForm(
  endpoint: string,
  body: URLSearchParams,
  label: string,
  timeoutMs: number,
): Promise<TokenResponse> {
  let res: Response;
  try {
    res = await postForm(endpoint, body, timeoutMs);
  } catch (err) {
    if (!isTimeout(err)) throw err;
    throw timedOut(label, timeoutMs);
  }
  if (!res.ok) {
    const failure = await readError(res);
    const detail = `${failure.error ?? res.status} ${failure.error_description ?? failure.text}`.trim();
    if (failure.error === 'invalid_grant') {
      throw new InvalidGrantError(`${label} failed: ${detail}`);
    }
    throw new Error(`${label} failed: ${detail}`);
  }
  return (await res.json()) as TokenResponse;
}

function toTokenSet(
  payload: TokenResponse,
  config: CliConfig,
  clientId: string,
  previousHandle?: string,
): TokenSet {
  return {
    access_token: payload.access_token,
    refresh_token: payload.refresh_token ?? previousHandle,
    id_token: payload.id_token,
    expires_at: parseExpiresAt(payload.expires_in),
    token_type: payload.token_type,
    scope: payload.scope,
    iss: issuerFor(config),
    client_id: clientId,
  };
}

export interface AuthorizeRequest {
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  codeChallenge: string;
}

export function buildAuthorizeUrl(config: LoopbackConfig, request: AuthorizeRequest): string {
  const url = new URL(identityEndpoints(config.issuer).authorize);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: request.clientId,
    redirect_uri: request.redirectUri,
    scope: config.scopes,
    state: request.state,
    nonce: request.nonce,
    code_challenge: request.codeChallenge,
    code_challenge_method: 'S256',
    resource: config.resource,
  }).toString();
  return url.toString();
}

export interface CodeExchange {
  clientId: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
}

export async function exchangeCode(
  config: LoopbackConfig,
  exchange: CodeExchange,
): Promise<TokenSet> {
  const payload = await postTokenForm(
    identityEndpoints(config.issuer).token,
    new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: exchange.clientId,
      code: exchange.code,
      code_verifier: exchange.codeVerifier,
      redirect_uri: exchange.redirectUri,
      resource: config.resource,
    }),
    'code exchange',
    config.requestTimeoutMs,
  );
  return toTokenSet(payload, config, exchange.clientId);
}

/**
 * The host answers an authorization request it will not serve (an unknown
 * client, a scope or resource it does not allow) with its own error page, or
 * with an error on the redirect, never with a code; the loopback receiver would
 * wait out its whole timeout. One request that follows no redirect surfaces the
 * refusal before a browser opens. Returns the reason, or null when the host
 * would go on to sign the user in.
 */
async function authorizeRefusal(authorizeUrl: string, timeoutMs: number): Promise<string | null> {
  let res: Response;
  try {
    res = await fetch(authorizeUrl, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    if (!isTimeout(err)) throw err;
    throw timedOut('authorization check', timeoutMs);
  }
  await res.body?.cancel();
  const location = res.headers.get('location');
  if (!location) return res.ok ? null : `the host answered ${res.status}`;
  const target = new URL(location, authorizeUrl);
  const error = target.searchParams.get('error');
  if (error) {
    const description = target.searchParams.get('error_description');
    return `${error}${description ? ` — ${description}` : ''}`;
  }
  return target.pathname.toLowerCase().endsWith('/error') ? `see ${target}` : null;
}

export async function loginWithLoopback(
  config: LoopbackConfig,
  options: LoginOptions = {},
): Promise<TokenSet> {
  const verifier = generateCodeVerifier();
  const state = randomState();
  const log = options.log ?? toStderr;

  let receiver: LoopbackReceiver | undefined;
  try {
    receiver = await startLoopbackReceiver({ state, timeoutMs: options.timeoutMs });
    const redirectUri = receiver.redirectUri;
    const nonce = randomNonce();
    const authorizeUrlFor = (clientId: string) =>
      buildAuthorizeUrl(config, { clientId, redirectUri, state, nonce, codeChallenge: codeChallenge(verifier) });

    let client = await resolveClient(config);
    let authorizeUrl = authorizeUrlFor(client.clientId);
    let refusal = await authorizeRefusal(authorizeUrl, config.requestTimeoutMs);
    if (refusal && client.stored) {
      // The host no longer knows the stored registration (revoked, or the
      // tenant was reset): register again, once.
      await clearRegistration();
      client = await resolveClient(config);
      authorizeUrl = authorizeUrlFor(client.clientId);
      refusal = await authorizeRefusal(authorizeUrl, config.requestTimeoutMs);
    }
    if (refusal) throw new Error(`the identity host refused the sign-in request: ${refusal}`);

    log('');
    log('Opening your browser to sign in. If it does not open, visit:');
    log(`  ${authorizeUrl}`);
    log('');
    log('Waiting for you to finish signing in…');

    const openBrowser = options.openBrowser ?? open;
    try {
      await openBrowser(authorizeUrl);
    } catch {
      // The printed URL is the fallback.
    }

    const code = await receiver.code;
    return await exchangeCode(config, {
      clientId: client.clientId,
      code,
      codeVerifier: verifier,
      redirectUri,
    });
  } finally {
    await receiver?.close();
  }
}

export async function login(config: CliConfig, options: LoginOptions = {}): Promise<TokenSet> {
  return config.mode === 'loopback'
    ? loginWithLoopback(config, options)
    : loginWithDeviceFlow(config, options);
}

/** `clientId` is the client the handle was issued to, as its token set records it. */
export async function refreshTokens(
  config: CliConfig,
  refreshToken: string,
  clientId?: string,
): Promise<TokenSet> {
  if (config.mode === 'device') {
    return refreshDeviceTokens(config, refreshToken);
  }
  const client = clientId ?? config.clientId;
  if (!client) {
    throw new InvalidGrantError('refresh failed: the stored token set names no client');
  }
  const payload = await postTokenForm(
    identityEndpoints(config.issuer).token,
    new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: client,
      refresh_token: refreshToken,
      resource: config.resource,
    }),
    'refresh',
    config.requestTimeoutMs,
  );
  return toTokenSet(payload, config, client, refreshToken);
}

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

async function requestDeviceCode(config: DeviceConfig): Promise<DeviceCodeResponse> {
  let res: Response;
  try {
    res = await postForm(
      legacyEndpoints(config.auth0Domain).deviceCode,
      new URLSearchParams({
        client_id: config.auth0ClientId,
        scope: config.scopes,
        audience: config.audience,
      }),
      config.requestTimeoutMs,
    );
  } catch (err) {
    if (!isTimeout(err)) throw err;
    throw timedOut('device code request', config.requestTimeoutMs);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`device code request failed: ${res.status} ${text}`);
  }
  return (await res.json()) as DeviceCodeResponse;
}

async function pollForTokens(
  config: DeviceConfig,
  deviceCode: string,
  intervalSec: number,
  expiresInSec: number,
): Promise<TokenResponse> {
  const deadline = Date.now() + expiresInSec * 1000;
  let interval = Math.max(intervalSec, 5) * 1000;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, interval));
    let res: Response;
    try {
      res = await postForm(
        legacyEndpoints(config.auth0Domain).token,
        new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: deviceCode,
          client_id: config.auth0ClientId,
        }),
        config.requestTimeoutMs,
      );
    } catch (err) {
      // One slow poll is not a failed sign-in; the device code's own deadline bounds the loop.
      if (isTimeout(err)) continue;
      throw err;
    }
    const body = (await res.json()) as Partial<TokenResponse> & ErrorResponse;
    if (res.ok && body.access_token) {
      return body as TokenResponse;
    }
    switch (body.error) {
      case 'authorization_pending':
        // User hasn't finished yet — keep polling at the current interval.
        break;
      case 'slow_down':
        // Spec-compliant back-off: bump interval by 5 seconds.
        interval += 5_000;
        break;
      case 'expired_token':
        throw new Error('device code expired — run `know login` again');
      case 'access_denied':
        throw new Error('authorization denied by user');
      default:
        throw new Error(
          `token poll failed: ${body.error ?? res.status} ${body.error_description ?? ''}`,
        );
    }
  }
  throw new Error('device code timed out before user authorized');
}

export async function loginWithDeviceFlow(
  config: DeviceConfig,
  options: LoginOptions = {},
): Promise<TokenSet> {
  const device = await requestDeviceCode(config);
  const log = options.log ?? toStderr;

  log('');
  log('To authorize this CLI, visit:');
  log(`  ${device.verification_uri_complete}`);
  log('');
  log('Verify this code matches the one shown in your browser:');
  log(`  ${device.user_code}`);
  log('');
  log('Waiting for you to finish signing in…');

  const openBrowser = options.openBrowser ?? open;
  try {
    await openBrowser(device.verification_uri_complete);
  } catch {
    // User can click the URL manually.
  }

  const tokens = await pollForTokens(config, device.device_code, device.interval, device.expires_in);
  return toTokenSet(tokens, config, config.auth0ClientId);
}

/** Back-compat alias so callers that say `loginWithPkce` keep working. */
export const loginWithPkce = loginWithDeviceFlow;

async function refreshDeviceTokens(config: DeviceConfig, refreshToken: string): Promise<TokenSet> {
  const payload = await postTokenForm(
    legacyEndpoints(config.auth0Domain).token,
    new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: config.auth0ClientId,
      refresh_token: refreshToken,
      scope: config.scopes,
    }),
    'refresh',
    config.requestTimeoutMs,
  );
  return toTokenSet(payload, config, config.auth0ClientId, refreshToken);
}
