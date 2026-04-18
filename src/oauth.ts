/**
 * Device Authorization Flow (RFC 8628) against Auth0. No loopback listener,
 * no callback URL matching drama. Works on headless machines too.
 *
 * Auth0's documented recommendation for CLIs; `auth0/auth0-cli` uses it and
 * the older `auth0/k8s-pixy-auth` (loopback + PKCE) was archived in favor of
 * this flow.
 */
import open from 'open';
import type { TokenSet } from './tokens.js';

export interface OAuthParams {
  auth0Domain: string;
  auth0ClientId: string;
  audience: string;
  scopes: string;
}

function parseExpiresAt(expiresInSec: number): number {
  return Math.floor(Date.now() / 1000) + Math.max(0, expiresInSec - 30);
}

function normalizeDomain(domain: string): string {
  return domain.replace(/^https?:\/\//, '').replace(/\/+$/, '');
}

function iss(domain: string): string {
  return `https://${normalizeDomain(domain)}/`;
}

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
  token_type: 'Bearer';
  scope?: string;
}

async function requestDeviceCode(params: OAuthParams): Promise<DeviceCodeResponse> {
  const domain = normalizeDomain(params.auth0Domain);
  const res = await fetch(`https://${domain}/oauth/device/code`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: params.auth0ClientId,
      scope: params.scopes,
      audience: params.audience,
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`device code request failed: ${res.status} ${text}`);
  }
  return (await res.json()) as DeviceCodeResponse;
}

async function pollForTokens(
  params: OAuthParams,
  deviceCode: string,
  intervalSec: number,
  expiresInSec: number,
): Promise<TokenResponse> {
  const domain = normalizeDomain(params.auth0Domain);
  const deadline = Date.now() + expiresInSec * 1000;
  let interval = Math.max(intervalSec, 5) * 1000;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, interval));
    const res = await fetch(`https://${domain}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceCode,
        client_id: params.auth0ClientId,
      }),
    });
    const body = (await res.json()) as Partial<TokenResponse> & {
      error?: string;
      error_description?: string;
    };
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

export async function loginWithDeviceFlow(params: OAuthParams): Promise<TokenSet> {
  const device = await requestDeviceCode(params);

  // Present the user code prominently; most CLIs print both the URL and the
  // code so users on headless shells can type them on another device.
  console.log('');
  console.log('To authorize this CLI, visit:');
  console.log(`  ${device.verification_uri_complete}`);
  console.log('');
  console.log('Verify this code matches the one shown in your browser:');
  console.log(`  ${device.user_code}`);
  console.log('');
  console.log('Waiting for you to finish signing in…');

  try {
    await open(device.verification_uri_complete);
  } catch {
    // User can click the URL manually.
  }

  const tokens = await pollForTokens(
    params,
    device.device_code,
    device.interval,
    device.expires_in,
  );

  return {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    id_token: tokens.id_token,
    expires_at: parseExpiresAt(tokens.expires_in),
    token_type: tokens.token_type,
    scope: tokens.scope,
    iss: iss(params.auth0Domain),
  };
}

/** Back-compat alias so callers that say `loginWithPkce` keep working. */
export const loginWithPkce = loginWithDeviceFlow;

export async function refreshTokens(
  params: OAuthParams,
  refreshToken: string,
): Promise<TokenSet> {
  const domain = normalizeDomain(params.auth0Domain);
  const res = await fetch(`https://${domain}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: params.auth0ClientId,
      refresh_token: refreshToken,
      scope: params.scopes,
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`refresh failed: ${res.status} ${text}`);
  }
  const payload = (await res.json()) as TokenResponse;
  return {
    access_token: payload.access_token,
    refresh_token: payload.refresh_token ?? refreshToken,
    id_token: payload.id_token,
    expires_at: parseExpiresAt(payload.expires_in),
    token_type: payload.token_type,
    scope: payload.scope,
    iss: iss(params.auth0Domain),
  };
}
