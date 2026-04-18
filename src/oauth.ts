/**
 * Authorization Code + PKCE against Auth0 with a loopback redirect_uri.
 * Returns the token set on success; rejects with a clean message otherwise.
 */
import http from 'node:http';
import { AddressInfo } from 'node:net';
import open from 'open';
import { codeChallenge, generateCodeVerifier, randomState } from './pkce.js';
import type { TokenSet } from './tokens.js';

export interface OAuthParams {
  auth0Domain: string;
  auth0ClientId: string;
  audience: string;
  scopes: string;
  /** 'localhost' or '127.0.0.1'. Auth0 Native apps accept either without a port. */
  loopbackHost?: string;
}

function parseExpiresAt(expiresInSec: number): number {
  return Math.floor(Date.now() / 1000) + Math.max(0, expiresInSec - 30);
}

function iss(domain: string): string {
  return domain.startsWith('http') ? domain.replace(/\/+$/, '') + '/'
    : `https://${domain}/`;
}

export async function loginWithPkce(params: OAuthParams): Promise<TokenSet> {
  const host = params.loopbackHost ?? '127.0.0.1';
  const verifier = generateCodeVerifier();
  const challenge = codeChallenge(verifier);
  const state = randomState();

  // Spin up a loopback listener on an ephemeral port before starting the browser.
  // Auth0 Native apps allow any port on http://localhost or http://127.0.0.1 so
  // long as the path matches the registered callback (/callback in our app).
  const server = http.createServer();
  await new Promise<void>((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, host, () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  const redirectUri = `http://${host}:${port}/callback`;

  const auth0Domain = params.auth0Domain.replace(/^https?:\/\//, '').replace(/\/+$/, '');
  const authorizeUrl = new URL(`https://${auth0Domain}/authorize`);
  authorizeUrl.searchParams.set('client_id', params.auth0ClientId);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', params.scopes);
  authorizeUrl.searchParams.set('audience', params.audience);
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');
  authorizeUrl.searchParams.set('prompt', 'login');

  const codePromise = new Promise<string>((resolve, reject) => {
    server.on('request', (req, res) => {
      if (!req.url) return;
      const url = new URL(req.url, `http://${host}:${port}`);
      if (url.pathname !== '/callback') {
        res.writeHead(404).end();
        return;
      }
      const returnedState = url.searchParams.get('state');
      const code = url.searchParams.get('code');
      const error = url.searchParams.get('error');
      const errorDesc = url.searchParams.get('error_description');

      if (error) {
        res.writeHead(400, { 'content-type': 'text/html' });
        res.end(
          `<html><body style="font-family:system-ui;padding:24px"><h2>know.sh login failed</h2><p><code>${escapeHtml(error)}</code>${errorDesc ? `: ${escapeHtml(errorDesc)}` : ''}</p><p>You can close this tab.</p></body></html>`,
        );
        reject(new Error(`authorization error: ${error}${errorDesc ? ` — ${errorDesc}` : ''}`));
        return;
      }
      if (!code) {
        res.writeHead(400).end('missing code');
        reject(new Error('authorization response missing code'));
        return;
      }
      if (returnedState !== state) {
        res.writeHead(400).end('state mismatch');
        reject(new Error('state mismatch (possible CSRF)'));
        return;
      }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(
        `<html><body style="font-family:system-ui;padding:24px"><h2>Signed in to know.sh</h2><p>You can close this tab and return to your terminal.</p></body></html>`,
      );
      resolve(code);
    });
  });

  console.log('Opening your browser to sign in at know.sh…');
  console.log(`If it does not open, visit: ${authorizeUrl.toString()}`);
  try {
    await open(authorizeUrl.toString());
  } catch {
    // fall through — the user can click the printed URL.
  }

  let code: string;
  try {
    code = await codePromise;
  } finally {
    server.close();
  }

  // Exchange the code for tokens.
  const tokenRes = await fetch(`https://${auth0Domain}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: params.auth0ClientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  });
  if (!tokenRes.ok) {
    const text = await tokenRes.text().catch(() => '');
    throw new Error(`token exchange failed: ${tokenRes.status} ${text}`);
  }
  const payload = (await tokenRes.json()) as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    expires_in: number;
    token_type: 'Bearer';
    scope?: string;
  };
  return {
    access_token: payload.access_token,
    refresh_token: payload.refresh_token,
    id_token: payload.id_token,
    expires_at: parseExpiresAt(payload.expires_in),
    token_type: payload.token_type,
    scope: payload.scope,
    iss: iss(params.auth0Domain),
  };
}

export async function refreshTokens(
  params: OAuthParams,
  refreshToken: string,
): Promise<TokenSet> {
  const auth0Domain = params.auth0Domain.replace(/^https?:\/\//, '').replace(/\/+$/, '');
  const res = await fetch(`https://${auth0Domain}/oauth/token`, {
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
  const payload = (await res.json()) as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    expires_in: number;
    token_type: 'Bearer';
    scope?: string;
  };
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

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      default:  return '&#39;';
    }
  });
}
