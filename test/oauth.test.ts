import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, afterEach, before, beforeEach, describe, it } from 'node:test';
import { DEFAULTS, REQUEST_TIMEOUT_MS, type LoopbackConfig } from '../src/config.js';
import {
  InvalidGrantError,
  buildAuthorizeUrl,
  exchangeCode,
  loginWithLoopback,
  refreshTokens,
} from '../src/oauth.js';
import { codeChallenge, generateCodeVerifier } from '../src/pkce.js';
import { REGISTERED_REDIRECT_URI, loadRegistration, registrationPath } from '../src/registration.js';
import {
  STATIC_CLIENT_ID,
  startBlackHoleHost,
  startFakeIdentityHost,
  type BlackHoleHost,
  type FakeIdentityHost,
} from './fake-identity-host.js';

/** Plays the browser: signs straight in and follows the host back to the loopback callback. */
async function answerTheBrowser(url: string, opened?: string[]): Promise<void> {
  opened?.push(url);
  const authorize = new URL(url);
  const callback = new URL(authorize.searchParams.get('redirect_uri') ?? '');
  callback.search = new URLSearchParams({
    code: 'code-1',
    state: authorize.searchParams.get('state') ?? '',
  }).toString();
  await fetch(callback, { headers: { connection: 'close' } });
}

describe('authorize request', () => {
  const config: LoopbackConfig = {
    mode: 'loopback',
    issuer: 'https://id.dev.know.sh',
    clientName: DEFAULTS.clientName,
    resource: DEFAULTS.resource,
    scopes: DEFAULTS.scopes,
    mcpUrl: DEFAULTS.mcpUrl,
    requestTimeoutMs: REQUEST_TIMEOUT_MS,
  };
  const verifier = generateCodeVerifier();
  const url = new URL(
    buildAuthorizeUrl(config, {
      clientId: 'client-7',
      redirectUri: 'http://127.0.0.1:51234/oauth/callback',
      state: 'state-value',
      nonce: 'nonce-value',
      codeChallenge: codeChallenge(verifier),
    }),
  );

  it('targets the host authorize endpoint', () => {
    assert.equal(url.origin + url.pathname, 'https://id.dev.know.sh/connect/authorize');
  });

  it('is an authorization code request with PKCE S256, state and nonce', () => {
    assert.equal(url.searchParams.get('response_type'), 'code');
    assert.equal(url.searchParams.get('client_id'), 'client-7');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('code_challenge'), codeChallenge(verifier));
    assert.equal(url.searchParams.get('state'), 'state-value');
    assert.equal(url.searchParams.get('nonce'), 'nonce-value');
    assert.equal(url.searchParams.get('redirect_uri'), 'http://127.0.0.1:51234/oauth/callback');
  });

  it('names exactly one resource, the MCP endpoint', () => {
    assert.deepEqual(url.searchParams.getAll('resource'), ['https://mcp.dev.know.sh/mcp']);
  });

  it('asks for the identity scopes plus the eight mcp: scopes and never email', () => {
    const scopes = (url.searchParams.get('scope') ?? '').split(' ');
    assert.ok(!scopes.includes('email'));
    assert.deepEqual(scopes, [
      'openid',
      'profile',
      'offline_access',
      'mcp:documents:read',
      'mcp:documents:write',
      'mcp:sections:read',
      'mcp:sections:write',
      'mcp:campaigns:read',
      'mcp:campaigns:write',
      'mcp:operations:read',
      'mcp:operations:write',
    ]);
  });
});

describe('token requests', () => {
  let host: FakeIdentityHost;

  before(async () => {
    host = await startFakeIdentityHost();
  });

  after(async () => {
    await host.close();
  });

  it('exchanges the code with the resource and the verifier', async () => {
    const config = host.config();
    const tokens = await exchangeCode(config, {
      clientId: STATIC_CLIENT_ID,
      code: 'code-1',
      codeVerifier: 'verifier-1',
      redirectUri: 'http://127.0.0.1:51234/oauth/callback',
    });

    assert.equal(tokens.access_token, 'access-1');
    assert.equal(tokens.refresh_token, 'refresh-1');
    assert.equal(tokens.iss, config.issuer);
    assert.equal(tokens.client_id, STATIC_CLIENT_ID);
    assert.ok(tokens.expires_at > Math.floor(Date.now() / 1000));

    const [request] = host.tokenRequests('authorization_code');
    assert.equal(request?.form.get('resource'), 'https://mcp.dev.know.sh/mcp');
    assert.equal(request?.form.get('code_verifier'), 'verifier-1');
    assert.equal(request?.form.get('client_id'), STATIC_CLIENT_ID);
    assert.equal(request?.form.get('redirect_uri'), 'http://127.0.0.1:51234/oauth/callback');
  });

  it('refreshes as the client the handle was issued to, with the same resource and no scope', async () => {
    host.clients.add('client-issued');
    const config = host.config();
    const tokens = await refreshTokens(config, 'refresh-1', 'client-issued');

    assert.match(tokens.refresh_token ?? '', /^refresh-1-r/);
    assert.equal(tokens.client_id, 'client-issued');

    const [request] = host.tokenRequests('refresh_token');
    assert.equal(request?.form.get('resource'), 'https://mcp.dev.know.sh/mcp');
    assert.equal(request?.form.get('scope'), null);
    assert.equal(request?.form.get('client_id'), 'client-issued');
  });

  it('reports a rotated-away handle as invalid_grant', async () => {
    await assert.rejects(refreshTokens(host.config(), 'refresh-1'), InvalidGrantError);
  });

  it('reports a set that names no client, with none configured, as invalid_grant without asking the host', async () => {
    const before = host.requests.length;
    await assert.rejects(
      refreshTokens(host.config({ clientId: undefined }), 'refresh-unknown-client'),
      InvalidGrantError,
    );
    assert.equal(host.requests.length, before);
  });
});

describe('a host that accepts the connection and never answers', () => {
  let blackHole: BlackHoleHost;

  before(async () => {
    blackHole = await startBlackHoleHost();
  });

  after(async () => {
    await blackHole.close();
  });

  // `fetch` waits 300 s on its own. A refresh runs while the token-file lock is
  // held, so an unbounded one outlives its lock and gets its handle replayed.
  it('gives the token request a deadline of its own', async () => {
    const config: LoopbackConfig = {
      mode: 'loopback',
      issuer: blackHole.issuer,
      clientId: STATIC_CLIENT_ID,
      clientName: DEFAULTS.clientName,
      resource: DEFAULTS.resource,
      scopes: DEFAULTS.scopes,
      mcpUrl: DEFAULTS.mcpUrl,
      requestTimeoutMs: 200,
    };

    const started = Date.now();
    await assert.rejects(refreshTokens(config, 'never-answered'), /refresh timed out after 200 ms/);
    assert.ok(Date.now() - started < 5_000, 'the request outlived its deadline');
  });
});

describe('loopback login', () => {
  let host: FakeIdentityHost;

  before(async () => {
    host = await startFakeIdentityHost();
  });

  after(async () => {
    await host.close();
  });

  it('completes the browser round trip and exchanges the code', async () => {
    const opened: string[] = [];
    const tokens = await loginWithLoopback(host.config(), {
      log: () => {},
      timeoutMs: 5_000,
      openBrowser: (url) => answerTheBrowser(url, opened),
    });

    assert.equal(tokens.access_token, 'access-1');
    assert.equal(tokens.refresh_token, 'refresh-1');

    const authorizeUrl = new URL(opened[0] ?? '');
    const redirectUri = new URL(authorizeUrl.searchParams.get('redirect_uri') ?? '');
    assert.equal(redirectUri.hostname, '127.0.0.1');
    assert.ok(Number(redirectUri.port) > 0);
    assert.equal(redirectUri.pathname, '/oauth/callback');

    const [exchange] = host.tokenRequests('authorization_code');
    assert.equal(exchange?.form.get('redirect_uri'), redirectUri.toString());
  });

  it('refuses a callback whose state does not match', async () => {
    await assert.rejects(
      loginWithLoopback(host.config(), {
        log: () => {},
        timeoutMs: 5_000,
        openBrowser: async (url) => {
          const callback = new URL(new URL(url).searchParams.get('redirect_uri') ?? '');
          callback.search = new URLSearchParams({ code: 'code-1', state: 'forged' }).toString();
          await fetch(callback, { headers: { connection: 'close' } });
        },
      }),
      /state did not match/,
    );
  });
});

describe('dynamic client registration', () => {
  let host: FakeIdentityHost;
  let configHome: string;
  const previousHome = process.env.XDG_CONFIG_HOME;
  const quiet = { log: () => {}, timeoutMs: 5_000 };

  beforeEach(async () => {
    host = await startFakeIdentityHost();
    host.authorizationCodes.set('code-1', `refresh-${Math.random().toString(36).slice(2)}`);
    configHome = await mkdtemp(path.join(os.tmpdir(), 'know-cli-registration-'));
    process.env.XDG_CONFIG_HOME = configHome;
  });

  afterEach(async () => {
    if (previousHome === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousHome;
    await host.close();
    await rm(configHome, { recursive: true, force: true });
  });

  const dynamic = () => host.config({ clientId: undefined });

  it('registers a public loopback client once and signs in as it', async () => {
    const tokens = await loginWithLoopback(dynamic(), { ...quiet, openBrowser: (url) => answerTheBrowser(url) });

    const [registration] = host.registrations();
    assert.deepEqual(registration?.json, {
      client_name: 'know.sh CLI',
      redirect_uris: [REGISTERED_REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      application_type: 'native',
      scope: DEFAULTS.scopes,
    });
    assert.equal(tokens.client_id, 'client-1');
    assert.equal(host.tokenRequests('authorization_code')[0]?.form.get('client_id'), 'client-1');
    assert.equal((await loadRegistration())?.client_id, 'client-1');
    assert.equal((await stat(registrationPath())).mode & 0o777, 0o600);
  });

  it('reuses the stored registration on the next sign-in', async () => {
    await loginWithLoopback(dynamic(), { ...quiet, openBrowser: (url) => answerTheBrowser(url) });
    host.authorizationCodes.set('code-1', 'refresh-second');
    const tokens = await loginWithLoopback(dynamic(), { ...quiet, openBrowser: (url) => answerTheBrowser(url) });

    assert.equal(host.registrations().length, 1);
    assert.equal(tokens.client_id, 'client-1');
  });

  it('registers again when the host no longer knows the stored client', async () => {
    await loginWithLoopback(dynamic(), { ...quiet, openBrowser: (url) => answerTheBrowser(url) });
    host.clients.delete('client-1');
    host.authorizationCodes.set('code-1', 'refresh-after-revocation');

    const opened: string[] = [];
    const tokens = await loginWithLoopback(dynamic(), { ...quiet, openBrowser: (url) => answerTheBrowser(url, opened) });

    assert.equal(host.registrations().length, 2);
    assert.equal(tokens.client_id, 'client-2');
    assert.equal(opened.length, 1);
    assert.equal(new URL(opened[0] ?? '').searchParams.get('client_id'), 'client-2');
    assert.equal((await loadRegistration())?.client_id, 'client-2');
  });

  it('registers again when the configured scopes outgrow the stored registration', async () => {
    await loginWithLoopback(host.config({ clientId: undefined, scopes: 'openid mcp:documents:read' }), {
      ...quiet,
      openBrowser: (url) => answerTheBrowser(url),
    });
    host.authorizationCodes.set('code-1', 'refresh-wider');
    const tokens = await loginWithLoopback(dynamic(), { ...quiet, openBrowser: (url) => answerTheBrowser(url) });

    assert.equal(host.registrations().length, 2);
    assert.equal(tokens.client_id, 'client-2');
  });

  it('never opens a browser on a request the host refuses', async () => {
    host.refuseAuthorization = true;
    let opened = false;
    await assert.rejects(
      loginWithLoopback(dynamic(), {
        ...quiet,
        openBrowser: async () => {
          opened = true;
        },
      }),
      /identity host refused the sign-in request: see .*\/account\/error/,
    );
    assert.equal(opened, false);
    assert.equal(host.registrations().length, 1);
  });

  it('uses a configured client without registering', async () => {
    const tokens = await loginWithLoopback(host.config(), { ...quiet, openBrowser: (url) => answerTheBrowser(url) });
    assert.equal(host.registrations().length, 0);
    assert.equal(tokens.client_id, STATIC_CLIENT_ID);
    assert.equal(await loadRegistration(), null);
  });
});
