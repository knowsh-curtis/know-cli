import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { DEFAULTS, REQUEST_TIMEOUT_MS, type LoopbackConfig } from '../src/config.js';
import {
  InvalidGrantError,
  buildAuthorizeUrl,
  exchangeCode,
  loginWithLoopback,
  refreshTokens,
} from '../src/oauth.js';
import { codeChallenge, generateCodeVerifier } from '../src/pkce.js';
import {
  startBlackHoleHost,
  startFakeIdentityHost,
  type BlackHoleHost,
  type FakeIdentityHost,
} from './fake-identity-host.js';

describe('authorize request', () => {
  const config: LoopbackConfig = {
    mode: 'loopback',
    issuer: 'https://id.dev.know.sh',
    clientId: DEFAULTS.clientId,
    resource: DEFAULTS.resource,
    scopes: DEFAULTS.scopes,
    mcpUrl: DEFAULTS.mcpUrl,
    requestTimeoutMs: REQUEST_TIMEOUT_MS,
  };
  const verifier = generateCodeVerifier();
  const url = new URL(
    buildAuthorizeUrl(config, {
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
    assert.equal(url.searchParams.get('client_id'), 'know-cli-development');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('code_challenge'), codeChallenge(verifier));
    assert.equal(url.searchParams.get('state'), 'state-value');
    assert.equal(url.searchParams.get('nonce'), 'nonce-value');
    assert.equal(url.searchParams.get('redirect_uri'), 'http://127.0.0.1:51234/oauth/callback');
  });

  it('names exactly one resource, the MCP identifier with its trailing slash', () => {
    assert.deepEqual(url.searchParams.getAll('resource'), ['https://mcp.dev.know.sh/']);
  });

  it('asks for the identity scopes plus the eight MCP scopes and never email', () => {
    const scopes = (url.searchParams.get('scope') ?? '').split(' ');
    assert.ok(!scopes.includes('email'));
    assert.deepEqual(scopes, [
      'openid',
      'profile',
      'offline_access',
      'research:read',
      'research:write',
      'findings:read',
      'findings:write',
      'campaigns:read',
      'campaigns:write',
      'operations:read',
      'operations:write',
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
      code: 'code-1',
      codeVerifier: 'verifier-1',
      redirectUri: 'http://127.0.0.1:51234/oauth/callback',
    });

    assert.equal(tokens.access_token, 'access-1');
    assert.equal(tokens.refresh_token, 'refresh-1');
    assert.equal(tokens.iss, config.issuer);
    assert.ok(tokens.expires_at > Math.floor(Date.now() / 1000));

    const [request] = host.tokenRequests('authorization_code');
    assert.equal(request?.form.get('resource'), 'https://mcp.dev.know.sh/');
    assert.equal(request?.form.get('code_verifier'), 'verifier-1');
    assert.equal(request?.form.get('client_id'), 'know-cli-development');
    assert.equal(request?.form.get('redirect_uri'), 'http://127.0.0.1:51234/oauth/callback');
  });

  it('refreshes with the same resource and no scope', async () => {
    const config = host.config();
    const tokens = await refreshTokens(config, 'refresh-1');

    assert.match(tokens.refresh_token ?? '', /^refresh-1-r/);

    const [request] = host.tokenRequests('refresh_token');
    assert.equal(request?.form.get('resource'), 'https://mcp.dev.know.sh/');
    assert.equal(request?.form.get('scope'), null);
    assert.equal(request?.form.get('client_id'), 'know-cli-development');
  });

  it('reports a rotated-away handle as invalid_grant', async () => {
    await assert.rejects(refreshTokens(host.config(), 'refresh-1'), InvalidGrantError);
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
      clientId: DEFAULTS.clientId,
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
      openBrowser: async (url) => {
        opened.push(url);
        const authorize = new URL(url);
        const callback = new URL(authorize.searchParams.get('redirect_uri') ?? '');
        callback.search = new URLSearchParams({
          code: 'code-1',
          state: authorize.searchParams.get('state') ?? '',
        }).toString();
        await fetch(callback, { headers: { connection: 'close' } });
      },
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
