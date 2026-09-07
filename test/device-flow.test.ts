import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { resolveConfig } from '../src/config.js';
import { login, refreshTokens } from '../src/oauth.js';

interface Call {
  url: string;
  form: URLSearchParams;
}

const realFetch = globalThis.fetch;

function stubFetch(responder: (call: Call) => unknown): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (
    input: Parameters<typeof realFetch>[0],
    init?: Parameters<typeof realFetch>[1],
  ) => {
    const call = { url: String(input), form: new URLSearchParams(String(init?.body ?? '')) };
    calls.push(call);
    return new Response(JSON.stringify(responder(call)), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof globalThis.fetch;
  return calls;
}

describe('legacy device flow', () => {
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it('still runs against Auth0 behind KNOWSH_LEGACY_DEVICE_FLOW', async () => {
    const config = resolveConfig({
      KNOWSH_LEGACY_DEVICE_FLOW: '1',
      KNOWSH_AUTH0_DOMAIN: 'tenant.us.auth0.com',
      KNOWSH_AUTH0_CLIENT_ID: 'legacy-client',
      KNOWSH_AUDIENCE: 'https://mcp.know.sh',
    });
    assert.equal(config.mode, 'device');

    const calls = stubFetch((call) =>
      call.url.endsWith('/oauth/device/code')
        ? {
            device_code: 'device-1',
            user_code: 'ABCD-EFGH',
            verification_uri: 'https://tenant.us.auth0.com/activate',
            verification_uri_complete: 'https://tenant.us.auth0.com/activate?user_code=ABCD-EFGH',
            expires_in: 60,
            interval: 1,
          }
        : {
            access_token: 'legacy-access',
            refresh_token: 'legacy-refresh',
            expires_in: 86_400,
            token_type: 'Bearer',
            scope: config.scopes,
          },
    );

    const opened: string[] = [];
    const tokens = await login(config, {
      log: () => {},
      openBrowser: async (url) => {
        opened.push(url);
      },
    });

    assert.equal(tokens.access_token, 'legacy-access');
    assert.equal(tokens.refresh_token, 'legacy-refresh');
    assert.equal(tokens.iss, 'https://tenant.us.auth0.com/');
    assert.deepEqual(opened, ['https://tenant.us.auth0.com/activate?user_code=ABCD-EFGH']);

    assert.equal(calls[0]?.url, 'https://tenant.us.auth0.com/oauth/device/code');
    assert.equal(calls[0]?.form.get('audience'), 'https://mcp.know.sh');
    assert.equal(calls[1]?.url, 'https://tenant.us.auth0.com/oauth/token');
    assert.equal(
      calls[1]?.form.get('grant_type'),
      'urn:ietf:params:oauth:grant-type:device_code',
    );
    assert.equal(calls[1]?.form.get('device_code'), 'device-1');
    assert.equal(calls[1]?.form.get('resource'), null);
  });

  it('refreshes against Auth0 with an audience-scoped request', async () => {
    const config = resolveConfig({
      KNOWSH_LEGACY_DEVICE_FLOW: '1',
      KNOWSH_AUTH0_DOMAIN: 'tenant.us.auth0.com',
      KNOWSH_AUTH0_CLIENT_ID: 'legacy-client',
    });
    const calls = stubFetch(() => ({
      access_token: 'legacy-access-2',
      expires_in: 86_400,
      token_type: 'Bearer',
    }));

    const tokens = await refreshTokens(config, 'legacy-refresh');

    assert.equal(tokens.access_token, 'legacy-access-2');
    assert.equal(tokens.refresh_token, 'legacy-refresh');
    assert.equal(calls[0]?.url, 'https://tenant.us.auth0.com/oauth/token');
    assert.equal(calls[0]?.form.get('grant_type'), 'refresh_token');
    assert.equal(calls[0]?.form.get('scope'), config.scopes);
    assert.equal(calls[0]?.form.get('resource'), null);
  });
});
