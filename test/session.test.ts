import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ensureFreshTokens, type LiveState } from '../src/commands/mcp-proxy.js';
import { issuerFor, resolveConfig, type CliConfig } from '../src/config.js';
import { InvalidGrantError } from '../src/oauth.js';
import type { TokenSet } from '../src/tokens.js';

const config: CliConfig = resolveConfig({});

function tokenSet(overrides: Partial<TokenSet> = {}): TokenSet {
  return {
    access_token: 'stored-access',
    refresh_token: 'stored-refresh',
    expires_at: Math.floor(Date.now() / 1000) + 900,
    token_type: 'Bearer',
    iss: issuerFor(config),
    ...overrides,
  };
}

describe('mcp-proxy token acquisition', () => {
  it('uses the stored access token while it is fresh', async () => {
    const state: LiveState = { tokens: tokenSet() };
    const token = await ensureFreshTokens(state, {
      config,
      refresh: async () => assert.fail('should not refresh'),
    });
    assert.equal(token, 'stored-access');
  });

  it('refreshes and persists when the access token is near expiry', async () => {
    const state: LiveState = { tokens: tokenSet({ expires_at: Math.floor(Date.now() / 1000) + 10 }) };
    const saved: TokenSet[] = [];
    const token = await ensureFreshTokens(state, {
      config,
      refresh: async () => tokenSet({ access_token: 'renewed', refresh_token: 'rotated' }),
      save: async (tokens) => {
        saved.push(tokens);
      },
    });

    assert.equal(token, 'renewed');
    assert.equal(state.tokens.refresh_token, 'rotated');
    assert.deepEqual(saved.map((t) => t.access_token), ['renewed']);
  });

  it('clears the stored token set and signs in again on invalid_grant', async () => {
    const state: LiveState = { tokens: tokenSet({ expires_at: Math.floor(Date.now() / 1000) + 10 }) };
    const events: string[] = [];

    const token = await ensureFreshTokens(state, {
      config,
      refresh: async () => {
        events.push('refresh');
        throw new InvalidGrantError('refresh failed: invalid_grant');
      },
      clear: async () => {
        events.push('clear');
      },
      signIn: async () => {
        events.push('login');
        return tokenSet({ access_token: 'after-login', refresh_token: 'fresh-handle' });
      },
      save: async () => {
        events.push('save');
      },
    });

    assert.equal(token, 'after-login');
    assert.deepEqual(events, ['refresh', 'clear', 'login', 'save']);
    assert.equal(state.tokens.refresh_token, 'fresh-handle');
  });

  it('does not swallow a failure that is not invalid_grant', async () => {
    const state: LiveState = { tokens: tokenSet({ expires_at: Math.floor(Date.now() / 1000) + 10 }) };
    await assert.rejects(
      ensureFreshTokens(state, {
        config,
        refresh: async () => {
          throw new Error('network down');
        },
        signIn: async () => assert.fail('should not sign in'),
      }),
      /network down/,
    );
  });

  it('treats a token set from another issuer as unusable', async () => {
    const state: LiveState = { tokens: tokenSet({ iss: 'https://dev-tenant.us.auth0.com/' }) };
    const token = await ensureFreshTokens(state, {
      config,
      refresh: async () => tokenSet({ access_token: 'host-issued' }),
      save: async () => {},
    });
    assert.equal(token, 'host-issued');
  });

  it('refuses to guess when there is no refresh handle', async () => {
    const state: LiveState = {
      tokens: tokenSet({ refresh_token: undefined, expires_at: Math.floor(Date.now() / 1000) + 10 }),
    };
    await assert.rejects(ensureFreshTokens(state, { config }), /run `know login`/);
  });

  it('refreshes once for concurrent callers, because rotation is one-time-use', async () => {
    const state: LiveState = { tokens: tokenSet({ expires_at: Math.floor(Date.now() / 1000) + 10 }) };
    let refreshes = 0;
    const deps = {
      config,
      refresh: async () => {
        refreshes += 1;
        await new Promise((resolve) => setTimeout(resolve, 10));
        return tokenSet({ access_token: 'renewed', refresh_token: 'rotated' });
      },
      save: async () => {},
    };

    const tokens = await Promise.all([
      ensureFreshTokens(state, deps),
      ensureFreshTokens(state, deps),
      ensureFreshTokens(state, deps),
    ]);

    assert.deepEqual(tokens, ['renewed', 'renewed', 'renewed']);
    assert.equal(refreshes, 1);
  });
});
