import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { ensureFreshTokens, type LiveState } from '../src/commands/mcp-proxy.js';
import { issuerFor, resolveConfig, type CliConfig } from '../src/config.js';
import { InvalidGrantError } from '../src/oauth.js';
import type { TokenSet } from '../src/tokens.js';

const config: CliConfig = resolveConfig({});

const nowSec = (): number => Math.floor(Date.now() / 1000);

function tokenSet(overrides: Partial<TokenSet> = {}): TokenSet {
  return {
    access_token: 'stored-access',
    refresh_token: 'stored-refresh',
    expires_at: nowSec() + 900,
    token_type: 'Bearer',
    iss: issuerFor(config),
    ...overrides,
  };
}

/** Near enough to expiry that the proxy must renew before using it. */
function stale(overrides: Partial<TokenSet> = {}): TokenSet {
  return tokenSet({ expires_at: nowSec() + 10, ...overrides });
}

const passthroughLock = <T>(run: () => Promise<T>): Promise<T> => run();

describe('mcp-proxy token acquisition', () => {
  // The lock file and the re-read both live beside tokens.json, so keep the
  // suite off the developer's real ~/.config/know.sh.
  let configHome: string;
  const previousConfigHome = process.env.XDG_CONFIG_HOME;

  before(async () => {
    configHome = await mkdtemp(path.join(os.tmpdir(), 'know-cli-session-'));
    process.env.XDG_CONFIG_HOME = configHome;
  });

  after(async () => {
    if (previousConfigHome === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousConfigHome;
    await rm(configHome, { recursive: true, force: true });
  });

  it('uses the stored access token while it is fresh', async () => {
    const state: LiveState = { tokens: tokenSet() };
    const token = await ensureFreshTokens(state, {
      config,
      refresh: async () => assert.fail('should not refresh'),
    });
    assert.equal(token, 'stored-access');
  });

  it('refreshes and persists when the access token is near expiry', async () => {
    const state: LiveState = { tokens: stale() };
    const saved: TokenSet[] = [];
    const token = await ensureFreshTokens(state, {
      config,
      load: async () => stale(),
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
    const state: LiveState = { tokens: stale() };
    const events: string[] = [];

    const token = await ensureFreshTokens(state, {
      config,
      lock: passthroughLock,
      load: async () => stale(),
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
    const state: LiveState = { tokens: stale() };
    await assert.rejects(
      ensureFreshTokens(state, {
        config,
        lock: passthroughLock,
        load: async () => stale(),
        refresh: async () => {
          throw new Error('network down');
        },
        signIn: async () => assert.fail('should not sign in'),
      }),
      /network down/,
    );
  });

  it('never presents a handle minted by another issuer', async () => {
    const state: LiveState = {
      tokens: tokenSet({ iss: 'https://dev-tenant.us.auth0.com/', refresh_token: 'auth0-handle' }),
    };
    const events: string[] = [];

    const token = await ensureFreshTokens(state, {
      config,
      lock: () => assert.fail('a foreign handle is never rotated, so nothing needs the lock'),
      load: async () => assert.fail('a foreign handle is never rotated'),
      refresh: async (_config, handle) => assert.fail(`presented ${handle} to the wrong issuer`),
      clear: async () => {
        events.push('clear');
      },
      signIn: async () => {
        events.push('login');
        return tokenSet({ access_token: 'host-issued', refresh_token: 'host-handle' });
      },
      save: async () => {
        events.push('save');
      },
    });

    assert.equal(token, 'host-issued');
    assert.deepEqual(events, ['clear', 'login', 'save']);
    assert.equal(state.tokens.refresh_token, 'host-handle');
  });

  it('refuses to guess when there is no refresh handle', async () => {
    const state: LiveState = { tokens: stale({ refresh_token: undefined }) };
    await assert.rejects(
      ensureFreshTokens(state, {
        config,
        lock: passthroughLock,
        load: async () => stale({ refresh_token: undefined }),
      }),
      /there is no refresh token/,
    );
  });

  it('refreshes once for concurrent callers, because rotation is one-time-use', async () => {
    const state: LiveState = { tokens: stale() };
    let refreshes = 0;
    const deps = {
      config,
      lock: passthroughLock,
      load: async () => stale(),
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

describe('mcp-proxy against a token file another process is using', () => {
  it('takes the token set a sibling already rotated instead of refreshing again', async () => {
    const state: LiveState = { tokens: stale({ refresh_token: 'spent' }) };
    const token = await ensureFreshTokens(state, {
      config,
      lock: passthroughLock,
      load: async () => tokenSet({ access_token: 'sibling-access', refresh_token: 'rotated' }),
      refresh: async () => assert.fail('the file already held a fresh token'),
    });

    assert.equal(token, 'sibling-access');
    assert.equal(state.tokens.refresh_token, 'rotated');
  });

  it('presents the rotated handle from the file, never the spent copy it held', async () => {
    const state: LiveState = { tokens: stale({ refresh_token: 'spent' }) };
    const presented: string[] = [];

    const token = await ensureFreshTokens(state, {
      config,
      lock: passthroughLock,
      load: async () => stale({ refresh_token: 'rotated' }),
      refresh: async (_config, handle) => {
        presented.push(handle);
        return tokenSet({ access_token: 'renewed', refresh_token: 'rotated-again' });
      },
      save: async () => {},
    });

    assert.deepEqual(presented, ['rotated']);
    assert.equal(token, 'renewed');
  });

  it('adopts a handle rotated under it rather than deleting the sibling token file', async () => {
    const state: LiveState = { tokens: stale({ refresh_token: 'spent' }) };
    const reads: (TokenSet | null)[] = [
      stale({ refresh_token: 'spent' }),
      stale({ refresh_token: 'rotated' }),
    ];
    const presented: string[] = [];

    const token = await ensureFreshTokens(state, {
      config,
      lock: passthroughLock,
      load: async () => reads.shift() ?? null,
      refresh: async (_config, handle) => {
        presented.push(handle);
        if (handle === 'spent') throw new InvalidGrantError('refresh failed: invalid_grant');
        return tokenSet({ access_token: 'renewed', refresh_token: 'rotated-again' });
      },
      clear: async () => assert.fail('a handle another process just rotated must survive'),
      signIn: async () => assert.fail('the adopted handle worked'),
      save: async () => {},
    });

    assert.deepEqual(presented, ['spent', 'rotated']);
    assert.equal(token, 'renewed');
    assert.equal(state.tokens.refresh_token, 'rotated-again');
  });

  it('clears the file when it still holds the handle that was refused', async () => {
    const state: LiveState = { tokens: stale({ refresh_token: 'dead' }) };
    const events: string[] = [];

    const token = await ensureFreshTokens(state, {
      config,
      lock: passthroughLock,
      load: async () => stale({ refresh_token: 'dead' }),
      refresh: async () => {
        throw new InvalidGrantError('refresh failed: invalid_grant');
      },
      clear: async () => {
        events.push('clear');
      },
      signIn: async () => tokenSet({ access_token: 'after-login', refresh_token: 'fresh-handle' }),
      save: async () => {},
    });

    assert.equal(token, 'after-login');
    assert.deepEqual(events, ['clear']);
  });

  it('refuses to start a browser when the token file was cleared under it', async () => {
    const state: LiveState = { tokens: stale() };

    await assert.rejects(
      ensureFreshTokens(state, {
        config,
        lock: passthroughLock,
        load: async () => null,
        refresh: async () => assert.fail('a handle nobody is storing must not be spent'),
        signIn: async () => assert.fail('`know logout` must not open a browser in every proxy'),
      }),
      /the stored token set was cleared — run `know login`/,
    );
  });

  it('picks up the token set the next `know login` writes', async () => {
    const state: LiveState = { tokens: stale() };
    const files: (TokenSet | null)[] = [null, tokenSet({ access_token: 'after-login' })];
    const deps = {
      config,
      lock: passthroughLock,
      load: async () => files.shift() ?? null,
      refresh: async () => assert.fail('the file already held a token that works'),
      signIn: async () => assert.fail('the user is the one who signs in'),
    };

    await assert.rejects(ensureFreshTokens(state, deps), /run `know login`/);
    assert.equal(await ensureFreshTokens(state, deps), 'after-login');
  });

  it('never presents a token set that names no issuer', async () => {
    const state: LiveState = { tokens: tokenSet({ iss: undefined, refresh_token: 'unknown' }) };
    const events: string[] = [];

    const token = await ensureFreshTokens(state, {
      config,
      lock: () => assert.fail('a set of unknown provenance is never rotated'),
      load: async () => assert.fail('a set of unknown provenance is never rotated'),
      refresh: async (_config, handle) => assert.fail(`presented ${handle} to an unproven host`),
      clear: async () => {
        events.push('clear');
      },
      signIn: async () => {
        events.push('login');
        return tokenSet({ access_token: 'host-issued', refresh_token: 'host-handle' });
      },
      save: async () => {
        events.push('save');
      },
    });

    assert.equal(token, 'host-issued');
    assert.deepEqual(events, ['clear', 'login', 'save']);
  });

  it('ignores a token file that belongs to another issuer', async () => {
    const state: LiveState = { tokens: stale({ refresh_token: 'ours' }) };
    const presented: string[] = [];

    await ensureFreshTokens(state, {
      config,
      lock: passthroughLock,
      load: async () => tokenSet({ iss: 'https://dev-tenant.us.auth0.com/', refresh_token: 'theirs' }),
      refresh: async (_config, handle) => {
        presented.push(handle);
        return tokenSet({ access_token: 'renewed', refresh_token: 'rotated' });
      },
      save: async () => {},
    });

    assert.deepEqual(presented, ['ours']);
  });
});
