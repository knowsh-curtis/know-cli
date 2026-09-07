import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { logoutCommand } from '../src/commands/logout.js';
import { InvalidGrantError, refreshTokens } from '../src/oauth.js';
import { revokeToken } from '../src/revoke.js';
import { loadTokens, saveTokens } from '../src/tokens.js';
import { startFakeIdentityHost, type FakeIdentityHost } from './fake-identity-host.js';

describe('revocation', () => {
  let host: FakeIdentityHost;
  let configHome: string;
  const previousEnv = { ...process.env };
  const quiet = { log: console.log, error: console.error };

  before(async () => {
    host = await startFakeIdentityHost();
    configHome = await mkdtemp(path.join(os.tmpdir(), 'know-cli-test-'));
    process.env.XDG_CONFIG_HOME = configHome;
    process.env.KNOWSH_ISSUER = host.issuer;
    delete process.env.KNOWSH_LEGACY_DEVICE_FLOW;
    console.log = () => {};
    console.error = () => {};
  });

  after(async () => {
    console.log = quiet.log;
    console.error = quiet.error;
    process.env = previousEnv;
    await host.close();
    await rm(configHome, { recursive: true, force: true });
  });

  it('posts the handle to /connect/revocation and the handle is refused afterwards', async () => {
    const config = host.config();
    host.handles.add('refresh-9');

    await revokeToken(config, 'refresh-9');

    const revocation = host.requests.find((r) => r.path === '/connect/revocation');
    assert.equal(revocation?.form.get('token'), 'refresh-9');
    assert.equal(revocation?.form.get('token_type_hint'), 'refresh_token');
    assert.equal(revocation?.form.get('client_id'), 'know-cli-development');

    await assert.rejects(refreshTokens(config, 'refresh-9'), InvalidGrantError);
  });

  it('logout revokes the stored handle and clears the token file', async () => {
    host.handles.add('refresh-8');
    await saveTokens({
      access_token: 'access-8',
      refresh_token: 'refresh-8',
      expires_at: Math.floor(Date.now() / 1000) + 900,
      token_type: 'Bearer',
      iss: host.issuer,
    });

    assert.equal(await logoutCommand(), 0);

    const revocations = host.requests.filter((r) => r.path === '/connect/revocation');
    assert.ok(revocations.some((r) => r.form.get('token') === 'refresh-8'));
    assert.equal(host.handles.has('refresh-8'), false);
    assert.equal(await loadTokens(), null);
    await assert.rejects(refreshTokens(host.config(), 'refresh-8'), InvalidGrantError);
  });

  it('still clears the token file when revocation fails', async () => {
    process.env.KNOWSH_ISSUER = 'http://127.0.0.1:1';
    try {
      await saveTokens({
        access_token: 'access-7',
        refresh_token: 'refresh-7',
        expires_at: Math.floor(Date.now() / 1000) + 900,
        token_type: 'Bearer',
      });
      assert.equal(await logoutCommand(), 0);
      assert.equal(await loadTokens(), null);
    } finally {
      process.env.KNOWSH_ISSUER = host.issuer;
    }
  });
});
