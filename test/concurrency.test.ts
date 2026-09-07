import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { InvalidGrantError, refreshTokens } from '../src/oauth.js';
import { loadTokens, saveTokens, type TokenSet } from '../src/tokens.js';
import { startFakeIdentityHost, type FakeIdentityHost } from './fake-identity-host.js';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));

interface WorkerOutcome {
  stdout: string;
  stderr: string;
  result: { ok: boolean; access?: string; error?: string };
}

describe('two proxies over one token file', () => {
  let host: FakeIdentityHost;
  let configHome: string;
  const previousEnv = { ...process.env };

  before(async () => {
    host = await startFakeIdentityHost();
    configHome = await mkdtemp(path.join(os.tmpdir(), 'know-cli-proxies-'));
    process.env.XDG_CONFIG_HOME = configHome;
    process.env.KNOWSH_ISSUER = host.issuer;
    delete process.env.KNOWSH_LEGACY_DEVICE_FLOW;
  });

  after(async () => {
    process.env = previousEnv;
    await host.close();
    await rm(configHome, { recursive: true, force: true });
  });

  async function runWorker(script: string, env: Record<string, string> = {}): Promise<WorkerOutcome> {
    const resultFile = path.join(configHome, `result-${script}-${Math.random().toString(36).slice(2)}.json`);
    const worker = fileURLToPath(new URL(`./${script}`, import.meta.url));

    const streams = await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
      const child = spawn(process.execPath, ['--import', 'tsx', worker], {
        cwd: repoRoot,
        env: { ...process.env, ...env, WORKER_RESULT_FILE: resultFile },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => (stdout += chunk));
      child.stderr.on('data', (chunk: string) => (stderr += chunk));
      child.once('error', reject);
      child.once('close', () => resolve({ stdout, stderr }));
    });

    const raw = await readFile(resultFile, 'utf8').catch(
      () => `{"ok":false,"error":"the worker wrote no result. stderr: ${streams.stderr.slice(0, 400)}"}`,
    );
    return { ...streams, result: JSON.parse(raw) };
  }

  function storedTokens(handle: string, secondsToExpiry: number): TokenSet {
    return {
      access_token: 'access-0',
      refresh_token: handle,
      expires_at: Math.floor(Date.now() / 1000) + secondsToExpiry,
      token_type: 'Bearer',
      iss: host.issuer,
    };
  }

  it('replaying a spent handle revokes the whole family, which is what the lock prevents', async () => {
    host.handles.add('family-root');
    const rotated = await refreshTokens(host.config(), 'family-root');

    await assert.rejects(refreshTokens(host.config(), 'family-root'), InvalidGrantError);
    assert.equal(host.familyRevoked('family-root'), true);
    await assert.rejects(refreshTokens(host.config(), rotated.refresh_token ?? ''), InvalidGrantError);
  });

  it('refreshes once and leaves both processes signed in', async () => {
    host.handles.add('shared-handle');
    await saveTokens(storedTokens('shared-handle', 10));
    const before = host.tokenRequests('refresh_token').length;

    const startAt = String(Date.now() + 800);
    const [first, second] = await Promise.all([
      runWorker('refresh-worker.ts', { WORKER_START_AT: startAt }),
      runWorker('refresh-worker.ts', { WORKER_START_AT: startAt }),
    ]);

    assert.ok(first.result.ok, first.result.error);
    assert.ok(second.result.ok, second.result.error);
    assert.equal(first.result.access, second.result.access);
    assert.equal(host.tokenRequests('refresh_token').length - before, 1);

    const stored = await loadTokens();
    assert.ok(stored, 'the token file survives the race');
    assert.equal(host.handles.has(stored.refresh_token ?? ''), true);
    assert.equal(host.familyRevoked('shared-handle'), false);
  });

  it('signs in again on a dead handle without writing to stdout', async () => {
    host.authorizationCodes.set('code-2', 'refresh-after-login');
    await saveTokens(storedTokens('dead-handle', 10));

    const worker = await runWorker('login-worker.ts', { WORKER_AUTHORIZATION_CODE: 'code-2' });

    assert.ok(worker.result.ok, worker.result.error);
    assert.equal(worker.stdout, '');
    assert.match(worker.stderr, /Opening your browser/);

    const stored = await loadTokens();
    assert.equal(stored?.refresh_token, 'refresh-after-login');
    assert.equal(stored?.access_token, worker.result.access);
  });
});
