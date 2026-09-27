/**
 * A proxy process holding a handle the host no longer honours: it refreshes, is
 * refused, and signs in again. The browser is answered in-process, and nothing
 * may reach stdout — the proxy's stdout carries JSON-RPC frames and nothing else.
 */
import { writeFile } from 'node:fs/promises';
import { ensureFreshTokens, type LiveState } from '../src/commands/mcp-proxy.js';
import { resolveConfig, type LoopbackConfig } from '../src/config.js';
import { loginWithLoopback } from '../src/oauth.js';
import { loadTokens } from '../src/tokens.js';

async function answerTheBrowser(url: string): Promise<void> {
  const authorize = new URL(url);
  const callback = new URL(authorize.searchParams.get('redirect_uri') ?? '');
  callback.search = new URLSearchParams({
    code: process.env.WORKER_AUTHORIZATION_CODE ?? 'code-1',
    state: authorize.searchParams.get('state') ?? '',
  }).toString();
  await fetch(callback, { headers: { connection: 'close' } });
}

async function acquire(): Promise<string> {
  const stored = await loadTokens();
  if (!stored) throw new Error('the worker found no stored tokens');

  const state: LiveState = { tokens: stored };
  return ensureFreshTokens(state, {
    config: resolveConfig(),
    signIn: (config) =>
      loginWithLoopback(config as LoopbackConfig, {
        openBrowser: answerTheBrowser,
        timeoutMs: 10_000,
      }),
  });
}

const resultFile = process.env.WORKER_RESULT_FILE ?? '';

await acquire().then(
  (access) => writeFile(resultFile, JSON.stringify({ ok: true, access })),
  async (err: unknown) => {
    await writeFile(
      resultFile,
      JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err) }),
    );
    process.exitCode = 1;
  },
);
