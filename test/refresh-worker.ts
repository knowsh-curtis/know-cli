/**
 * One proxy's token acquisition, run as its own process so the cross-process
 * lock over `tokens.json` is exercised for real rather than simulated. The
 * outcome goes to WORKER_RESULT_FILE; stdout stays empty, as it does in the
 * proxy, where it is the JSON-RPC channel.
 */
import { writeFile } from 'node:fs/promises';
import { ensureFreshTokens, type LiveState } from '../src/commands/mcp-proxy.js';
import { resolveConfig } from '../src/config.js';
import { loadTokens } from '../src/tokens.js';

async function acquire(): Promise<string> {
  const stored = await loadTokens();
  if (!stored) throw new Error('the worker found no stored tokens');

  const startAt = Number(process.env.WORKER_START_AT ?? '0');
  const wait = startAt - Date.now();
  if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));

  const state: LiveState = { tokens: stored };
  return ensureFreshTokens(state, {
    config: resolveConfig(),
    signIn: async () => {
      throw new Error('an interactive sign-in would have opened a browser');
    },
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
