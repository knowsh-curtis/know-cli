/**
 * Stdio ↔ Streamable-HTTP MCP proxy.
 *
 * Claude Code (and every MCP client that supports stdio) spawns this command.
 * We read JSON-RPC frames from stdin, POST each to the hosted MCP server with
 * the user's Bearer token, and stream responses back out on stdout.
 *
 * We also refresh the access token when it's near expiry so the user doesn't
 * see auth errors mid-session, and start a fresh sign-in when the host refuses
 * the stored handle.
 */
import { issuerFor, resolveConfig, type CliConfig } from '../config.js';
import { withFileLock } from '../lock.js';
import { InvalidGrantError, login, refreshTokens } from '../oauth.js';
import { clearTokens, loadTokens, saveTokens, tokensLockPath, type TokenSet } from '../tokens.js';
import { createInterface } from 'node:readline';

/** Renew this far ahead of expiry so a token cannot die in flight. */
const FRESHNESS_FLOOR_SEC = 60;

export interface LiveState {
  tokens: TokenSet;
  /** The in-process half of the single flight; the lock file is the other half. */
  acquiring?: Promise<string>;
}

export interface SessionDeps {
  config?: CliConfig;
  refresh?: typeof refreshTokens;
  signIn?: typeof login;
  load?: typeof loadTokens;
  save?: typeof saveTokens;
  clear?: typeof clearTokens;
  /** Serialises acquisition against the other proxies sharing `tokens.json`. */
  lock?: <T>(run: () => Promise<T>) => Promise<T>;
}

const lockTokenFile = <T>(run: () => Promise<T>): Promise<T> => withFileLock(tokensLockPath(), run);

/** A set that names no issuer has unknown provenance, so it is nobody's to present either. */
function mintedByConfiguredIssuer(tokens: TokenSet, config: CliConfig): boolean {
  return tokens.iss === issuerFor(config);
}

function isFresh(tokens: TokenSet): boolean {
  return tokens.expires_at - Math.floor(Date.now() / 1000) > FRESHNESS_FLOOR_SEC;
}

async function signInAgain(state: LiveState, config: CliConfig, deps: SessionDeps): Promise<string> {
  const fresh = await (deps.signIn ?? login)(config);
  state.tokens = fresh;
  await (deps.lock ?? lockTokenFile)(() => (deps.save ?? saveTokens)(fresh));
  return fresh.access_token;
}

/** `know logout` and a sibling proxy both sign out by deleting the token file. */
const SIGNED_OUT = 'the stored token set was cleared — run `know login`';

/**
 * Renew the handle while holding the token-file lock. Returns null when only an
 * interactive sign-in can recover, which runs outside the lock because it waits
 * on a human for up to five minutes.
 */
async function refreshUnderLock(
  state: LiveState,
  config: CliConfig,
  deps: SessionDeps,
): Promise<string | null> {
  const load = deps.load ?? loadTokens;
  const refresh = deps.refresh ?? refreshTokens;
  const persist = async (renewed: TokenSet): Promise<string> => {
    state.tokens = renewed;
    await (deps.save ?? saveTokens)(renewed);
    return renewed.access_token;
  };

  // The file, not this process's memory, says whether anyone is signed in: a
  // logout deletes it, and so does a sibling the host refused. Renewing what is
  // left in memory would undo a sign-out the user asked for, and starting a
  // browser would ask every running proxy to sign in again for them.
  const onDisk = await load();
  if (!onDisk) throw new Error(SIGNED_OUT);
  if (mintedByConfiguredIssuer(onDisk, config)) {
    state.tokens = onDisk;
    if (isFresh(onDisk)) return onDisk.access_token;
  } else if (!mintedByConfiguredIssuer(state.tokens, config)) {
    await (deps.clear ?? clearTokens)();
    return null;
  }

  const handle = state.tokens.refresh_token;
  if (!handle) {
    throw new Error('stored access token is unusable and there is no refresh token — run `know login`');
  }

  try {
    return await persist(await refresh(config, handle));
  } catch (err) {
    if (!(err instanceof InvalidGrantError)) throw err;
  }

  // The handle is spent. If the file has moved on to a different one, a sibling
  // rotated it while this process held the old copy: adopt that handle rather
  // than deleting a credential which still works.
  const rotated = await load();
  if (!rotated) throw new Error(SIGNED_OUT);
  if (
    rotated.refresh_token &&
    rotated.refresh_token !== handle &&
    mintedByConfiguredIssuer(rotated, config)
  ) {
    state.tokens = rotated;
    if (isFresh(rotated)) return rotated.access_token;
    try {
      return await persist(await refresh(config, rotated.refresh_token));
    } catch (err) {
      if (!(err instanceof InvalidGrantError)) throw err;
    }
  }

  await (deps.clear ?? clearTokens)();
  return null;
}

async function acquireTokens(state: LiveState, deps: SessionDeps): Promise<string> {
  const config = deps.config ?? resolveConfig();
  const renewed = await (deps.lock ?? lockTokenFile)(() => refreshUnderLock(state, config, deps));
  return renewed ?? signInAgain(state, config, deps);
}

export async function ensureFreshTokens(
  state: LiveState,
  deps: SessionDeps = {},
): Promise<string> {
  const config = deps.config ?? resolveConfig();
  if (mintedByConfiguredIssuer(state.tokens, config) && isFresh(state.tokens)) {
    return state.tokens.access_token;
  }
  state.acquiring ??= acquireTokens(state, { ...deps, config }).finally(() => {
    state.acquiring = undefined;
  });
  return state.acquiring;
}

/** Send one JSON-RPC frame to the MCP server; stream the response (or error) out. */
async function forwardFrame(
  mcpUrl: string,
  getToken: () => Promise<string>,
  frame: string,
  sessionHeader: { value: string | null },
): Promise<void> {
  const token = await getToken();
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'accept': 'application/json, text/event-stream',
    'authorization': `Bearer ${token}`,
  };
  if (sessionHeader.value) headers['mcp-session-id'] = sessionHeader.value;

  const res = await fetch(mcpUrl, { method: 'POST', headers, body: frame });

  const newSession = res.headers.get('mcp-session-id');
  if (newSession) sessionHeader.value = newSession;

  if (res.status === 202) {
    // No body — notification ack.
    return;
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    writeFrame(JSON.stringify({
      jsonrpc: '2.0',
      id: safeId(frame),
      error: {
        code: -32603,
        message: `MCP server returned ${res.status}`,
        data: text.slice(0, 500),
      },
    }));
    return;
  }

  const contentType = res.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    const body = await res.text();
    writeFrame(body);
    return;
  }

  if (contentType.includes('text/event-stream') && res.body) {
    // Parse SSE; emit `data: ...` JSON frames to stdout as they arrive.
    const reader = (res.body as any).getReader?.() ?? null;
    if (!reader) return;
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buffer.indexOf('\n\n')) !== -1) {
        const event = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        const dataLines = event
          .split('\n')
          .filter((l) => l.startsWith('data:'))
          .map((l) => l.slice(5).trimStart());
        if (dataLines.length === 0) continue;
        const data = dataLines.join('\n');
        if (data.trim().length > 0) writeFrame(data);
      }
    }
    return;
  }

  // Unknown content type: pass through raw.
  writeFrame(await res.text());
}

function writeFrame(frame: string): void {
  process.stdout.write(frame.trimEnd() + '\n');
}

function safeId(frame: string): string | number | null {
  try {
    const obj = JSON.parse(frame) as { id?: string | number | null };
    return obj.id ?? null;
  } catch {
    return null;
  }
}

export async function mcpProxyCommand(): Promise<number> {
  const stored = await loadTokens();
  if (!stored) {
    writeFrame(JSON.stringify({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32001,
        message: 'know.sh CLI is not logged in. Run: npx @know.sh/cli login',
      },
    }));
    return 2;
  }
  const state: LiveState = { tokens: stored };
  const config = resolveConfig();
  const sessionHeader = { value: null as string | null };

  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const frame = line.trim();
    if (!frame) continue;
    try {
      await forwardFrame(config.mcpUrl, () => ensureFreshTokens(state, { config }), frame, sessionHeader);
    } catch (err) {
      writeFrame(JSON.stringify({
        jsonrpc: '2.0',
        id: safeId(frame),
        error: {
          code: -32603,
          message: err instanceof Error ? err.message : String(err),
        },
      }));
    }
  }
  return 0;
}
