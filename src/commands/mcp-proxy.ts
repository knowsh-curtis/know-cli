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
import { InvalidGrantError, login, refreshTokens } from '../oauth.js';
import { clearTokens, loadTokens, saveTokens, type TokenSet } from '../tokens.js';
import { createInterface } from 'node:readline';

export interface LiveState {
  tokens: TokenSet;
  /** Rotation is one-time-use, so two concurrent refreshes would revoke the family. */
  acquiring?: Promise<string>;
}

export interface SessionDeps {
  config?: CliConfig;
  refresh?: typeof refreshTokens;
  signIn?: typeof login;
  save?: typeof saveTokens;
  clear?: typeof clearTokens;
}

function isUsable(tokens: TokenSet, config: CliConfig): boolean {
  if (tokens.iss !== undefined && tokens.iss !== issuerFor(config)) return false;
  return tokens.expires_at - Math.floor(Date.now() / 1000) > 60;
}

async function acquireTokens(state: LiveState, deps: SessionDeps): Promise<string> {
  const config = deps.config ?? resolveConfig();
  const save = deps.save ?? saveTokens;
  const handle = state.tokens.refresh_token;
  if (!handle) {
    throw new Error('stored access token is unusable and there is no refresh token — run `know login`');
  }

  try {
    const renewed = await (deps.refresh ?? refreshTokens)(config, handle);
    state.tokens = renewed;
    await save(renewed);
    return renewed.access_token;
  } catch (err) {
    if (!(err instanceof InvalidGrantError)) throw err;
    await (deps.clear ?? clearTokens)();
  }

  const fresh = await (deps.signIn ?? login)(config);
  state.tokens = fresh;
  await save(fresh);
  return fresh.access_token;
}

export async function ensureFreshTokens(
  state: LiveState,
  deps: SessionDeps = {},
): Promise<string> {
  const config = deps.config ?? resolveConfig();
  if (isUsable(state.tokens, config)) {
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
