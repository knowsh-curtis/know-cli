/**
 * Stdio ↔ Streamable-HTTP MCP proxy.
 *
 * Claude Code (and every MCP client that supports stdio) spawns this command.
 * We read JSON-RPC frames from stdin, POST each to the hosted MCP server with
 * the user's Bearer token, and stream responses back out on stdout.
 *
 * We also refresh the access token when it's near expiry so the user doesn't
 * see auth errors mid-session.
 */
import { resolveConfig } from '../config.js';
import { refreshTokens } from '../oauth.js';
import { loadTokens, saveTokens, type TokenSet } from '../tokens.js';
import { createInterface } from 'node:readline';

interface LiveState {
  tokens: TokenSet;
}

async function ensureFreshTokens(state: LiveState): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (state.tokens.expires_at - now > 60) {
    return state.tokens.access_token;
  }
  if (!state.tokens.refresh_token) {
    throw new Error('access token near expiry and no refresh token — run `know login`');
  }
  const config = resolveConfig();
  const fresh = await refreshTokens(config, state.tokens.refresh_token);
  state.tokens = fresh;
  await saveTokens(fresh);
  return fresh.access_token;
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
      await forwardFrame(config.mcpUrl, () => ensureFreshTokens(state), frame, sessionHeader);
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
