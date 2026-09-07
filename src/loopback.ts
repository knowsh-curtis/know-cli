/**
 * One-shot loopback redirect receiver for the authorization code flow.
 *
 * `know-cli-development` registers `http://127.0.0.1/oauth/callback` and the
 * host matches it at any ephemeral port, so the CLI binds 127.0.0.1:0 and reads
 * the assigned port back. Exactly one callback is served, then the listener is
 * gone: a second authorization response has nothing to talk to.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';

export const CALLBACK_PATH = '/oauth/callback';
export const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

export interface LoopbackReceiver {
  redirectUri: string;
  port: number;
  /** Resolves with the authorization code carried by the one served callback. */
  code: Promise<string>;
  close(): Promise<void>;
}

export interface LoopbackOptions {
  state: string;
  timeoutMs?: number;
}

const PAGE_STYLE =
  'font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;' +
  'color:#111;background:#fff;margin:0;padding:64px;max-width:34rem';

function page(heading: string, detail: string): string {
  return `<!doctype html><meta charset="utf-8"><title>know.sh</title><body style="${PAGE_STYLE}"><h1 style="font-size:1.1rem;font-weight:600;margin:0 0 .5rem">${heading}</h1><p style="margin:0;color:#555">${detail}</p></body>`;
}

const SUCCESS_PAGE = page('Signed in to know.sh', 'You can close this tab and return to your terminal.');

function respond(res: http.ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    connection: 'close',
    'cache-control': 'no-store',
  });
  res.end(body);
}

export async function startLoopbackReceiver(options: LoopbackOptions): Promise<LoopbackReceiver> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let settle: ((code: string) => void) | undefined;
  let fail: ((err: Error) => void) | undefined;
  const code = new Promise<string>((resolve, reject) => {
    settle = resolve;
    fail = reject;
  });
  // A callback can arrive before the caller awaits, so keep an early rejection
  // from being reported as an unhandled one; the caller still sees it.
  code.catch(() => {});

  let done = false;
  let timer: NodeJS.Timeout | undefined;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (url.pathname !== CALLBACK_PATH) {
      respond(res, 404, page('Not found', 'This local listener only serves the sign-in callback.'));
      return;
    }
    if (done) {
      respond(res, 410, page('Already used', 'This sign-in callback was already served.'));
      return;
    }
    done = true;

    const error = url.searchParams.get('error');
    const returnedState = url.searchParams.get('state');
    const authorizationCode = url.searchParams.get('code');

    if (returnedState !== options.state) {
      respond(res, 400, page('Sign-in refused', 'The authorization response did not match this request.'));
      fail?.(new Error('authorization state did not match — callback refused'));
      return;
    }
    if (error) {
      const description = url.searchParams.get('error_description');
      respond(res, 400, page('Sign-in failed', 'Return to your terminal for the details.'));
      fail?.(new Error(`authorization failed: ${error}${description ? ` — ${description}` : ''}`));
      return;
    }
    if (!authorizationCode) {
      respond(res, 400, page('Sign-in failed', 'The authorization response carried no code.'));
      fail?.(new Error('authorization response carried no code'));
      return;
    }

    respond(res, 200, SUCCESS_PAGE);
    settle?.(authorizationCode);
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  server.on('error', (err) => {
    done = true;
    fail?.(err);
  });

  const address = server.address() as AddressInfo;

  const close = async (): Promise<void> => {
    if (timer) clearTimeout(timer);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };

  timer = setTimeout(() => {
    done = true;
    fail?.(new Error(`timed out after ${Math.round(timeoutMs / 1000)}s waiting for the browser callback`));
  }, timeoutMs);

  return {
    redirectUri: `http://127.0.0.1:${address.port}${CALLBACK_PATH}`,
    port: address.port,
    code,
    close,
  };
}
