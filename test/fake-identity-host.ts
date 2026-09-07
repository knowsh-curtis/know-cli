import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { DEFAULTS, type LoopbackConfig } from '../src/config.js';

export interface RecordedRequest {
  path: string;
  form: URLSearchParams;
}

export interface FakeIdentityHost {
  issuer: string;
  requests: RecordedRequest[];
  /** Refresh handles the host still honours. */
  handles: Set<string>;
  authorizationCodes: Map<string, string>;
  config(overrides?: Partial<LoopbackConfig>): LoopbackConfig;
  tokenRequests(grantType: string): RecordedRequest[];
  close(): Promise<void>;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => (body += chunk));
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function json(res: http.ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

export async function startFakeIdentityHost(): Promise<FakeIdentityHost> {
  const requests: RecordedRequest[] = [];
  const handles = new Set<string>();
  const authorizationCodes = new Map<string, string>();
  authorizationCodes.set('code-1', 'refresh-1');
  let minted = 0;

  const server = http.createServer((req, res) => {
    void (async () => {
      const path = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;
      const form = new URLSearchParams(await readBody(req));
      requests.push({ path, form });

      if (path === '/connect/token') {
        const grantType = form.get('grant_type');
        if (grantType === 'authorization_code') {
          const handle = authorizationCodes.get(form.get('code') ?? '');
          if (!handle || !form.get('code_verifier')) {
            json(res, 400, { error: 'invalid_grant', error_description: 'unknown code' });
            return;
          }
          handles.add(handle);
          json(res, 200, {
            access_token: `access-${(minted += 1)}`,
            refresh_token: handle,
            expires_in: 900,
            token_type: 'Bearer',
            scope: form.get('scope') ?? DEFAULTS.scopes,
          });
          return;
        }
        if (grantType === 'refresh_token') {
          const presented = form.get('refresh_token') ?? '';
          if (!handles.has(presented)) {
            json(res, 400, { error: 'invalid_grant', error_description: 'refresh token is not active' });
            return;
          }
          handles.delete(presented);
          const rotated = `${presented}-r${(minted += 1)}`;
          handles.add(rotated);
          json(res, 200, {
            access_token: `access-${minted}`,
            refresh_token: rotated,
            expires_in: 900,
            token_type: 'Bearer',
            scope: DEFAULTS.scopes,
          });
          return;
        }
        json(res, 400, { error: 'unsupported_grant_type' });
        return;
      }

      if (path === '/connect/revocation') {
        handles.delete(form.get('token') ?? '');
        res.writeHead(200, { 'content-length': 0 });
        res.end();
        return;
      }

      json(res, 404, { error: 'not_found' });
    })();
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    issuer,
    requests,
    handles,
    authorizationCodes,
    config: (overrides = {}) => ({
      mode: 'loopback',
      issuer,
      clientId: DEFAULTS.clientId,
      resource: DEFAULTS.resource,
      scopes: DEFAULTS.scopes,
      mcpUrl: DEFAULTS.mcpUrl,
      ...overrides,
    }),
    tokenRequests: (grantType: string) =>
      requests.filter((r) => r.path === '/connect/token' && r.form.get('grant_type') === grantType),
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
