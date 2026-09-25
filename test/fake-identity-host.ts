import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { DEFAULTS, REQUEST_TIMEOUT_MS, type LoopbackConfig } from '../src/config.js';

/** Registered on every fake host, as a pre-registered client would be. */
export const STATIC_CLIENT_ID = 'know-cli-test';

export interface RecordedRequest {
  path: string;
  form: URLSearchParams;
  /** The body of a JSON request, such as a client registration. */
  json?: Record<string, unknown>;
}

export interface FakeIdentityHost {
  issuer: string;
  requests: RecordedRequest[];
  /** Refresh handles the host still honours. */
  handles: Set<string>;
  authorizationCodes: Map<string, string>;
  /** Client ids the host knows; deleting one is how a registration is revoked. */
  clients: Set<string>;
  /** When set, every authorization request lands on the host's error page. */
  refuseAuthorization: boolean;
  /** True once a handle from this family was replayed or revoked. */
  familyRevoked(handle: string): boolean;
  config(overrides?: Partial<LoopbackConfig>): LoopbackConfig;
  tokenRequests(grantType: string): RecordedRequest[];
  registrations(): RecordedRequest[];
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

export interface BlackHoleHost {
  issuer: string;
  close(): Promise<void>;
}

/** Accepts the connection and never answers, so a request's own deadline is all there is. */
export async function startBlackHoleHost(): Promise<BlackHoleHost> {
  const server = http.createServer(() => {});
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  return {
    issuer: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

export async function startFakeIdentityHost(): Promise<FakeIdentityHost> {
  const requests: RecordedRequest[] = [];
  const handles = new Set<string>();
  const authorizationCodes = new Map<string, string>();
  authorizationCodes.set('code-1', 'refresh-1');
  const clients = new Set<string>([STATIC_CLIENT_ID]);
  let minted = 0;
  let registered = 0;

  // ReplaySafeRefreshTokenService: one-time use, and replaying a spent handle
  // revokes every handle in its family (DESIGN §6.3).
  const familyOf = new Map<string, string>();
  const revokedFamilies = new Set<string>();

  const familyFor = (handle: string): string => {
    const known = familyOf.get(handle);
    if (known) return known;
    familyOf.set(handle, handle);
    return handle;
  };

  const revokeFamily = (family: string): void => {
    revokedFamilies.add(family);
    for (const handle of [...handles]) {
      if (familyOf.get(handle) === family) handles.delete(handle);
    }
  };

  const server = http.createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const path = url.pathname;
      const body = await readBody(req);
      const isJson = (req.headers['content-type'] ?? '').startsWith('application/json');
      const form = isJson ? new URLSearchParams() : new URLSearchParams(body);
      requests.push({ path, form, ...(isJson ? { json: JSON.parse(body) as Record<string, unknown> } : {}) });

      if (path === '/connect/authorize') {
        // Like IdentityServer: an unknown client never reaches the redirect,
        // only the host's own error page; a known one is sent to sign in.
        const known = clients.has(url.searchParams.get('client_id') ?? '');
        const target = !host.refuseAuthorization && known ? '/account/login?ReturnUrl=x' : '/account/error?errorId=x';
        res.writeHead(302, { location: target, 'content-length': 0 });
        res.end();
        return;
      }

      if (path === '/connect/register') {
        const clientId = `client-${(registered += 1)}`;
        clients.add(clientId);
        json(res, 201, { client_id: clientId, token_endpoint_auth_method: 'none' });
        return;
      }

      if (path === '/connect/token' && !clients.has(form.get('client_id') ?? '')) {
        json(res, 400, { error: 'invalid_client' });
        return;
      }

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
            const replayed = familyOf.get(presented);
            if (replayed !== undefined) revokeFamily(replayed);
            json(res, 400, {
              error: 'invalid_grant',
              error_description: replayed !== undefined
                ? 'refresh token was already used; the family is revoked'
                : 'refresh token is not active',
            });
            return;
          }
          const family = familyFor(presented);
          handles.delete(presented);
          const rotated = `${presented}-r${(minted += 1)}`;
          familyOf.set(rotated, family);
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
        // FamilyRevokingTokenRevocationResponseGenerator: revoking one handle
        // revokes its whole family, which is what makes logout a sign-out.
        const token = form.get('token') ?? '';
        handles.delete(token);
        const family = familyOf.get(token);
        if (family !== undefined) revokeFamily(family);
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

  const host: FakeIdentityHost = {
    issuer,
    requests,
    handles,
    authorizationCodes,
    clients,
    refuseAuthorization: false,
    familyRevoked: (handle: string) => {
      const family = familyOf.get(handle);
      return family !== undefined && revokedFamilies.has(family);
    },
    config: (overrides = {}) => ({
      mode: 'loopback',
      issuer,
      clientId: STATIC_CLIENT_ID,
      clientName: DEFAULTS.clientName,
      resource: DEFAULTS.resource,
      scopes: DEFAULTS.scopes,
      mcpUrl: DEFAULTS.mcpUrl,
      requestTimeoutMs: REQUEST_TIMEOUT_MS,
      ...overrides,
    }),
    tokenRequests: (grantType: string) =>
      requests.filter((r) => r.path === '/connect/token' && r.form.get('grant_type') === grantType),
    registrations: () => requests.filter((r) => r.path === '/connect/register'),
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
  return host;
}
