/**
 * The CLI's OAuth client, registered with the identity host through RFC 7591
 * dynamic client registration. The host has no pre-registered client for the
 * CLI. A registration is public (no secret) and loopback-only, and the host
 * matches a loopback redirect at any port (RFC 8252 §7.3), so one registration
 * serves every sign-in. It is kept beside the token file and reused until the
 * host refuses it.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { identityEndpoints, issuerFor, type LoopbackConfig } from './config.js';
import { isTimeout, postJson, timedOut } from './http.js';
import { CALLBACK_PATH } from './loopback.js';
import { configDir } from './tokens.js';

export interface ClientRegistration {
  issuer: string;
  client_id: string;
  /** The scopes the registration was granted; the host fixes them at registration. */
  scope: string;
  redirect_uris: string[];
}

export interface ResolvedClient {
  clientId: string;
  /** True when the id came from the registration store, so a refusal may mean it went stale. */
  stored: boolean;
}

/** Portless, so the host accepts the ephemeral port the loopback receiver binds. */
export const REGISTERED_REDIRECT_URI = `http://127.0.0.1${CALLBACK_PATH}`;

export const registrationPath = (): string => path.join(configDir(), 'client.json');

export async function loadRegistration(): Promise<ClientRegistration | null> {
  try {
    return JSON.parse(await fs.readFile(registrationPath(), 'utf8')) as ClientRegistration;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

async function saveRegistration(registration: ClientRegistration): Promise<void> {
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  await fs.writeFile(registrationPath(), JSON.stringify(registration, null, 2), { mode: 0o600 });
}

export async function clearRegistration(): Promise<void> {
  try {
    await fs.unlink(registrationPath());
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}

const fits = (registration: ClientRegistration, config: LoopbackConfig): boolean =>
  registration.issuer === issuerFor(config) && registration.scope === config.scopes;

export async function registerClient(config: LoopbackConfig): Promise<ClientRegistration> {
  let res: Response;
  try {
    res = await postJson(
      identityEndpoints(config.issuer).registration,
      {
        client_name: config.clientName,
        redirect_uris: [REGISTERED_REDIRECT_URI],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        application_type: 'native',
        scope: config.scopes,
      },
      config.requestTimeoutMs,
    );
  } catch (err) {
    if (!isTimeout(err)) throw err;
    throw timedOut('client registration', config.requestTimeoutMs);
  }
  const text = await res.text().catch(() => '');
  if (!res.ok) {
    let detail = text;
    try {
      const failure = JSON.parse(text) as { error?: string; error_description?: string };
      detail = `${failure.error ?? res.status} ${failure.error_description ?? ''}`;
    } catch {
      detail = `${res.status} ${text}`;
    }
    throw new Error(`client registration failed: ${detail.trim()}`);
  }
  const { client_id } = JSON.parse(text) as { client_id?: string };
  if (!client_id) throw new Error('client registration failed: the host returned no client_id');

  const registration: ClientRegistration = {
    issuer: issuerFor(config),
    client_id,
    scope: config.scopes,
    redirect_uris: [REGISTERED_REDIRECT_URI],
  };
  await saveRegistration(registration);
  return registration;
}

/** The configured client, else the stored registration that fits, else a new registration. */
export async function resolveClient(config: LoopbackConfig): Promise<ResolvedClient> {
  if (config.clientId) return { clientId: config.clientId, stored: false };
  const stored = await loadRegistration();
  if (stored && fits(stored, config)) return { clientId: stored.client_id, stored: true };
  return { clientId: (await registerClient(config)).client_id, stored: false };
}
