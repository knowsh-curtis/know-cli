/**
 * RFC 7009 token revocation against the identity host. Revoking the refresh
 * handle takes the whole token family with it, which is what makes `logout` a
 * server-side sign-out rather than a local file deletion.
 */
import { identityEndpoints, type LoopbackConfig } from './config.js';
import { isTimeout, postForm, timedOut } from './http.js';

export type TokenTypeHint = 'refresh_token' | 'access_token';

export async function revokeToken(
  config: LoopbackConfig,
  token: string,
  hint: TokenTypeHint = 'refresh_token',
): Promise<void> {
  let res: Response;
  try {
    res = await postForm(
      identityEndpoints(config.issuer).revocation,
      new URLSearchParams({ token, token_type_hint: hint, client_id: config.clientId }),
      config.requestTimeoutMs,
    );
  } catch (err) {
    if (!isTimeout(err)) throw err;
    throw timedOut('revocation', config.requestTimeoutMs);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`revocation failed: ${res.status} ${text}`.trim());
  }
}
