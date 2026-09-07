import { resolveConfig } from '../config.js';
import { revokeToken } from '../revoke.js';
import { clearTokens, loadTokens, tokensPath } from '../tokens.js';

export async function logoutCommand(): Promise<number> {
  const config = resolveConfig();
  const stored = await loadTokens();
  const handle = stored?.refresh_token;

  if (config.mode === 'loopback' && handle) {
    try {
      await revokeToken(config, handle);
      console.log('Revoked the refresh token.');
    } catch (err) {
      // A server-side failure must not strand the tokens on disk.
      console.error(`warning: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  await clearTokens();
  console.log(`Cleared ${tokensPath()}.`);
  return 0;
}
