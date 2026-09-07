import { issuerFor, resolveConfig } from '../config.js';
import { revokeToken } from '../revoke.js';
import { clearTokens, loadTokens, tokensPath } from '../tokens.js';

export async function logoutCommand(): Promise<number> {
  const config = resolveConfig();
  const stored = await loadTokens();
  const issuer = issuerFor(config);

  if (stored && stored.iss !== issuer) {
    // Only the issuer that minted a handle can revoke it, and presenting it
    // anywhere else hands that issuer's credential to a host it does not belong to.
    console.error(
      `warning: the stored tokens were issued by ${stored.iss ?? 'an unnamed issuer'}, not ${issuer}; ` +
        'clearing them locally without revoking.',
    );
  } else if (config.mode === 'loopback' && stored?.refresh_token) {
    try {
      await revokeToken(config, stored.refresh_token);
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
