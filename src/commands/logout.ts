import { issuerFor, resolveConfig, type CliConfig } from '../config.js';
import { withFileLock } from '../lock.js';
import { revokeToken } from '../revoke.js';
import { clearTokens, loadTokens, tokensLockPath, tokensPath } from '../tokens.js';

export interface LogoutDeps {
  config?: CliConfig;
  load?: typeof loadTokens;
  clear?: typeof clearTokens;
  revoke?: typeof revokeToken;
  lock?: <T>(run: () => Promise<T>) => Promise<T>;
}

export async function logoutCommand(deps: LogoutDeps = {}): Promise<number> {
  const config = deps.config ?? resolveConfig();
  const lock = deps.lock ?? ((run) => withFileLock(tokensLockPath(), run));

  return lock(async () => {
    const stored = await (deps.load ?? loadTokens)();
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
        await (deps.revoke ?? revokeToken)(config, stored.refresh_token);
        console.log('Revoked the refresh token.');
      } catch (err) {
        // A server-side failure must not strand the tokens on disk.
        console.error(`warning: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    await (deps.clear ?? clearTokens)();
    console.log(`Cleared ${tokensPath()}.`);
    return 0;
  });
}
