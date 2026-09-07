import { resolveConfig, type CliConfig } from '../config.js';
import { withFileLock } from '../lock.js';
import { login } from '../oauth.js';
import { saveTokens, tokensLockPath, tokensPath } from '../tokens.js';

export interface LoginDeps {
  config?: CliConfig;
  signIn?: typeof login;
  save?: typeof saveTokens;
  lock?: <T>(run: () => Promise<T>) => Promise<T>;
}

export async function loginCommand(deps: LoginDeps = {}): Promise<number> {
  const config = deps.config ?? resolveConfig();
  const tokens = await (deps.signIn ?? login)(config);
  const lock = deps.lock ?? ((run) => withFileLock(tokensLockPath(), run));
  await lock(() => (deps.save ?? saveTokens)(tokens));
  console.log(`\n✓ Signed in. Tokens saved to ${tokensPath()}.`);
  console.log('  Next:  npx @know.sh/cli install');
  return 0;
}
