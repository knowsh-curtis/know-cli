import { resolveConfig } from '../config.js';
import { loginWithPkce } from '../oauth.js';
import { saveTokens, tokensPath } from '../tokens.js';

export async function loginCommand(): Promise<number> {
  const config = resolveConfig();
  const tokens = await loginWithPkce(config);
  await saveTokens(tokens);
  console.log(`\n✓ Signed in. Tokens saved to ${tokensPath()}.`);
  console.log('  Next:  npx @know.sh/cli install');
  return 0;
}
