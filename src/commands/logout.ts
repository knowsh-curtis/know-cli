import { clearTokens, tokensPath } from '../tokens.js';

export async function logoutCommand(): Promise<number> {
  await clearTokens();
  console.log(`Cleared ${tokensPath()}.`);
  return 0;
}
