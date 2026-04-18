/**
 * Token persistence — flat JSON at ~/.config/know.sh/tokens.json with
 * file-mode 0600. No keychain integration yet; keep it platform-agnostic.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export interface TokenSet {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_at: number; // epoch seconds when the access_token stops working
  token_type: 'Bearer';
  scope?: string;
  /** Echo of the issuer so we can detect tenant changes. */
  iss?: string;
}

function tokensDir(): string {
  const xdg = process.env.XDG_CONFIG_HOME;
  const base = xdg && xdg.length > 0 ? xdg : path.join(os.homedir(), '.config');
  return path.join(base, 'know.sh');
}

export function tokensPath(): string {
  return path.join(tokensDir(), 'tokens.json');
}

export async function saveTokens(tokens: TokenSet): Promise<void> {
  const dir = tokensDir();
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const file = tokensPath();
  await fs.writeFile(file, JSON.stringify(tokens, null, 2), { mode: 0o600 });
}

export async function loadTokens(): Promise<TokenSet | null> {
  try {
    const raw = await fs.readFile(tokensPath(), 'utf8');
    return JSON.parse(raw) as TokenSet;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function clearTokens(): Promise<void> {
  try {
    await fs.unlink(tokensPath());
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}
