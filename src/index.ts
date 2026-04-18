#!/usr/bin/env node
/**
 * know — the know.sh CLI.
 *
 * Commands:
 *   login      Sign in via your browser (PKCE, no password typed here).
 *   install    Add the know.sh MCP server to Claude Code's config.
 *   logout     Forget your tokens.
 *   mcp-proxy  Internal: stdio ↔ HTTP proxy spawned by Claude Code.
 */
import { loginCommand } from './commands/login.js';
import { logoutCommand } from './commands/logout.js';
import { installCommand } from './commands/install.js';
import { mcpProxyCommand } from './commands/mcp-proxy.js';

const USAGE = `know.sh CLI

Usage:
  npx @know.sh/cli login        # sign in via your browser
  npx @know.sh/cli install      # add the MCP server to Claude Code
  npx @know.sh/cli logout       # clear tokens

Internal (called by Claude Code — don't run by hand):
  npx @know.sh/cli mcp-proxy
`;

async function main(): Promise<number> {
  const cmd = process.argv[2];
  switch (cmd) {
    case 'login':     return loginCommand();
    case 'install':   return installCommand();
    case 'logout':    return logoutCommand();
    case 'mcp-proxy': return mcpProxyCommand();
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(USAGE);
      return 0;
    default:
      process.stderr.write(`unknown command: ${cmd}\n${USAGE}`);
      return 2;
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  },
);
