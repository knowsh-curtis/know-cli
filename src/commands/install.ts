/**
 * Write a Claude Code MCP entry that spawns our stdio proxy.
 *
 * Claude Code reads MCP server configuration from one of:
 *   - ~/.claude.json                 (project-wide merged config)
 *   - ~/.claude/settings.json        (user settings)
 *   - project-level .mcp.json
 *
 * We target ~/.claude.json since that's where `claude mcp add` writes today.
 * If a different file exists already, we fall back to creating it.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { loadTokens } from '../tokens.js';

function claudeConfigPath(): string {
  return path.join(os.homedir(), '.claude.json');
}

export async function installCommand(): Promise<number> {
  const tokens = await loadTokens();
  if (!tokens) {
    console.error('Not signed in. Run `npx @know.sh/cli login` first.');
    return 2;
  }

  const configPath = claudeConfigPath();
  let config: Record<string, unknown> = {};
  try {
    config = JSON.parse(await fs.readFile(configPath, 'utf8'));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }

  const mcpServers = (config.mcpServers as Record<string, unknown> | undefined) ?? {};

  // Our entry uses the stdio proxy — maximum compatibility with MCP clients.
  // The proxy reads ~/.config/know.sh/tokens.json and refreshes transparently.
  mcpServers['know-sh'] = {
    command: 'npx',
    args: ['-y', '@know.sh/cli', 'mcp-proxy'],
    env: {},
  };

  config.mcpServers = mcpServers;
  await fs.writeFile(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });

  console.log(`✓ Added MCP server "know-sh" to ${configPath}.`);
  console.log('  Restart Claude Code to pick it up.');
  return 0;
}
