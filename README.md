# @know.sh/cli

Sign in to [know.sh](https://know.sh) from your terminal and install the
know.sh MCP server into Claude Code (and any other MCP client that supports
stdio servers).

## Install

One command:

```sh
npx @know.sh/cli login        # opens your browser
npx @know.sh/cli install      # adds the MCP server to Claude Code
```

Restart Claude Code. Your research docs and findings are now available as
MCP tools: `research.list`, `research.get`, `research.create`,
`research.update_overview`, `finding.add`, `finding.update`, `finding.delete`,
`search`, …

## Install as a Claude Code plugin

This repository is also a Claude Code plugin marketplace. The plugin connects
Claude Code straight to the know.sh MCP server over Streamable HTTP; Claude
Code registers itself and signs you in with OAuth the first time you use it,
so no token or credential is stored in the plugin.

```sh
claude plugin marketplace add knowsh-curtis/know-cli
claude plugin install know-dev@know-sh
```

Start a new session and run `/mcp` to sign in. The plugin and its server are
named `know-dev` because they address the know.sh dev environment
(`https://mcp.dev.know.sh/mcp`).

## Use in claude.ai / ChatGPT

The same server works as a remote connector. Both clients sign in with OAuth;
there is nothing to paste but the URL.

- claude.ai: Settings → Connectors → Add custom connector, URL
  `https://mcp.dev.know.sh/mcp`.
- ChatGPT: Settings → Connectors → Advanced → Developer mode, then Create,
  URL `https://mcp.dev.know.sh/mcp`, authentication OAuth.

The server is named `know-dev` because it addresses the dev environment.

## What it does

- `login`: opens your browser and runs OAuth 2.1 Authorization Code + PKCE
  against know.sh's Auth0 tenant. Tokens land in
  `~/.config/know.sh/tokens.json` (mode 0600).
- `install`: writes an entry to `~/.claude.json`'s `mcpServers` pointing at
  `npx @know.sh/cli mcp-proxy`.
- `mcp-proxy`: stdio ↔ Streamable-HTTP bridge. Reads JSON-RPC frames from
  stdin, posts them to `https://mcp.know.sh/mcp` with the current access
  token, streams responses back. Refreshes the token transparently when it's
  near expiry.
- `logout`: deletes the token file.

## Security model

- The CLI's Auth0 client_id is a PUBLIC identifier for a Native app
  (PKCE, no secret). Safe to distribute in the bundle.
- Refresh tokens are rotated by Auth0 on every use; reuse of a previously-
  issued refresh token triggers breach detection and revokes the whole
  family.
- The proxy never writes tokens to stdout or stderr.
- `~/.config/know.sh/tokens.json` is created with 0600 permissions.

## Overrides (uncommon)

Environment variables:

- `KNOWSH_AUTH0_DOMAIN` — default `dev-hcpmhp1w4f2455pb.us.auth0.com`.
- `KNOWSH_AUTH0_CLIENT_ID` — default `rEsn27jbd8IAD7k1JkRsES3pEKFwyjJd`.
- `KNOWSH_AUDIENCE` — default `https://mcp.know.sh`.
- `KNOWSH_SCOPES` — default `openid profile email offline_access research:read research:write findings:read findings:write`.
- `KNOWSH_MCP_URL` — default `https://mcp.know.sh/mcp`.

## License

MIT.
