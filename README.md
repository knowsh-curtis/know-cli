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

## What it does

- `login`: binds a listener on `127.0.0.1` at an ephemeral port, opens your
  browser and runs OAuth 2.1 Authorization Code + PKCE (S256) against the
  know.sh identity host. Exactly one callback is served, within five minutes,
  and a response whose `state` does not match the request is refused. Tokens
  land in `~/.config/know.sh/tokens.json` (mode 0600).
- `install`: writes an entry to `~/.claude.json`'s `mcpServers` pointing at
  `npx @know.sh/cli mcp-proxy`.
- `mcp-proxy`: stdio ↔ Streamable-HTTP bridge. Reads JSON-RPC frames from
  stdin, posts them to the MCP server with the current access token, streams
  responses back. Refreshes the token transparently when it's near expiry.
- `logout`: revokes the refresh token at the host's `/connect/revocation`,
  which drops the whole token family, then deletes the token file.

## Token audience

Every token request names one RFC 8707 resource,
`https://mcp.dev.know.sh/` — the trailing slash is part of the identifier —
so the access token carries exactly that audience. Refreshes name the same
resource and no scope. The requested scope is `openid profile offline_access`
plus the eight MCP scopes; the host issues no `email` claim and grants no
`email` scope.

## Security model

- The CLI's `client_id` is a PUBLIC identifier for a Native app (PKCE, no
  secret). Safe to distribute in the bundle.
- Refresh tokens are one-time-use: every renewal rotates the handle, and
  replaying a spent one revokes the whole family. Each MCP client runs its own
  `mcp-proxy` over the same token file, so renewal is serialised by a lock file
  (`tokens.json.lock`) and the file is re-read inside the lock: a proxy that
  loses the race picks up the rotated handle instead of replaying a spent one.
- A refused refresh (`invalid_grant`) clears the stored token set and starts a
  fresh sign-in rather than looping on a dead handle — unless the token file
  has meanwhile moved on to a different handle, which means another proxy
  rotated it, and that one is adopted instead.
- Tokens minted by a different issuer (an Auth0 set left over from the device
  flow, say) are never presented to the configured host, neither for refresh
  nor for revocation. They are cleared locally and a fresh sign-in starts.
- The proxy never writes tokens to stdout or stderr, and sign-in prompts go to
  stderr so they cannot corrupt the JSON-RPC channel.
- `~/.config/know.sh/tokens.json` is created with 0600 permissions.

## Overrides (uncommon)

Environment variables:

- `KNOWSH_ISSUER` — default `https://id.dev.know.sh`.
- `KNOWSH_CLIENT_ID` — default `know-cli-development`.
- `KNOWSH_RESOURCE` — default `https://mcp.dev.know.sh/`.
- `KNOWSH_SCOPES` — default `openid profile offline_access research:read research:write findings:read findings:write campaigns:read campaigns:write operations:read operations:write`.
- `KNOWSH_MCP_URL` — default `https://mcp.dev.know.sh/mcp`.

Legacy: setting `KNOWSH_LEGACY_DEVICE_FLOW=1` runs the previous OAuth 2.0
Device Authorization Flow against Auth0 instead, with
`KNOWSH_AUTH0_DOMAIN`, `KNOWSH_AUTH0_CLIENT_ID` and `KNOWSH_AUDIENCE` as its
overrides. It exists only until the Auth0 tenant retires; the identity host
serves no device authorization endpoint.

## Development

```sh
npm install
npm test        # typechecks the tests, then runs the node:test suite
npm run build
```

## License

MIT.
