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
  which drops the whole token family, then deletes the token file. Proxies that
  are still running report that they are signed out on their next call; they do
  not open a browser to sign you back in.

## Token audience

Every token request names one RFC 8707 resource, the MCP endpoint
`https://mcp.dev.know.sh/mcp` exactly as its protected-resource metadata
names it, so the access token carries exactly that audience. Refreshes name
the same resource and no scope. The requested scope is `openid profile
offline_access` plus the eight MCP scopes, which the identity host names
under `mcp:` (`mcp:research:read`, …); the host issues no `email` claim and
grants no `email` scope.

## Client registration

The identity host has no pre-registered client for the CLI. On the first
`login` the CLI registers itself through RFC 7591 dynamic client
registration — a public native client (no secret) whose only redirect is
`http://127.0.0.1/oauth/callback`, which the host matches at any port — and
keeps the result in `~/.config/know.sh/client.json` (mode 0600). Later
sign-ins reuse it. Before opening the browser the CLI asks the host once,
without following redirects, whether it would serve the request; if the host
no longer knows a stored registration it registers again, once, and if it
refuses a fresh one the CLI stops with the reason instead of waiting on a
browser that shows an error page. Each token set records the `client_id` it
was issued to, and refresh and revocation present that one.

## Security model

- The CLI's `client_id` is a PUBLIC identifier for a native app (PKCE, no
  secret), registered per machine; `client.json` holds no secret.
- Refresh tokens are one-time-use: every renewal rotates the handle, and
  replaying a spent one revokes the whole family. Each MCP client runs its own
  `mcp-proxy` over the same token file, so renewal is serialised by a lock file
  (`tokens.json.lock`) and the file is re-read inside the lock: a proxy that
  loses the race picks up the rotated handle instead of replaying a spent one.
  The lock is kept alive while it is held, and every request to the identity
  host has a deadline, so a slow host cannot make a live holder look abandoned
  and get its handle spent twice.
- A refused refresh (`invalid_grant`) clears the stored token set and starts a
  fresh sign-in rather than looping on a dead handle — unless the token file
  has meanwhile moved on to a different handle, which means another proxy
  rotated it, and that one is adopted instead.
- The token file, not a running proxy's memory, decides whether anyone is
  signed in. A file that has been deleted ends the session: the proxy reports
  it and stops rather than renewing a handle the user revoked or opening a
  browser nobody asked for.
- Tokens minted by a different issuer (an Auth0 set left over from the device
  flow, say) are never presented to the configured host, neither for refresh
  nor for revocation, and neither is a set that names no issuer at all. They
  are cleared locally and a fresh sign-in starts.
- The proxy never writes tokens to stdout or stderr, and sign-in prompts go to
  stderr so they cannot corrupt the JSON-RPC channel.
- `~/.config/know.sh/tokens.json` is created with 0600 permissions.

## Overrides (uncommon)

Environment variables:

- `KNOWSH_ISSUER` — default `https://id.dev.know.sh`.
- `KNOWSH_CLIENT_ID` — a pre-registered client to use instead of the dynamic
  registration; unset by default.
- `KNOWSH_RESOURCE` — default `https://mcp.dev.know.sh/mcp`.
- `KNOWSH_SCOPES` — default `openid profile offline_access mcp:research:read mcp:research:write mcp:findings:read mcp:findings:write mcp:campaigns:read mcp:campaigns:write mcp:operations:read mcp:operations:write`.
- `KNOWSH_MCP_URL` — default `https://mcp.dev.know.sh/mcp`.
- `KNOWSH_HTTP_TIMEOUT_MS` — deadline for one request to the identity host,
  default `15000`.

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
