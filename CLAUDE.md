# know-cli — working notes

TypeScript CLI client. Cross-workspace conventions in
`~/know/CLAUDE.md` are mostly .NET-specific; the relevant ones for here:

- **No section-divider comments** (`// =====`, `// -----`, 3-line
  divider/heading/divider blocks). Folder + file structure carries the
  organization.
- **Don't add explanatory comments** that restate the code. Only write
  a comment when the *why* is non-obvious.
- **Concise style** — prefer `Array.prototype` methods, optional
  chaining, nullish coalescing over verbose imperative loops and
  null checks.

## API consumption

Tokens come from the know.sh identity host: authorization code with PKCE
over a `127.0.0.1` loopback redirect, `know-cli-development`, and one RFC
8707 `resource` (`https://mcp.dev.know.sh/`, trailing slash included) on
every token request, which is what gives the access token its single
audience. Refreshes name the same resource and no scope; the handle is
one-time-use and a replay revokes the whole family, so token acquisition is
single-flight both inside a process and between processes — every MCP client
spawns its own `mcp-proxy` over one `tokens.json`, so the file lock in
`src/lock.ts` is the half that matters. That lock heartbeats while it is held
and every identity-host request carries a deadline (`src/http.ts`), because a
holder that outlives its own staleness window is evicted and replays the handle
it is in the middle of spending.

A stored handle belongs to the issuer that minted it. When `tokens.iss` is not
the configured issuer — including when the set names no issuer — it is cleared
and a sign-in starts; it is never presented for refresh or revocation.

The token file is what says a user is signed in. `know logout` and a sibling
proxy whose handle was refused both sign out by deleting it, so a proxy that
finds it gone reports that and stops instead of opening a browser.

The Auth0 device-code flow survives behind `KNOWSH_LEGACY_DEVICE_FLOW`
until that tenant retires — the identity host serves no device
authorization endpoint.
