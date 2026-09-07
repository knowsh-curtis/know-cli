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
one-time-use, so token acquisition is single-flight.

The Auth0 device-code flow survives behind `KNOWSH_LEGACY_DEVICE_FLOW`
until that tenant retires — the identity host serves no device
authorization endpoint.
