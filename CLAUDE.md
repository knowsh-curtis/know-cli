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

Auth + token handling mirrors what the SPA does. Tokens come from
Auth0 (`@auth0/*` SDK or device-code flow). The CLI is one of the
audiences `know-api` accepts via `Auth0:AdditionalAudiences` — coordinate
with `know-api` config when adding new audiences.
