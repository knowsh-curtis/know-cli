/**
 * RFC 7636 — PKCE code_verifier + code_challenge helpers.
 * Uses Node's webcrypto + base64url. No third-party deps.
 */
import crypto from 'node:crypto';

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** Between 43 and 128 unreserved chars per the RFC. 96 bytes = 128 b64url chars. */
export function generateCodeVerifier(): string {
  return base64url(crypto.randomBytes(96));
}

export function codeChallenge(verifier: string): string {
  return base64url(crypto.createHash('sha256').update(verifier).digest());
}

export function randomState(): string {
  return base64url(crypto.randomBytes(24));
}
