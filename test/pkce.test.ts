import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';
import { codeChallenge, generateCodeVerifier, randomNonce, randomState } from '../src/pkce.js';

const UNRESERVED = /^[A-Za-z0-9\-._~]+$/;

describe('pkce', () => {
  it('generates a verifier of legal length from the unreserved character set', () => {
    const verifier = generateCodeVerifier();
    assert.ok(verifier.length >= 43 && verifier.length <= 128, `length ${verifier.length}`);
    assert.match(verifier, UNRESERVED);
  });

  it('derives the S256 challenge', () => {
    const verifier = generateCodeVerifier();
    const expected = crypto.createHash('sha256').update(verifier).digest('base64url');
    assert.equal(codeChallenge(verifier), expected);
    assert.match(codeChallenge(verifier), UNRESERVED);
  });

  it('never repeats a verifier, state or nonce', () => {
    const values = [
      generateCodeVerifier(),
      generateCodeVerifier(),
      randomState(),
      randomState(),
      randomNonce(),
      randomNonce(),
    ];
    assert.equal(new Set(values).size, values.length);
  });
});
