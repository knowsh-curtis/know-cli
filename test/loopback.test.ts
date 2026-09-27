import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CALLBACK_PATH, startLoopbackReceiver } from '../src/loopback.js';

async function callback(redirectUri: string, query: Record<string, string>): Promise<Response> {
  const url = new URL(redirectUri);
  url.search = new URLSearchParams(query).toString();
  return fetch(url, { headers: { connection: 'close' } });
}

describe('loopback receiver', () => {
  it('binds an ephemeral port on 127.0.0.1 and serves the registered callback path', async () => {
    const receiver = await startLoopbackReceiver({ state: 'st', timeoutMs: 2_000 });
    try {
      assert.ok(receiver.port > 0);
      assert.equal(receiver.redirectUri, `http://127.0.0.1:${receiver.port}${CALLBACK_PATH}`);
      assert.equal(new URL(receiver.redirectUri).hostname, '127.0.0.1');
    } finally {
      await receiver.close();
    }
  });

  it('resolves the code and answers a plain success page', async () => {
    const receiver = await startLoopbackReceiver({ state: 'st', timeoutMs: 2_000 });
    try {
      const res = await callback(receiver.redirectUri, { code: 'code-1', state: 'st' });
      assert.equal(res.status, 200);
      const body = await res.text();
      assert.match(body, /Signed in to know\.sh/);
      assert.equal(await receiver.code, 'code-1');
    } finally {
      await receiver.close();
    }
  });

  it('refuses a callback whose state does not match', async () => {
    const receiver = await startLoopbackReceiver({ state: 'expected', timeoutMs: 2_000 });
    try {
      const res = await callback(receiver.redirectUri, { code: 'code-1', state: 'attacker' });
      assert.equal(res.status, 400);
      await assert.rejects(receiver.code, /state did not match/);
    } finally {
      await receiver.close();
    }
  });

  it('refuses a callback carrying no state at all', async () => {
    const receiver = await startLoopbackReceiver({ state: 'expected', timeoutMs: 2_000 });
    try {
      const res = await callback(receiver.redirectUri, { code: 'code-1' });
      assert.equal(res.status, 400);
      await assert.rejects(receiver.code, /state did not match/);
    } finally {
      await receiver.close();
    }
  });

  it('surfaces an authorization error response', async () => {
    const receiver = await startLoopbackReceiver({ state: 'st', timeoutMs: 2_000 });
    try {
      const res = await callback(receiver.redirectUri, {
        error: 'access_denied',
        error_description: 'user said no',
        state: 'st',
      });
      assert.equal(res.status, 400);
      await assert.rejects(receiver.code, /access_denied.*user said no/);
    } finally {
      await receiver.close();
    }
  });

  it('serves exactly one callback', async () => {
    const receiver = await startLoopbackReceiver({ state: 'st', timeoutMs: 2_000 });
    try {
      await callback(receiver.redirectUri, { code: 'code-1', state: 'st' });
      assert.equal(await receiver.code, 'code-1');
      const second = await callback(receiver.redirectUri, { code: 'code-2', state: 'st' });
      assert.equal(second.status, 410);
    } finally {
      await receiver.close();
    }
  });

  it('ignores requests to other paths', async () => {
    const receiver = await startLoopbackReceiver({ state: 'st', timeoutMs: 2_000 });
    try {
      const favicon = await fetch(`http://127.0.0.1:${receiver.port}/favicon.ico`, {
        headers: { connection: 'close' },
      });
      assert.equal(favicon.status, 404);
      await callback(receiver.redirectUri, { code: 'code-1', state: 'st' });
      assert.equal(await receiver.code, 'code-1');
    } finally {
      await receiver.close();
    }
  });

  it('gives up when the deadline passes', async () => {
    const receiver = await startLoopbackReceiver({ state: 'st', timeoutMs: 25 });
    try {
      await assert.rejects(receiver.code, /timed out/);
    } finally {
      await receiver.close();
    }
  });
});
