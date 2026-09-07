import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { withFileLock } from '../src/lock.js';

describe('token file lock', () => {
  let dir: string;
  let lockPath: string;

  before(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), 'know-cli-lock-'));
    lockPath = path.join(dir, 'tokens.json.lock');
  });

  after(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('lets one holder finish before the next one starts', async () => {
    const order: string[] = [];
    const hold = (name: string) =>
      withFileLock(lockPath, async () => {
        order.push(`${name} in`);
        await new Promise((resolve) => setTimeout(resolve, 40));
        order.push(`${name} out`);
      });

    await Promise.all([hold('a'), hold('b')]);

    const [first, second] = order[0] === 'a in' ? ['a', 'b'] : ['b', 'a'];
    assert.deepEqual(order, [`${first} in`, `${first} out`, `${second} in`, `${second} out`]);
  });

  it('releases the lock even when the work throws', async () => {
    await assert.rejects(
      withFileLock(lockPath, async () => {
        throw new Error('token endpoint refused');
      }),
      /token endpoint refused/,
    );
    await assert.rejects(stat(lockPath), /ENOENT/);
  });

  it('breaks a lock left behind by a process that died holding it', async () => {
    await writeFile(lockPath, '999999:abandoned', { mode: 0o600 });
    const old = new Date(Date.now() - 120_000);
    await utimes(lockPath, old, old);

    let ran = false;
    await withFileLock(
      lockPath,
      async () => {
        ran = true;
      },
      { staleMs: 1_000, waitMs: 2_000 },
    );

    assert.equal(ran, true);
  });

  it('gives up rather than joining a holder that is still alive', async () => {
    await withFileLock(lockPath, async () => {
      await assert.rejects(
        withFileLock(lockPath, async () => assert.fail('two holders at once'), {
          waitMs: 100,
          staleMs: 60_000,
        }),
        /timed out/,
      );
    });
  });

  it('never deletes a lock that someone else took after ours was broken', async () => {
    await withFileLock(lockPath, async () => {
      await writeFile(lockPath, 'a-later-holder');
    });

    assert.equal(await readFile(lockPath, 'utf8'), 'a-later-holder');
    await rm(lockPath, { force: true });
  });
});
