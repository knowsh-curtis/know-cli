/**
 * An exclusive lock file, used to serialise refresh-token rotation between
 * processes. Every MCP host that installs know.sh spawns its own `mcp-proxy`,
 * and all of them read and write one `tokens.json`. Rotation is one-time-use
 * and replaying a spent handle revokes the whole family, so an in-process gate
 * only covers the concurrency that does not actually happen.
 */
import { randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

export interface LockOptions {
  /** A lock older than this belongs to a process that died holding it. */
  staleMs?: number;
  /** How long to wait for the holder before giving up. */
  waitMs?: number;
  pollMs?: number;
}

const LOCK_DEFAULTS: Required<LockOptions> = { staleMs: 30_000, waitMs: 60_000, pollMs: 25 };

const errorCode = (err: unknown): string | undefined => (err as NodeJS.ErrnoException)?.code;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function claim(lockPath: string, owner: string): Promise<boolean> {
  let file;
  try {
    file = await fs.open(lockPath, 'wx', 0o600);
  } catch (err) {
    if (errorCode(err) === 'EEXIST') return false;
    throw err;
  }
  try {
    await file.writeFile(owner);
  } finally {
    await file.close();
  }
  return true;
}

async function evictStale(lockPath: string, staleMs: number): Promise<boolean> {
  let age: number;
  try {
    age = Date.now() - (await fs.stat(lockPath)).mtimeMs;
  } catch (err) {
    if (errorCode(err) === 'ENOENT') return true;
    throw err;
  }
  if (age <= staleMs) return false;

  // Rename before unlinking: only one waiter can move the inode, so two of them
  // cannot both call it stale and then delete each other's fresh replacement.
  const evicted = `${lockPath}.stale.${process.pid}.${Date.now()}`;
  try {
    await fs.rename(lockPath, evicted);
  } catch (err) {
    if (errorCode(err) === 'ENOENT') return true;
    throw err;
  }
  await fs.rm(evicted, { force: true });
  return true;
}

async function release(lockPath: string, owner: string): Promise<void> {
  try {
    if ((await fs.readFile(lockPath, 'utf8')) !== owner) return;
    await fs.unlink(lockPath);
  } catch (err) {
    if (errorCode(err) !== 'ENOENT') throw err;
  }
}

export async function withFileLock<T>(
  lockPath: string,
  run: () => Promise<T>,
  options: LockOptions = {},
): Promise<T> {
  const { staleMs, waitMs, pollMs } = { ...LOCK_DEFAULTS, ...options };
  const owner = `${process.pid}:${randomUUID()}`;
  await fs.mkdir(path.dirname(lockPath), { recursive: true, mode: 0o700 });

  const deadline = Date.now() + waitMs;
  while (!(await claim(lockPath, owner))) {
    if (!(await evictStale(lockPath, staleMs)) && Date.now() >= deadline) {
      throw new Error(`timed out after ${Math.round(waitMs / 1000)}s waiting for ${lockPath}`);
    }
    await sleep(pollMs);
  }

  try {
    return await run();
  } finally {
    await release(lockPath, owner);
  }
}
