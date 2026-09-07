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
  /** A lock this old with no heartbeat belongs to a process that died holding it. */
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

async function touch(lockPath: string, owner: string): Promise<void> {
  try {
    if ((await fs.readFile(lockPath, 'utf8')) !== owner) return;
    const now = new Date();
    await fs.utimes(lockPath, now, now);
  } catch {
    // The lock is gone or already someone else's; `release` decides what that means.
  }
}

/**
 * Keep the lock file's mtime current for as long as the holder is inside it.
 * Nothing bounds the work a holder does — a token request against a slow host
 * can run for minutes — so without this a live holder ages past `staleMs`, a
 * waiter evicts it, and both processes spend the same one-time-use handle.
 */
function beatWhileHeld(lockPath: string, owner: string, staleMs: number): () => void {
  const beat = Math.max(10, Math.floor(staleMs / 3));
  const timer = setInterval(() => void touch(lockPath, owner), beat);
  timer.unref();
  return () => clearInterval(timer);
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

  const stopHeartbeat = beatWhileHeld(lockPath, owner, staleMs);
  try {
    return await run();
  } finally {
    stopHeartbeat();
    await release(lockPath, owner);
  }
}
