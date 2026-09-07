/**
 * Form POSTs to the identity host, every one of them bounded in time. Node's
 * `fetch` has no deadline of its own (undici gives up after 300 s), and a token
 * request runs while the token-file lock is held: an unbounded one outlives its
 * own lock, gets evicted as stale, and ends up replaying a spent handle — the
 * failure `src/lock.ts` exists to prevent.
 */
export const isTimeout = (err: unknown): boolean =>
  (err as { name?: string } | null)?.name === 'TimeoutError';

export const timedOut = (label: string, timeoutMs: number): Error =>
  new Error(`${label} timed out after ${timeoutMs} ms`);

export function postForm(
  endpoint: string,
  body: URLSearchParams,
  timeoutMs: number,
): Promise<Response> {
  return fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body,
    signal: AbortSignal.timeout(timeoutMs),
  });
}
