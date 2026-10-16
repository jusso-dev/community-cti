import { gunzipSync } from "node:zlib";

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface FeedFetchOptions {
  url: string;
  /** URL prefixes the request and every redirect must start with, for example "https://crt.sh/". */
  allow: string[];
  userAgent: string;
  fetchImpl: FetchLike;
  sleep: (ms: number) => Promise<void>;
  headers?: Record<string, string>;
  timeoutMs?: number;
  maxBytes?: number;
  retries?: number;
}

export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_BYTES = 50 * 1024 * 1024;
const MAX_REDIRECTS = 3;

export class FeedError extends Error {
  constructor(message: string, readonly retryable: boolean, readonly retryAfterMs?: number) {
    super(message);
    this.name = "FeedError";
  }
}

export function isAllowedUrl(url: string, allow: string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return allow.some((prefix) => parsed.href.startsWith(prefix));
}

/**
 * Fetch an allow-listed feed: fixed timeout, body size cap, a named User-Agent,
 * redirects only to allow-listed prefixes, and at most `retries` retries with backoff.
 */
export async function fetchFeed(options: FeedFetchOptions): Promise<{ body: Buffer; finalUrl: string }> {
  const retries = options.retries ?? 2;
  for (let attempt = 0; ; attempt++) {
    try {
      return await fetchOnce(options);
    } catch (error) {
      const retryable = error instanceof FeedError ? error.retryable : true;
      if (!retryable || attempt >= retries) throw error;
      const asked = error instanceof FeedError ? error.retryAfterMs : undefined;
      await options.sleep(asked ?? 1000 * 2 ** attempt);
    }
  }
}

async function fetchOnce(options: FeedFetchOptions): Promise<{ body: Buffer; finalUrl: string }> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const signal = AbortSignal.timeout(timeoutMs);
  let current = options.url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!isAllowedUrl(current, options.allow)) throw new FeedError(`${hostOf(current)} is not allow-listed for this source`, false);
    let response: Response;
    try {
      response = await options.fetchImpl(current, {
        redirect: "manual",
        signal,
        headers: { "user-agent": options.userAgent, accept: "*/*", ...(options.headers ?? {}) },
      });
    } catch (error) {
      const name = error instanceof Error ? error.name : "";
      const code = (error as { cause?: { code?: string } }).cause?.code;
      throw new FeedError(name === "TimeoutError" || name === "AbortError" ? "request timed out" : `request failed${code ? ` (${code})` : ""}`, true);
    }
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (!location) throw new FeedError("redirect without a location", false);
      current = new URL(location, current).toString();
      continue;
    }
    if (response.status === 429 || response.status >= 500) {
      await response.body?.cancel();
      const retryAfter = Number(response.headers.get("retry-after"));
      throw new FeedError(`HTTP ${response.status}`, true, response.status === 429 ? Math.min(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 60_000, 120_000) : undefined);
    }
    if (response.status !== 200) {
      await response.body?.cancel();
      throw new FeedError(`HTTP ${response.status}`, false);
    }
    const declared = Number(response.headers.get("content-length") ?? "0");
    if (declared > maxBytes) {
      await response.body?.cancel();
      throw new FeedError("body is larger than the cap", false);
    }
    return { body: await readCapped(response, maxBytes), finalUrl: current };
  }
  throw new FeedError("too many redirects", false);
}

async function readCapped(response: Response, maxBytes: number): Promise<Buffer> {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new FeedError("body is larger than the cap", false);
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof FeedError) throw error;
    const name = error instanceof Error ? error.name : "";
    throw new FeedError(name === "TimeoutError" || name === "AbortError" ? "request timed out" : "body read failed", true);
  }
  return Buffer.concat(chunks);
}

/** Gunzip when the body has the gzip magic bytes, with an output cap. */
export function maybeGunzip(body: Buffer, maxBytes = 4 * DEFAULT_MAX_BYTES): Buffer {
  if (body.length >= 2 && body[0] === 0x1f && body[1] === 0x8b) return gunzipSync(body, { maxOutputLength: maxBytes });
  return body;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "invalid url";
  }
}
