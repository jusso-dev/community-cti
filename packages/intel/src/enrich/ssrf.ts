const BLOCKED_HOSTS = new Set(["localhost", "metadata.google.internal"]);

export function isPrivateAddress(ip: string): boolean {
  const value = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (value === "::1" || value === "0.0.0.0" || value === "::") return true;
  const v4 = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if ([a, b, Number(v4[3]), Number(v4[4])].some((part) => part > 255)) return true;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }
  if (value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe80")) return true;
  return false;
}

export interface SafeFetchResult {
  ok: boolean;
  status?: number;
  body?: string;
  error?: string;
  finalUrl?: string;
}

export async function safeFetch(options: {
  url: string;
  lookup: (host: string) => Promise<string[]>;
  fetchImpl: (url: string, init: { redirect: "manual"; signal: AbortSignal }) => Promise<{
    status: number;
    headers: { get(name: string): string | null };
    text(): Promise<string>;
  }>;
  timeoutMs?: number;
  maxBytes?: number;
  redirectsLeft?: number;
}): Promise<SafeFetchResult> {
  const timeoutMs = options.timeoutMs ?? 5000;
  const maxBytes = options.maxBytes ?? 1_048_576;
  const redirectsLeft = options.redirectsLeft ?? 3;
  let parsed: URL;
  try {
    parsed = new URL(options.url);
  } catch {
    return { ok: false, error: "invalid url" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return { ok: false, error: "scheme refused" };
  if (BLOCKED_HOSTS.has(parsed.hostname.toLowerCase())) return { ok: false, error: "host refused" };
  const literal = parsed.hostname.replace(/^\[|\]$/g, "");
  if (isPrivateAddress(literal) || /^\d+\.\d+\.\d+\.\d+$/.test(literal) && isPrivateAddress(literal)) {
    return { ok: false, error: "private address" };
  }
  try {
    const addresses = await options.lookup(parsed.hostname);
    if (addresses.length === 0 || addresses.some((address) => isPrivateAddress(address))) {
      return { ok: false, error: "private address" };
    }
  } catch {
    return { ok: false, error: "dns failed" };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new DOMException("timeout", "TimeoutError"));
  }, timeoutMs);
  try {
    const response = await options.fetchImpl(parsed.toString(), {
      redirect: "manual",
      signal: controller.signal,
    });
    if (response.status >= 300 && response.status < 400) {
      if (redirectsLeft <= 0) return { ok: false, error: "too many redirects" };
      const location = response.headers.get("location");
      if (!location) return { ok: false, error: "redirect missing location" };
      const next = new URL(location, parsed).toString();
      return safeFetch({ ...options, url: next, redirectsLeft: redirectsLeft - 1 });
    }
    const length = Number(response.headers.get("content-length") ?? "0");
    if (length > maxBytes) return { ok: false, error: "body too large" };
    const body = await response.text();
    if (body.length > maxBytes) return { ok: false, error: "body too large" };
    return { ok: true, status: response.status, body, finalUrl: parsed.toString() };
  } catch (error) {
    const name = error instanceof Error ? error.name : "";
    if (name === "TimeoutError" || name === "AbortError") return { ok: false, error: "timeout" };
    return { ok: false, error: "fetch failed" };
  } finally {
    clearTimeout(timer);
  }
}
