import { BlockList, isIP } from "node:net";
import { createHash } from "node:crypto";

const blocked = new BlockList();
blocked.addSubnet("0.0.0.0", 8, "ipv4");
blocked.addSubnet("10.0.0.0", 8, "ipv4");
blocked.addSubnet("127.0.0.0", 8, "ipv4");
blocked.addSubnet("169.254.0.0", 16, "ipv4");
blocked.addSubnet("172.16.0.0", 12, "ipv4");
blocked.addSubnet("192.168.0.0", 16, "ipv4");
blocked.addSubnet("100.64.0.0", 10, "ipv4");
blocked.addAddress("::1", "ipv6");
blocked.addSubnet("fc00::", 7, "ipv6");
blocked.addSubnet("fe80::", 10, "ipv6");

const BLOCKED_NAMES = new Set(["localhost", "metadata.google.internal"]);

export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 0) return true;
  return blocked.check(ip, version === 6 ? "ipv6" : "ipv4");
}

export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

export function assertPublicHost(host: string, addresses: string[]): void {
  if (BLOCKED_NAMES.has(host.toLowerCase()) || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new SsrfError(`refusing host ${host}`);
  }
  if (addresses.length === 0 || addresses.some((address) => isPrivateAddress(address))) {
    throw new SsrfError(`refusing private address for ${host}`);
  }
}

export interface FetchPageResult {
  ok: boolean;
  status?: number;
  body?: string;
  sha256?: string;
  error?: string;
}

export async function fetchPublicPage(input: {
  url: string;
  resolve: (host: string) => Promise<string[]>;
  fetchImpl: (url: string, init?: RequestInit) => Promise<Response>;
  timeoutMs?: number;
  maxBytes?: number;
}): Promise<FetchPageResult> {
  const timeoutMs = input.timeoutMs ?? 5_000;
  const maxBytes = input.maxBytes ?? 1_000_000;
  try {
    const target = new URL(input.url);
    if (target.protocol !== "https:" && target.protocol !== "http:") throw new SsrfError("unsupported protocol");
    assertPublicHost(target.hostname, await input.resolve(target.hostname));
    const response = await input.fetchImpl(target.toString(), { redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    if (response.status >= 300 && response.status < 400) {
      const next = response.headers.get("location");
      if (!next) return { ok: false, status: response.status, error: "redirect without location" };
      return fetchPublicPage({ ...input, url: new URL(next, target).toString() });
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maxBytes) return { ok: false, status: response.status, error: "body too large" };
    const body = new TextDecoder().decode(bytes);
    return { ok: response.ok, status: response.status, body, sha256: createHash("sha256").update(bytes).digest("hex") };
  } catch (error) {
    const message = error instanceof Error ? error.message : "fetch failed";
    return { ok: false, error: message.includes("Timeout") || message.includes("aborted") ? "timeout" : message };
  }
}

/** mmh3 32-bit, used to compare favicon bytes. */
export function murmur3(data: Uint8Array, seed = 0): number {
  let h1 = seed >>> 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const blocks = Math.floor(data.length / 4);
  for (let i = 0; i < blocks; i++) {
    let k1 = data[i * 4]! | (data[i * 4 + 1]! << 8) | (data[i * 4 + 2]! << 16) | (data[i * 4 + 3]! << 24);
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = Math.imul(h1, 5) + 0xe6546b64;
  }
  let k1 = 0;
  const tail = data.length % 4;
  const offset = blocks * 4;
  if (tail >= 3) k1 ^= data[offset + 2]! << 16;
  if (tail >= 2) k1 ^= data[offset + 1]! << 8;
  if (tail >= 1) {
    k1 ^= data[offset]!;
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
  }
  h1 ^= data.length;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return h1 | 0;
}
