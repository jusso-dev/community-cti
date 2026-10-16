import { lookup as systemLookup } from "node:dns/promises";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";

const BLOCKED_HOSTS = new Set(["localhost", "metadata.google.internal"]);

const PRIVATE_V4: Array<[number, number]> = [
  [0x00000000, 8], // this network
  [0x0a000000, 8], // private
  [0x64400000, 10], // carrier-grade NAT
  [0x7f000000, 8], // loopback
  [0xa9fe0000, 16], // link local, cloud metadata
  [0xac100000, 12], // private
  [0xc0000000, 24], // IETF protocol assignments
  [0xc0000200, 24], // documentation
  [0xc0586300, 24], // 6to4 relay anycast
  [0xc0a80000, 16], // private
  [0xc6120000, 15], // benchmarking
  [0xc6336400, 24], // documentation
  [0xcb007100, 24], // documentation
  [0xe0000000, 4], // multicast
  [0xf0000000, 4], // reserved and broadcast
];

function v4Number(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((sum, part) => sum * 256 + Number(part), 0);
}

function privateV4(value: number): boolean {
  return PRIVATE_V4.some(([base, bits]) => Math.floor(value / 2 ** (32 - bits)) === Math.floor(base / 2 ** (32 - bits)));
}

function v6Words(value: string): number[] | null {
  let text = value;
  const tail = text.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (tail) {
    const v4 = v4Number(tail[1]!);
    if (v4 === null) return null;
    text = `${text.slice(0, -tail[1]!.length)}${Math.floor(v4 / 65536).toString(16)}:${(v4 % 65536).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : null;
  const words = rest === null ? head : [...head, ...new Array(8 - head.length - rest.length).fill("0"), ...rest];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return null;
  return words.map((word) => parseInt(word, 16));
}

function embeddedV4(high: number, low: number): number {
  return high * 65536 + low;
}

/**
 * True for any address an enrichment fetch must not reach: private,
 * loopback, link-local, metadata, documentation, multicast and reserved
 * ranges, including IPv4 hidden inside IPv6 (mapped, compatible, NAT64,
 * 6to4). Anything that does not parse as an IP address is refused too.
 */
export function isPrivateAddress(ip: string): boolean {
  const value = ip.toLowerCase().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const v4 = v4Number(value);
  if (v4 !== null) return privateV4(v4);
  const words = v6Words(value);
  if (!words) return true;
  const [w0, w1, w2, w3, w4, w5, w6, w7] = words as [number, number, number, number, number, number, number, number];
  if (words.every((word) => word === 0)) return true;
  if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0 && w6 === 0 && w7 === 1) return true;
  if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && (w5 === 0xffff || w5 === 0)) return privateV4(embeddedV4(w6, w7));
  if (w0 === 0x64 && w1 === 0xff9b && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0) return privateV4(embeddedV4(w6, w7));
  if (w0 === 0x64 && w1 === 0xff9b && w2 === 1) return true;
  if (w0 === 0x2002) return privateV4(embeddedV4(w1, w2));
  if (w0 === 0x2001 && w1 === 0) return true; // Teredo
  if (w0 === 0x2001 && w1 === 0xdb8) return true; // documentation
  if (w0 === 0x100 && w1 === 0 && w2 === 0 && w3 === 0) return true; // discard
  if ((w0 & 0xfe00) === 0xfc00) return true; // unique local
  if ((w0 & 0xffc0) === 0xfe80 || (w0 & 0xffc0) === 0xfec0) return true; // link and site local
  if ((w0 & 0xff00) === 0xff00) return true; // multicast
  return false;
}

export interface SafeFetchResult {
  ok: boolean;
  status?: number;
  body?: string;
  error?: string;
  finalUrl?: string;
}

export type Resolver = (host: string) => Promise<string[]>;

export interface FetchedPage {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}

export type FetchLike = (url: string, init: { redirect: "manual"; signal: AbortSignal }) => Promise<FetchedPage>;

export const systemResolver: Resolver = async (host) => (await systemLookup(host, { all: true, verbatim: true })).map((item) => item.address);

function codedError(code: string, message: string): Error {
  return Object.assign(new Error(message), { code });
}

/**
 * A socket lookup that resolves once, refuses the connection if any answer is
 * private, and hands the checked address straight to the socket. Because the
 * address that was checked is the address that is dialled, a DNS answer that
 * changes between "check" and "connect" (DNS rebinding) cannot slip through.
 */
export function pinnedLookup(resolve: Resolver, allow: (ip: string) => boolean = (ip) => !isPrivateAddress(ip)): LookupFunction {
  return ((hostname: string, options: { family?: number | string; all?: boolean }, callback: (error: Error | null, address: unknown, family?: number) => void) => {
    resolve(hostname)
      .then((addresses) => {
        if (addresses.length === 0) throw codedError("ENOTFOUND", `no addresses for ${hostname}`);
        if (addresses.some((address) => !allow(address))) throw codedError("EPRIVATE", "private address");
        const family = options.family === 4 || options.family === "IPv4" ? 4 : options.family === 6 || options.family === "IPv6" ? 6 : 0;
        const usable = family ? addresses.filter((address) => isIP(address) === family) : addresses;
        if (usable.length === 0) throw codedError("ENOTFOUND", `no IPv${family} address for ${hostname}`);
        if (options.all) callback(null, usable.map((address) => ({ address, family: isIP(address) })));
        else callback(null, usable[0], isIP(usable[0]!));
      })
      .catch((error: Error) => callback(error, options.all ? [] : "", 0));
  }) as unknown as LookupFunction;
}

/** Plain GET over node:http(s) with the pinned lookup, no connection reuse and a streaming size cap. */
export function pinnedTransport(options: { resolve: Resolver; allow?: (ip: string) => boolean; maxBytes: number; userAgent: string }): FetchLike {
  return (url, init) => new Promise<FetchedPage>((done, fail) => {
    const target = new URL(url);
    const send = target.protocol === "https:" ? httpsRequest : httpRequest;
    const request = send(target, {
      method: "GET",
      agent: false,
      lookup: pinnedLookup(options.resolve, options.allow),
      signal: init.signal,
      headers: { "user-agent": options.userAgent, accept: "text/html,application/xhtml+xml,image/*;q=0.8,*/*;q=0.5" },
    }, (response: IncomingMessage) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > options.maxBytes) {
          response.destroy();
          fail(codedError("ETOOBIG", "body too large"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("error", fail);
      response.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        done({
          status: response.statusCode ?? 0,
          headers: {
            get(name: string) {
              const value = response.headers[name.toLowerCase()];
              return Array.isArray(value) ? value.join(", ") : value ?? null;
            },
          },
          async text() {
            return body;
          },
        });
      });
    });
    request.on("error", fail);
    request.end();
  });
}

export async function safeFetch(options: {
  url: string;
  /** Resolver used for the address check. Defaults to the system resolver. */
  lookup?: Resolver;
  /**
   * Test hook. When set, requests go through this function after a separate
   * address check, which leaves a rebinding window; production callers leave
   * it unset so the IP-pinned transport is used.
   */
  fetchImpl?: FetchLike;
  /** Test hook to accept addresses the default policy refuses, for example a local test server. */
  allowAddress?: (ip: string) => boolean;
  timeoutMs?: number;
  maxBytes?: number;
  redirectsLeft?: number;
  userAgent?: string;
}): Promise<SafeFetchResult> {
  const timeoutMs = options.timeoutMs ?? 5000;
  const maxBytes = options.maxBytes ?? 1_048_576;
  const redirectsLeft = options.redirectsLeft ?? 3;
  const resolve = options.lookup ?? systemResolver;
  const allow = options.allowAddress ?? ((ip: string) => !isPrivateAddress(ip));
  let parsed: URL;
  try {
    parsed = new URL(options.url);
  } catch {
    return { ok: false, error: "invalid url" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return { ok: false, error: "scheme refused" };
  if (parsed.username || parsed.password) return { ok: false, error: "credentials in url refused" };
  if (BLOCKED_HOSTS.has(parsed.hostname.toLowerCase())) return { ok: false, error: "host refused" };
  const literal = parsed.hostname.replace(/^\[|\]$/g, "");
  if (isIP(literal) && !allow(literal)) return { ok: false, error: "private address" };
  if (options.fetchImpl) {
    try {
      const addresses = isIP(literal) ? [literal] : await resolve(parsed.hostname);
      if (addresses.length === 0 || addresses.some((address) => !allow(address))) return { ok: false, error: "private address" };
    } catch {
      return { ok: false, error: "dns failed" };
    }
  }
  const transport = options.fetchImpl ?? pinnedTransport({
    resolve,
    allow,
    maxBytes,
    userAgent: options.userAgent ?? "community-cti-enrichment/0.1",
  });
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new DOMException("timeout", "TimeoutError"));
  }, timeoutMs);
  try {
    const response = await transport(parsed.toString(), { redirect: "manual", signal: controller.signal });
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
    if (Buffer.byteLength(body) > maxBytes) return { ok: false, error: "body too large" };
    return { ok: true, status: response.status, body, finalUrl: parsed.toString() };
  } catch (error) {
    const name = error instanceof Error ? error.name : "";
    const code = (error as { code?: string }).code ?? (error as { cause?: { code?: string } }).cause?.code;
    if (name === "TimeoutError" || name === "AbortError" || controller.signal.aborted) return { ok: false, error: "timeout" };
    if (code === "EPRIVATE") return { ok: false, error: "private address" };
    if (code === "ETOOBIG") return { ok: false, error: "body too large" };
    if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "ENODATA") return { ok: false, error: "dns failed" };
    return { ok: false, error: "fetch failed" };
  } finally {
    clearTimeout(timer);
  }
}
