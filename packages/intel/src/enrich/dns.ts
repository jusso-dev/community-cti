export interface DnsSnapshot {
  a: string[];
  aaaa: string[];
  mx: string[];
  resolves: boolean;
  hasMx: boolean;
}

export interface DnsResolver {
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
  resolveMx(host: string): Promise<string[]>;
}

async function safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

export async function lookupDns(host: string, resolver: DnsResolver): Promise<DnsSnapshot> {
  const a = await safe(() => resolver.resolve4(host), []);
  const aaaa = await safe(() => resolver.resolve6(host), []);
  const mx = await safe(() => resolver.resolveMx(host), []);
  return { a, aaaa, mx, resolves: a.length + aaaa.length > 0, hasMx: mx.length > 0 };
}
