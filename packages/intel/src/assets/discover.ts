export interface VerifiedDomain {
  domain: string;
  verified: boolean;
}

export interface Asset {
  host: string;
  addresses: string[];
  via: "apex" | "ct" | "dns";
}

export function isUnderVerifiedDomain(host: string, verified: string[]): boolean {
  const value = host.toLowerCase().replace(/\.$/, "");
  return verified.some((domain) => {
    const root = domain.toLowerCase();
    return value === root || value.endsWith(`.${root}`);
  });
}

/** Passive discovery from certificate names and DNS answers. This does not connect to ports. */
export function discoverAssets(input: {
  domains: VerifiedDomain[];
  ctNames: string[];
  dns: Record<string, string[]>;
}): Asset[] {
  const verified = input.domains.filter((item) => item.verified).map((item) => item.domain.toLowerCase());
  const hosts = new Set<string>(verified);
  for (const name of input.ctNames) {
    const host = name.toLowerCase().replace(/^\*\./, "");
    if (isUnderVerifiedDomain(host, verified)) hosts.add(host);
  }
  for (const host of Object.keys(input.dns)) {
    if (isUnderVerifiedDomain(host, verified)) hosts.add(host.toLowerCase());
  }
  return [...hosts].map((host) => ({
    host,
    addresses: input.dns[host] ?? input.dns[host.toLowerCase()] ?? [],
    via: verified.includes(host) ? "apex" : input.ctNames.some((name) => name.toLowerCase().replace(/^\*\./, "") === host) ? "ct" : "dns",
  }));
}
