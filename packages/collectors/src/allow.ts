export const ACSC_HOSTS = new Set(["www.cyber.gov.au", "cyber.gov.au"]);
export const RANSOM_HOSTS = new Set(["api.ransomware.live", "ransomware.live"]);

export function assertAllowListed(url: string, allow: Set<string>): void {
  const host = new URL(url).hostname.toLowerCase();
  if (!allow.has(host)) throw new Error(`host ${host} is not allow-listed`);
}
