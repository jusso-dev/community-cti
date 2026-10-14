export function crtShUrl(keyword: string, verified: boolean): string {
  if (!verified) throw new Error(`refusing crt.sh lookup for unverified keyword ${keyword}`);
  return `https://crt.sh/?q=${encodeURIComponent(`%.${keyword}.%`)}&output=json`;
}
