export interface CertStreamMessage {
  data?: { leaf_cert?: { all_domains?: string[] } };
}

export function parseCertStream(message: CertStreamMessage): string[] {
  return (message.data?.leaf_cert?.all_domains ?? []).map((name) => name.toLowerCase().replace(/^\*\./, ""));
}

export function backoffMs(attempt: number): number {
  return Math.min(30_000, 500 * 2 ** Math.max(0, attempt));
}
