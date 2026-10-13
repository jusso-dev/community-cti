/** Keep the numbers in this file identical to config/tiers.ts. */
export const TIERS = {
  community: { monthlyAud: 15, hypothesis: true },
  community_plus: { monthlyAud: 40, hypothesis: true },
  business: { monthlyAud: 120, hypothesis: true },
  managed: { monthlyAud: 400, hypothesis: true },
} as const;

export type TierName = keyof typeof TIERS;

export interface LedgerRow {
  tenantId: string;
  category: string;
  units: number;
  aud: number;
  at: string;
}

export function monthKey(at: Date): string {
  return at.toISOString().slice(0, 7);
}

export function monthTotal(rows: LedgerRow[], tenantId: string, month: string): number {
  return rows
    .filter((row) => row.tenantId === tenantId && row.at.slice(0, 7) === month)
    .reduce((sum, row) => sum + row.aud, 0);
}

export function processingMode(spentAud: number, limitAud: number): "normal" | "deterministic" {
  return spentAud >= limitAud ? "deterministic" : "normal";
}

export function costReport(rows: LedgerRow[], month: string): Array<{ tenantId: string; aud: number }> {
  const totals = new Map<string, number>();
  for (const row of rows) {
    if (row.at.slice(0, 7) !== month) continue;
    totals.set(row.tenantId, (totals.get(row.tenantId) ?? 0) + row.aud);
  }
  return [...totals.entries()].map(([tenantId, aud]) => ({ tenantId, aud: Number(aud.toFixed(4)) }));
}
