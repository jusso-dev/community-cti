export interface CostEntry {
  tenantId: string;
  category: "agent" | "enrichment" | "storage" | "api";
  units: number;
  aud: number;
  at: string;
}

export interface CostState {
  entries: CostEntry[];
  limitAud: number;
}

export function recordCost(state: CostState, entry: CostEntry): { state: CostState; mode: "normal" | "deterministic-only"; notify: boolean } {
  const entries = [...state.entries, entry];
  const spent = entries.filter((item) => item.tenantId === entry.tenantId).reduce((sum, item) => sum + item.aud, 0);
  const degraded = spent >= state.limitAud;
  return {
    state: { ...state, entries },
    mode: degraded ? "deterministic-only" : "normal",
    notify: degraded,
  };
}

export function monthlyReport(entries: CostEntry[]): Array<{ tenantId: string; aud: number }> {
  const totals = new Map<string, number>();
  for (const entry of entries) totals.set(entry.tenantId, (totals.get(entry.tenantId) ?? 0) + entry.aud);
  return [...totals.entries()].map(([tenantId, aud]) => ({ tenantId, aud }));
}
