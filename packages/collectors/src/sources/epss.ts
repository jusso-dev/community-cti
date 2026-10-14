export interface EpssRow {
  cve: string;
  epss: number;
  percentile: number;
}

export function parseEpss(csv: string): EpssRow[] {
  const rows: EpssRow[] = [];
  for (const line of csv.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("cve,")) continue;
    const [cve, epss, percentile] = trimmed.split(",");
    if (!cve || !epss) continue;
    rows.push({ cve, epss: Number(epss), percentile: Number(percentile) });
  }
  return rows;
}

export function attachEpss<T extends { extra?: Record<string, unknown>; cve?: string }>(
  objects: T[],
  scores: EpssRow[],
): T[] {
  const byCve = new Map(scores.map((row) => [row.cve, row]));
  return objects.map((obj) => {
    const score = obj.cve ? byCve.get(obj.cve) : undefined;
    if (!score) return obj;
    return { ...obj, extra: { ...(obj.extra ?? {}), x_epss_score: score.epss, x_epss_percentile: score.percentile } };
  });
}
