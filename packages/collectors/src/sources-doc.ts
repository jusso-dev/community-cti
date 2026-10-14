export interface SourceRow {
  id: string;
  name: string;
  type: string;
  licence: string;
  commercialUse: string;
  cost: string;
  coverage: string;
  tlp: string;
  accessMethod: string;
  status: "candidate" | "approved" | "rejected" | "blocked";
  reviewedBy: string;
  notes: string;
}

export function parseSourcesMarkdown(markdown: string): SourceRow[] {
  const rows: SourceRow[] = [];
  for (const line of markdown.split("\n")) {
    if (!line.startsWith("| `")) continue;
    const cells = line.split("|").slice(1, -1).map((cell) => cell.trim().replace(/^`|`$/g, ""));
    if (cells.length < 12) continue;
    const status = cells[9] as SourceRow["status"];
    rows.push({
      id: cells[0],
      name: cells[1],
      type: cells[2],
      licence: cells[3],
      commercialUse: cells[4],
      cost: cells[5],
      coverage: cells[6],
      tlp: cells[7],
      accessMethod: cells[8],
      status,
      reviewedBy: cells[10] ?? "",
      notes: cells[11] ?? "",
    });
  }
  return rows;
}
