export interface SourceMarkdownRow {
  id: string;
  name: string;
  type: string;
  licence: string;
  commercialUse: string;
  cost: string;
  coverage: string;
  tlp: string;
  accessMethod: string;
  status: string;
  reviewedBy: string;
  notes: string;
}

/** Parses the inventory table in docs/SOURCES.md. */
export function parseSourcesMarkdown(markdown: string): SourceMarkdownRow[] {
  const rows: SourceMarkdownRow[] = [];
  for (const line of markdown.split(/\r?\n/)) {
    if (!line.startsWith("|")) continue;
    const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
    if (cells.length < 12) continue;
    if (cells[0] === "Id" || cells[0].startsWith("---") || cells.every((cell) => /^-+$/.test(cell.replace(/\s/g, "")))) continue;
    const id = cells[0]?.replace(/`/g, "") ?? "";
    if (!id || id === "Id") continue;
    rows.push({
      id,
      name: cells[1] ?? "",
      type: cells[2] ?? "",
      licence: cells[3] ?? "",
      commercialUse: cells[4] ?? "",
      cost: cells[5] ?? "",
      coverage: cells[6] ?? "",
      tlp: cells[7] ?? "",
      accessMethod: cells[8] ?? "",
      status: cells[9] ?? "",
      reviewedBy: cells[10] ?? "",
      notes: cells[11] ?? "",
    });
  }
  return rows;
}
