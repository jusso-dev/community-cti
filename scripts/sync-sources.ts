import { readFileSync } from "node:fs";
import { parseSourcesMarkdown } from "../packages/collectors/src/sources-doc.ts";

const markdown = readFileSync(new URL("../docs/SOURCES.md", import.meta.url), "utf8");
const rows = parseSourcesMarkdown(markdown);
console.log(JSON.stringify(rows, null, 2));
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not set, so rows were not written. Status values are unchanged.");
}
