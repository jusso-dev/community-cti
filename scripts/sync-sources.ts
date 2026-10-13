import { readFileSync } from "node:fs";
import { parseSourcesMarkdown } from "../packages/collectors/dist/sync.js";

const markdown = readFileSync(new URL("../docs/SOURCES.md", import.meta.url), "utf8");
const rows = parseSourcesMarkdown(markdown);
console.log(`parsed ${rows.length} sources`);
const blocked = rows.filter((row) => row.status === "blocked").map((row) => row.id);
console.log(`blocked ${blocked.join(", ")}`);
if (!process.env.DATABASE_URL) {
  console.log("DATABASE_URL is not set, so nothing was written.");
}
