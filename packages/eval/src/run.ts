import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildCases, renderReport } from "./metrics.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const cases = buildCases(200);
const casesDir = join(root, "eval", "cases");
const reportsDir = join(root, "eval", "reports");
mkdirSync(casesDir, { recursive: true });
mkdirSync(reportsDir, { recursive: true });
writeFileSync(join(casesDir, "synthetic.json"), JSON.stringify(cases, null, 2));
const date = "2026-10-14";
const report = renderReport(cases, date);
writeFileSync(join(reportsDir, `${date}.md`), report);
console.log(report);
