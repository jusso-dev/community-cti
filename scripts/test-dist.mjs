import { spawnSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

function testFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...testFiles(path));
    else if (name.endsWith(".test.js")) out.push(path);
  }
  return out;
}

const extra = process.argv.slice(2).filter((arg) => arg !== "--");
const files = testFiles("dist");
if (files.length === 0) {
  console.error("no compiled tests in dist/");
  process.exit(1);
}
const result = spawnSync(process.execPath, ["--test", ...extra, ...files], { stdio: "inherit" });
process.exit(result.status ?? 1);
