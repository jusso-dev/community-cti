import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The Next.js client runtime is about 300 KB raw. These pages are server HTML
// with ordinary links and forms, so the served files drop that runtime.
// The budget test measures the HTML that this script writes.

const root = fileURLToPath(new URL("../out/", import.meta.url));

function walk(dir) {
  const files = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) files.push(...walk(path));
    else if (name.endsWith(".html")) files.push(path);
  }
  return files;
}

for (const path of walk(root)) {
  const html = readFileSync(path, "utf8")
    .replace(/<link\s+[^>]*rel="preload"[^>]*as="script"[^>]*>/g, "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "");
  if (html.includes("<script")) throw new Error(`script tag remains in ${path}`);
  writeFileSync(path, html);
}
console.log("Served portal HTML has no script tags.");
