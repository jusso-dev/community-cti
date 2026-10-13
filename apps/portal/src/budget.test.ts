import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const LIMIT = 200 * 1024;

function walk(dir: string): string[] {
  const files: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) files.push(...walk(path));
    else if (name.endsWith(".html")) files.push(path);
  }
  return files;
}

test("served portal HTML stays under 200 KB of initial JS", () => {
  const outDir = fileURLToPath(new URL("../out/", import.meta.url));
  assert.equal(existsSync(outDir), true, "portal build did not write out/");
  const pages = walk(outDir);
  assert.ok(pages.length >= 4, "expected the findings, detail, domains and notifications pages");
  for (const page of pages) {
    const html = readFileSync(page, "utf8");
    assert.equal(html.includes("<script"), false, page);
    const srcs = [...html.matchAll(/<script[^>]+src="([^"]+)"/g)].map((match) => match[1] ?? "");
    let total = 0;
    for (const src of srcs) {
      const file = join(outDir, src.replace(/^\//, ""));
      total += existsSync(file) ? statSync(file).size : LIMIT + 1;
    }
    assert.ok(total <= LIMIT, `${page} references ${total} bytes of JS`);
  }
  for (const rel of ["index.html", "domains.html", join("settings", "notifications.html"), join("findings", "example-lookalike.html")]) {
    const html = readFileSync(join(outDir, rel), "utf8");
    assert.match(html, /<main>/, rel);
  }
  assert.match(readFileSync(join(outDir, "findings", "example-lookalike.html"), "utf8"), /Dismiss/);
});
