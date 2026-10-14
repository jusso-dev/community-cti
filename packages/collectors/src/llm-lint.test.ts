import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync as readRoot } from "node:fs";
import { parseSourcesMarkdown } from "./sources-doc.js";

const root = fileURLToPath(new URL("../src", import.meta.url));
const banned = ["openai", "@anthropic-ai/sdk", "langchain", "@aws-sdk/client-bedrock-runtime", "ollama"];

function walk(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walk(path));
    else if (entry.name.endsWith(".ts")) files.push(path);
  }
  return files;
}

test("collector sources do not import an LLM SDK", () => {
  for (const file of walk(root)) {
    const text = readFileSync(file, "utf8");
    for (const name of banned) {
      assert.equal(text.includes(`from "${name}`), false, `${file} imports ${name}`);
      assert.equal(text.includes(`require("${name}`), false, `${file} requires ${name}`);
    }
  }
});

test("source inventory parser keeps blocked rows blocked", () => {
  const markdown = readRoot(fileURLToPath(new URL("../../../docs/SOURCES.md", import.meta.url)), "utf8");
  const rows = parseSourcesMarkdown(markdown);
  const blocked = rows.filter((row) => row.status === "blocked").map((row) => row.id).sort();
  assert.deepEqual(blocked, ["stealer-logs", "underground"]);
  assert.ok(rows.some((row) => row.id === "cisa-kev" && row.status === "candidate"));
});
