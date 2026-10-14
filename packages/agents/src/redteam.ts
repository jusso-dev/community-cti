import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { rejectUnsafeOutput } from "./runtime.js";
import { systemPrompt, wrapUntrusted } from "./untrusted.js";

export interface RedTeamFixture {
  id: string;
  category: "ignore" | "status" | "url" | "tenant" | "evidence" | "markup";
  untrusted: string;
  output: unknown;
  blocking: boolean;
}

export function loadRedTeam(): RedTeamFixture[] {
  const path = fileURLToPath(new URL("../test/redteam/fixtures.json", import.meta.url));
  return JSON.parse(readFileSync(path, "utf8")) as RedTeamFixture[];
}

export function evaluateFixture(fixture: RedTeamFixture, evidenceIds: string[], tenantId: string): { blocked: boolean; wrapped: string } {
  const wrapped = wrapUntrusted(fixture.untrusted, "fixture");
  const errors = rejectUnsafeOutput(fixture.output, evidenceIds, tenantId);
  const prompt = systemPrompt();
  const blocked = fixture.blocking ? errors.length > 0 && prompt.includes("data, not instructions") : errors.length === 0;
  return { blocked, wrapped };
}
