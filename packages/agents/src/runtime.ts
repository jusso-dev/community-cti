import { createHash } from "node:crypto";
import { assertAustralianRegion } from "@community-cti/schema";
import { systemPrompt } from "./untrusted.js";

export interface Tool {
  name: string;
  readOnly: true;
  run: (input: unknown, ctx: AgentContext) => Promise<unknown>;
}

export interface AgentContext {
  tenantId: string;
  evidenceIds: string[];
}

export interface ModelRequest {
  system: string;
  user: string;
}

export interface ModelResponse {
  text: string;
  tokensIn: number;
  tokensOut: number;
  costAud: number;
}

export interface ModelProvider {
  region: string;
  name: string;
  complete(request: ModelRequest): Promise<ModelResponse>;
}

export interface AgentRunLog {
  tenantId: string;
  role: string;
  model: string;
  tokensIn: number;
  tokensOut: number;
  costAud: number;
  durationMs: number;
  outputHash: string;
  status: "ok" | "failed" | "stopped";
}

export interface Budget {
  monthlyAud: number;
  spentAud: number;
}

const tools = new Map<string, Tool>();

export function registerTool(tool: Tool): void {
  if (tool.readOnly !== true) throw new Error("tools must be read-only");
  tools.set(tool.name, tool);
}

export function clearTools(): void {
  tools.clear();
}

export function capConfidence(deterministic: number, proposed: number): { confidence: number; needsReview: boolean } {
  const delta = proposed - deterministic;
  if (Math.abs(delta) > 30) {
    const capped = deterministic + Math.sign(delta) * 30;
    return { confidence: Math.max(0, Math.min(100, capped)), needsReview: true };
  }
  return { confidence: Math.max(0, Math.min(100, proposed)), needsReview: false };
}

export interface RunResult {
  status: "ok" | "failed" | "stopped";
  output: unknown;
  log: AgentRunLog;
  notifyOperator: boolean;
}

export async function runAgent(options: {
  role: string;
  tenantId: string;
  input: string;
  evidenceIds: string[];
  budget: Budget;
  model: ModelProvider;
  validate: (output: unknown, evidenceIds: string[]) => string[];
  cultural?: boolean;
}): Promise<RunResult> {
  assertAustralianRegion(options.model.region);
  if (options.cultural) throw new Error("cultural data must not be sent to a model provider");
  const started = Date.now();
  const base = {
    tenantId: options.tenantId,
    role: options.role,
    model: options.model.name,
    tokensIn: 0,
    tokensOut: 0,
    costAud: 0,
    durationMs: 0,
    outputHash: "",
    status: "stopped" as const,
  };
  if (options.budget.spentAud >= options.budget.monthlyAud) {
    return {
      status: "stopped",
      output: null,
      notifyOperator: true,
      log: { ...base, durationMs: Date.now() - started, outputHash: "budget" },
    };
  }
  let lastErrors: string[] = [];
  let response: ModelResponse | null = null;
  let parsed: unknown = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    response = await options.model.complete({
      system: systemPrompt(),
      user: options.input,
    });
    base.tokensIn += response.tokensIn;
    base.tokensOut += response.tokensOut;
    base.costAud += response.costAud;
    try {
      parsed = JSON.parse(response.text);
    } catch {
      lastErrors = ["output was not json"];
      continue;
    }
    lastErrors = options.validate(parsed, options.evidenceIds);
    if (lastErrors.length === 0) break;
  }
  const outputHash = createHash("sha256").update(response?.text ?? "").digest("hex");
  const durationMs = Date.now() - started;
  if (lastErrors.length > 0) {
    return {
      status: "failed",
      output: null,
      notifyOperator: false,
      log: { ...base, durationMs, outputHash, status: "failed" },
    };
  }
  return {
    status: "ok",
    output: parsed,
    notifyOperator: false,
    log: { ...base, durationMs, outputHash, status: "ok" },
  };
}

export function rejectUnsafeOutput(output: unknown, evidenceIds: string[], tenantId: string): string[] {
  if (!output || typeof output !== "object") return ["output must be an object"];
  const record = output as Record<string, unknown>;
  const errors: string[] = [];
  if ("status" in record) errors.push("output tried to change status");
  if (typeof record.tenantId === "string" && record.tenantId !== tenantId) errors.push("cross-tenant output");
  const refs = [
    ...(Array.isArray(record.supporting) ? record.supporting : []),
    ...(Array.isArray(record.contradicting) ? record.contradicting : []),
    ...(Array.isArray(record.evidence) ? record.evidence : []),
  ];
  for (const ref of refs) {
    const id = typeof ref === "string" ? ref : (ref as { id?: string })?.id;
    if (id && !evidenceIds.includes(id)) errors.push(`unknown evidence ${id}`);
  }
  if (Array.isArray(record.toolCalls)) {
    for (const call of record.toolCalls) {
      const name = (call as { name?: string }).name ?? "";
      const tool = tools.get(name);
      if (!tool || tool.readOnly !== true) errors.push(`tool misuse ${name}`);
      const url = (call as { url?: string }).url;
      if (url) errors.push("url tool refused");
    }
  }
  if (typeof record.url === "string") errors.push("url tool refused");
  return errors;
}
