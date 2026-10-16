import { SinkMailer } from "@community-cti/notify";
import type pg from "pg";
import { loadConfig } from "./config.js";
import type { WorkerContext } from "./context.js";
import { effectiveSources, loadSourcesDoc } from "./governance.js";

export const sourceRows = loadSourcesDoc();

/** Offline context: no network, empty DNS, fixed clock unless overridden. */
export function fakeCtx(overrides: Partial<WorkerContext> = {}, env: Record<string, string> = {}): WorkerContext {
  return {
    pool: {} as pg.Pool,
    config: loadConfig({ DATABASE_URL: "postgres://unused", ...env }),
    sources: effectiveSources(sourceRows, [], "development"),
    fetchImpl: async () => {
      throw new Error("network is not allowed in unit tests");
    },
    dns: { resolve4: async () => [], resolve6: async () => [], resolveMx: async () => [], resolveTxt: async () => [] },
    sleep: async () => {},
    now: () => new Date("2026-10-16T00:00:00.000Z"),
    mailer: new SinkMailer(),
    log: () => {},
    putRaw: async () => {},
    intel: { upsert: async () => {}, getById: async () => null, getRelated: async () => [], listVisible: async () => [] },
    ...overrides,
  };
}

export function dnsError(code: string): Error {
  return Object.assign(new Error(code), { code });
}
