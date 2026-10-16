import type pg from "pg";
import type { SourceRecord } from "@community-cti/collectors";
import type { Mailer } from "@community-cti/notify";
import type { IntelStore } from "@community-cti/schema";
import type { WorkerConfig } from "./config.js";
import type { FetchLike } from "./http.js";
import type { Logger } from "./log.js";

export interface Dns {
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
  resolveMx(host: string): Promise<Array<{ exchange: string; priority: number }>>;
  resolveTxt(host: string): Promise<string[][]>;
}

/**
 * Everything a job touches. The pool connects as the table owner: the worker
 * is the one privileged, cross-tenant component, so tenant writes still go
 * through withTenant() and name the tenant explicitly in every query.
 */
export interface WorkerContext {
  pool: pg.Pool;
  config: WorkerConfig;
  sources: Map<string, SourceRecord>;
  fetchImpl: FetchLike;
  dns: Dns;
  sleep: (ms: number) => Promise<void>;
  now: () => Date;
  mailer: Mailer;
  log: Logger;
  putRaw: (key: string, body: string) => Promise<void>;
  intel: IntelStore;
}

export interface JobCounts {
  fetched: number;
  inserted: number;
  duplicates: number;
  findings: number;
  errors: number;
  [key: string]: number;
}

export function emptyCounts(): JobCounts {
  return { fetched: 0, inserted: 0, duplicates: 0, findings: 0, errors: 0 };
}

export function isApproved(ctx: Pick<WorkerContext, "sources">, sourceId: string): boolean {
  return ctx.sources.get(sourceId)?.status === "approved";
}
