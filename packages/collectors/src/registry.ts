import type { Collector } from "./index.js";

/** These source ids stay unimplemented. Do not add collectors for them. */
export const DEFERRED_SOURCE_IDS = ["stealer-logs", "underground"] as const;

const collectors = new Map<string, Collector<unknown>>();

export function registerCollector(collector: Collector<unknown>): void {
  if ((DEFERRED_SOURCE_IDS as readonly string[]).includes(collector.sourceId)) {
    throw new Error(`source ${collector.sourceId} is deferred and must not be registered`);
  }
  collectors.set(collector.sourceId, collector);
}

export function getCollector(sourceId: string): Collector<unknown> | undefined {
  if ((DEFERRED_SOURCE_IDS as readonly string[]).includes(sourceId)) return undefined;
  return collectors.get(sourceId);
}

export const registry = {
  get: getCollector,
  register: registerCollector,
  ids(): string[] {
    return [...collectors.keys()];
  },
};
