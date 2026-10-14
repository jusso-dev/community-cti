export const SOURCE_CRONS: Record<string, string> = {
  "cisa-kev": "0 3 * * *",
  nvd: "15 3 * * *",
  epss: "30 3 * * *",
  urlhaus: "0 * * * *",
  openphish: "10 * * * *",
  phishtank: "20 * * * *",
  "acsc-alerts": "0 4 * * *",
  ransomwatch: "30 4 * * *",
  crtsh: "0 5 * * 1",
  certstream: "* * * * *",
  "hibp-domain": "0 6 * * *",
};

export interface JobQueue {
  schedule(name: string, cron: string, data: unknown): Promise<void>;
  work(name: string, handler: (data: unknown) => Promise<void>): Promise<void>;
}

export async function registerSchedules(queue: JobQueue, crons: Record<string, string> = SOURCE_CRONS): Promise<string[]> {
  const names: string[] = [];
  for (const [sourceId, cron] of Object.entries(crons)) {
    const name = `collect-${sourceId}`;
    await queue.schedule(name, cron, { sourceId });
    names.push(name);
  }
  return names;
}

/**
 * PostgreSQL-backed queue via pg-boss. Not started in unit tests.
 * Callers pass a connection string; this function does not embed credentials.
 */
export async function startPgBoss(databaseUrl: string): Promise<JobQueue> {
  const imported = (await import("pg-boss")) as unknown as { default?: new (url: string) => PgBossLike; PgBoss?: new (url: string) => PgBossLike };
  const Ctor = imported.default ?? imported.PgBoss;
  if (!Ctor) throw new Error("pg-boss did not export a constructor");
  const boss = new Ctor(databaseUrl);
  await boss.start();
  return {
    async schedule(name, cron, data) {
      await boss.schedule(name, cron, data);
    },
    async work(name, handler) {
      await boss.work(name, async (job: { data?: unknown } | unknown) => {
        const data = job && typeof job === "object" && "data" in job ? (job as { data?: unknown }).data : job;
        await handler(data);
      });
    },
  };
}

interface PgBossLike {
  start(): Promise<void>;
  schedule(name: string, cron: string, data: unknown): Promise<unknown>;
  work(name: string, handler: (job: unknown) => Promise<void>): Promise<unknown>;
}
