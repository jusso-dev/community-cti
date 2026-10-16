export interface WorkerConfig {
  databaseUrl: string;
  smtpUrl: string | null;
  mailFrom: string;
  emailRegion: string | undefined;
  portalBaseUrl: string;
  rawDir: string;
  threatSieveUrl: string | null;
  threatSieveApiKey: string | null;
  findingMinConfidence: number;
  userAgent: string;
  healthPort: number;
  runOnce: boolean;
  env: string;
  testApprovedSources: string[];
  epssTopN: number;
  /** Empty means every job. */
  workerJobs: string[];
  nvdApiKey: string | null;
  retentionDaysRaw: number;
}

function intFrom(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.trim() === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) throw new Error(`${name} must be a whole number`);
  return parsed;
}

export function parseList(value: string | undefined): string[] {
  return (value ?? "").split(",").map((item) => item.trim()).filter(Boolean);
}

export function loadConfig(env: Record<string, string | undefined>): WorkerConfig {
  const databaseUrl = env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is not set");
  const ctiEnv = env.CTI_ENV?.trim() || "development";
  const testApprovedSources = parseList(env.TEST_APPROVED_SOURCES);
  if (testApprovedSources.length > 0 && ctiEnv === "production") {
    throw new Error("TEST_APPROVED_SOURCES must not be set when CTI_ENV is production");
  }
  const smtpUrl = env.SMTP_URL?.trim() || null;
  const mailFrom = env.MAIL_FROM?.trim() || "";
  if (smtpUrl && !mailFrom) throw new Error("MAIL_FROM is required when SMTP_URL is set");
  const portalBaseUrl = (env.PORTAL_BASE_URL?.trim() || "http://localhost:3000").replace(/\/+$/, "");
  const findingMinConfidence = intFrom(env.FINDING_MIN_CONFIDENCE, 40, "FINDING_MIN_CONFIDENCE");
  if (findingMinConfidence > 100) throw new Error("FINDING_MIN_CONFIDENCE must be 0 to 100");
  return {
    databaseUrl,
    smtpUrl,
    mailFrom: mailFrom || "community-cti@localhost",
    emailRegion: env.EMAIL_REGION?.trim() || undefined,
    portalBaseUrl,
    rawDir: env.RAW_DIR?.trim() || "./data/raw",
    threatSieveUrl: env.THREATSIEVE_TAXII_URL?.trim() || null,
    threatSieveApiKey: env.THREATSIEVE_API_KEY?.trim() || null,
    findingMinConfidence,
    // cyber.gov.au drops requests whose User-Agent carries a comment or URL, so the default is a bare product token.
    userAgent: env.USER_AGENT?.trim() || "community-cti-worker/0.1",
    healthPort: intFrom(env.WORKER_HEALTH_PORT, 8090, "WORKER_HEALTH_PORT"),
    runOnce: env.RUN_ONCE === "1",
    env: ctiEnv,
    testApprovedSources,
    epssTopN: intFrom(env.EPSS_TOP_N, 1000, "EPSS_TOP_N"),
    workerJobs: parseList(env.WORKER_JOBS),
    nvdApiKey: env.NVD_API_KEY?.trim() || null,
    retentionDaysRaw: intFrom(env.RETENTION_DAYS_RAW, 90, "RETENTION_DAYS_RAW"),
  };
}
