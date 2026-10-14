export interface CredentialRecord {
  email: string;
  breachName: string;
  breachDate: string | null;
  dataClasses: string[];
}

const SECRET_KEY = /(password|passwd|^pwd$|^secret$|password_hash|hash_value|passwd_hash)/i;

export function dropPasswordFields(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => dropPasswordFields(item));
  if (!value || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEY.test(key)) continue;
    out[key] = dropPasswordFields(inner);
  }
  return out;
}

export function toCredentialRecords(payload: unknown): CredentialRecord[] {
  const cleaned = dropPasswordFields(payload);
  if (!Array.isArray(cleaned)) return [];
  const records: CredentialRecord[] = [];
  for (const item of cleaned) {
    if (!item || typeof item !== "object") continue;
    const row = item as Record<string, unknown>;
    const email = typeof row.email === "string" ? row.email : "";
    if (!email) continue;
    const breaches = Array.isArray(row.breaches) ? row.breaches : [row];
    for (const breach of breaches) {
      if (!breach || typeof breach !== "object") continue;
      const b = breach as Record<string, unknown>;
      const breachName = stringField(b, "Name", "breachName", "name");
      if (!breachName) continue;
      const dataClasses = Array.isArray(b.DataClasses)
        ? b.DataClasses.filter((entry): entry is string => typeof entry === "string")
        : Array.isArray(b.dataClasses)
          ? b.dataClasses.filter((entry): entry is string => typeof entry === "string")
          : [];
      records.push({
        email,
        breachName,
        breachDate: stringField(b, "BreachDate", "breachDate") || null,
        dataClasses,
      });
    }
  }
  return records;
}

function stringField(row: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    if (typeof row[key] === "string") return row[key] as string;
  }
  return "";
}

export function assertDomainVerified(verified: boolean, domain: string): void {
  if (!verified) throw new Error(`refusing HIBP lookup for unverified domain ${domain}`);
}
