export type Logger = (event: Record<string, unknown>) => void;

/** One JSON line per event. Callers pass counts and ids, never secrets or staff emails. */
export const jsonLogger: Logger = (event) => {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...event }));
};

const EMAIL = /[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+/g;
const URL_CREDENTIALS = /\/\/[^/\s:@]+:[^/\s@]+@/g;
const BEARER = /bearer\s+[^\s"']+/gi;

/** Strip emails, URL credentials and bearer tokens from an error before it is logged or stored. */
export function redact(value: unknown): string {
  const text = value instanceof Error ? `${value.name}: ${value.message}` : String(value);
  return text.replace(URL_CREDENTIALS, "//[redacted]@").replace(BEARER, "Bearer [redacted]").replace(EMAIL, "[email]").slice(0, 500);
}
