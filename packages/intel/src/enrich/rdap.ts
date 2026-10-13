export function registrationAgeDays(rdap: unknown, now: Date): number | null {
  if (!rdap || typeof rdap !== "object") return null;
  const events = (rdap as { events?: Array<{ eventAction?: string; eventDate?: string }> }).events ?? [];
  const registration = events.find((event) => event.eventAction === "registration" && event.eventDate);
  if (!registration?.eventDate) return null;
  const when = new Date(registration.eventDate);
  if (Number.isNaN(when.getTime())) return null;
  return Math.floor((now.getTime() - when.getTime()) / 86_400_000);
}

export async function fetchRdap(domain: string, fetchImpl: (url: string, init?: RequestInit) => Promise<Response>, now: Date): Promise<{ ageDays: number | null; error?: string }> {
  try {
    const response = await fetchImpl(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(5_000) });
    if (!response.ok) return { ageDays: null, error: `rdap ${response.status}` };
    return { ageDays: registrationAgeDays(await response.json(), now) };
  } catch (error) {
    return { ageDays: null, error: error instanceof Error ? error.message : "rdap failed" };
  }
}
