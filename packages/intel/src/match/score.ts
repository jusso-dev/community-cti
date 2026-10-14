import type { ConfidenceFactor } from "@community-cti/schema";

export interface LookalikeSignals {
  editDistance: number | null;
  homoglyph: boolean;
  hasMx: boolean;
  resolves: boolean;
  registeredDaysAgo: number | null;
  faviconMatch: boolean;
  parked: boolean;
}

export interface Score {
  confidence: number;
  factors: ConfidenceFactor[];
}

function clamp(value: number): number {
  return Math.max(0, Math.min(100, value));
}

export function scoreLookalike(signals: LookalikeSignals): Score {
  let score = 0;
  const factors: ConfidenceFactor[] = [];
  const add = (code: string, points: number, reason: string) => {
    score += points;
    factors.push({ code, points, reason });
  };
  if (signals.editDistance === 1) add("edit_distance_1", 25, "The name is one change away from your domain.");
  if (signals.homoglyph) add("homoglyph", 25, "The name uses characters that look like yours.");
  if (signals.hasMx) add("has_mx", 15, "The site can send email.");
  if (signals.resolves) add("resolves", 10, "The name points at a website.");
  if (signals.registeredDaysAgo !== null && signals.registeredDaysAgo < 30) {
    add("new_registration", 15, "The name was registered in the last 30 days.");
  }
  if (signals.faviconMatch) add("favicon_match", 30, "The site icon matches yours.");
  if (signals.parked) add("parked", -30, "The page looks parked or for sale.");
  if (factors.length === 0) add("no_signal", 0, "No impersonation signals were found.");
  return { confidence: clamp(score), factors };
}

export function jaroWinkler(left: string, right: string): number {
  if (left === right) return 1;
  const s1 = left.toLowerCase();
  const s2 = right.toLowerCase();
  const maxDist = Math.max(0, Math.floor(Math.max(s1.length, s2.length) / 2) - 1);
  const match1 = new Array<boolean>(s1.length).fill(false);
  const match2 = new Array<boolean>(s2.length).fill(false);
  let matches = 0;
  for (let i = 0; i < s1.length; i++) {
    const start = Math.max(0, i - maxDist);
    const end = Math.min(i + maxDist + 1, s2.length);
    for (let j = start; j < end; j++) {
      if (match2[j] || s1[i] !== s2[j]) continue;
      match1[i] = true;
      match2[j] = true;
      matches += 1;
      break;
    }
  }
  if (matches === 0) return 0;
  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < s1.length; i++) {
    if (!match1[i]) continue;
    while (!match2[k]) k += 1;
    if (s1[i] !== s2[k]) transpositions += 1;
    k += 1;
  }
  transpositions /= 2;
  const jaro = (matches / s1.length + matches / s2.length + (matches - transpositions) / matches) / 3;
  let prefix = 0;
  for (let i = 0; i < Math.min(4, s1.length, s2.length); i++) {
    if (s1[i] !== s2[i]) break;
    prefix += 1;
  }
  return jaro + prefix * 0.1 * (1 - jaro);
}

export function scoreRansomware(input: { victim: string; tenantName: string; aliases?: string[]; secondSignal: boolean }): Score {
  const names = [input.tenantName, ...(input.aliases ?? [])];
  const similarity = Math.max(...names.map((name) => jaroWinkler(input.victim, name)));
  if (similarity < 0.92) {
    return { confidence: 0, factors: [{ code: "name_mismatch", points: 0, reason: "The reported name is not close to your organisation." }] };
  }
  const factors: ConfidenceFactor[] = [{
    code: "name_match",
    points: 60,
    reason: "The reported name is close to your organisation.",
  }];
  if (!input.secondSignal) return { confidence: 60, factors };
  factors.push({ code: "second_signal", points: 20, reason: "A second signal supports the name match." });
  return { confidence: 80, factors };
}
