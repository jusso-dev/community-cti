import { createFinding, type ConfidenceFactor, type Finding, type Provenance } from "@community-cti/schema";

export interface LookalikeSignals {
  editDistance1: boolean;
  homoglyph: boolean;
  hasMx: boolean;
  resolves: boolean;
  registeredUnder30Days: boolean;
  faviconMatch: boolean;
  parked: boolean;
}

function add(factors: ConfidenceFactor[], on: boolean, code: string, points: number, reason: string) {
  if (on) factors.push({ code, points, reason });
}

export function scoreLookalike(signals: LookalikeSignals): { confidence: number; factors: ConfidenceFactor[] } {
  const factors: ConfidenceFactor[] = [];
  add(factors, signals.editDistance1, "edit_distance", 25, "The name is one change away from yours");
  add(factors, signals.homoglyph, "homoglyph", 25, "The name uses lookalike characters");
  add(factors, signals.hasMx, "mx", 15, "The name can receive email");
  add(factors, signals.resolves, "resolves", 10, "The name resolves on the internet");
  add(factors, signals.registeredUnder30Days, "young", 15, "The name was registered in the last 30 days");
  add(factors, signals.faviconMatch, "favicon", 30, "The site icon matches yours");
  add(factors, signals.parked, "parked", -30, "The page looks parked or empty");
  const raw = factors.reduce((sum, factor) => sum + factor.points, 0);
  const confidence = Math.max(0, Math.min(100, raw));
  if (factors.length === 0) factors.push({ code: "none", points: 0, reason: "No lookalike signals" });
  return { confidence, factors };
}

export function scoreRansomware(similarity: number, secondSignal: boolean): { confidence: number; factors: ConfidenceFactor[] } {
  if (similarity < 0.92) {
    return { confidence: 0, factors: [{ code: "name_mismatch", points: 0, reason: "The victim name is not close to yours" }] };
  }
  const factors: ConfidenceFactor[] = [{ code: "name_match", points: 55, reason: "The victim name is close to your organisation" }];
  let confidence = 55;
  if (secondSignal) {
    factors.push({ code: "second_signal", points: 20, reason: "Another signal supports this match" });
    confidence += 20;
  } else {
    confidence = Math.min(confidence, 69);
  }
  return { confidence, factors };
}

export function jaroWinkler(left: string, right: string): number {
  if (left === right) return 1;
  if (!left.length || !right.length) return 0;
  const a = left.toLowerCase();
  const b = right.toLowerCase();
  const window = Math.max(0, Math.floor(Math.max(a.length, b.length) / 2) - 1);
  const matchedA = new Array(a.length).fill(false);
  const matchedB = new Array(b.length).fill(false);
  let matches = 0;
  for (let i = 0; i < a.length; i++) {
    const start = Math.max(0, i - window);
    const end = Math.min(i + window + 1, b.length);
    for (let j = start; j < end; j++) {
      if (matchedB[j] || a[i] !== b[j]) continue;
      matchedA[i] = true;
      matchedB[j] = true;
      matches += 1;
      break;
    }
  }
  if (matches === 0) return 0;
  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < a.length; i++) {
    if (!matchedA[i]) continue;
    while (!matchedB[k]) k += 1;
    if (a[i] !== b[k]) transpositions += 1;
    k += 1;
  }
  const jaro = (matches / a.length + matches / b.length + (matches - transpositions / 2) / matches) / 3;
  let prefix = 0;
  for (; prefix < Math.min(4, a.length, b.length) && a[prefix] === b[prefix]; prefix += 1);
  return jaro + prefix * 0.1 * (1 - jaro);
}

export function scoreRansomwareName(names: string[], victim: string, secondSignal: boolean) {
  const similarity = Math.max(...names.map((name) => jaroWinkler(name, victim)));
  return scoreRansomware(similarity, secondSignal);
}

export interface LabelledLookalike {
  id: string;
  label: "true" | "false";
  signals: LookalikeSignals;
}

export function labelledLookalikes(): LabelledLookalike[] {
  const strong: LookalikeSignals = {
    editDistance1: true, homoglyph: false, hasMx: true, resolves: true,
    registeredUnder30Days: true, faviconMatch: false, parked: false,
  };
  const homoglyph: LookalikeSignals = {
    editDistance1: false, homoglyph: true, hasMx: true, resolves: true,
    registeredUnder30Days: false, faviconMatch: false, parked: false,
  };
  const sister: LookalikeSignals = {
    editDistance1: true, homoglyph: false, hasMx: true, resolves: true,
    registeredUnder30Days: false, faviconMatch: false, parked: false,
  };
  const quiet: LookalikeSignals[] = [
    { editDistance1: false, homoglyph: false, hasMx: false, resolves: true, registeredUnder30Days: false, faviconMatch: false, parked: false },
    { editDistance1: true, homoglyph: false, hasMx: false, resolves: true, registeredUnder30Days: false, faviconMatch: false, parked: true },
    { editDistance1: false, homoglyph: false, hasMx: true, resolves: false, registeredUnder30Days: false, faviconMatch: false, parked: false },
  ];
  const cases: LabelledLookalike[] = [];
  for (let i = 0; i < 16; i++) cases.push({ id: `tp-strong-${i}`, label: "true", signals: strong });
  for (let i = 0; i < 16; i++) cases.push({ id: `tp-homo-${i}`, label: "true", signals: homoglyph });
  for (let i = 0; i < 6; i++) cases.push({ id: `fp-sister-${i}`, label: "false", signals: sister });
  for (let i = 0; i < 12; i++) cases.push({ id: `fp-quiet-${i}`, label: "false", signals: quiet[i % quiet.length] ?? quiet[0]! });
  return cases;
}

export const ALERT_THRESHOLD = 40;

/** Fixed weights. Review can read them. Nothing in this package writes them back. */
export const LOOKALIKE_WEIGHTS = {
  edit_distance: 25,
  homoglyph: 25,
  mx: 15,
  resolves: 10,
  young: 15,
  favicon: 30,
  parked: -30,
} as const;

export function alertPrecision(cases: LabelledLookalike[], threshold = ALERT_THRESHOLD): number {
  let tp = 0;
  let fp = 0;
  for (const item of cases) {
    const scored = scoreLookalike(item.signals);
    if (scored.confidence < threshold) continue;
    if (item.label === "true") tp += 1;
    else fp += 1;
  }
  return tp + fp === 0 ? 0 : tp / (tp + fp);
}

export function findingFromLookalike(input: {
  id: string;
  tenantId: string;
  title: string;
  summary: string;
  signals: LookalikeSignals;
  provenance: Provenance[];
  stixRefs?: string[];
}): Finding {
  const scored = scoreLookalike(input.signals);
  return createFinding({
    id: input.id,
    tenantId: input.tenantId,
    kind: "lookalike_domain",
    title: input.title,
    plainEnglishSummary: input.summary,
    confidence: scored.confidence,
    confidenceFactors: scored.factors,
    provenance: input.provenance,
    stixRefs: input.stixRefs ?? [],
  });
}
