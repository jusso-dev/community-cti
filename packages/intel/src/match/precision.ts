import { scoreLookalike, type LookalikeSignals } from "./score.js";

export interface LabelledCase {
  id: string;
  label: boolean;
  signals: LookalikeSignals;
}

const strong: LookalikeSignals = {
  editDistance: 1,
  homoglyph: true,
  hasMx: true,
  resolves: true,
  registeredDaysAgo: 5,
  faviconMatch: false,
  parked: false,
};

const weak: LookalikeSignals = {
  editDistance: null,
  homoglyph: false,
  hasMx: false,
  resolves: false,
  registeredDaysAgo: 400,
  faviconMatch: false,
  parked: false,
};

const falsePositive: LookalikeSignals = {
  editDistance: 1,
  homoglyph: false,
  hasMx: true,
  resolves: true,
  registeredDaysAgo: 10,
  faviconMatch: false,
  parked: false,
};

export function precisionFixtures(): LabelledCase[] {
  const cases: LabelledCase[] = [];
  for (let i = 0; i < 30; i++) {
    cases.push({ id: `tp-${i}`, label: true, signals: { ...strong, registeredDaysAgo: i } });
  }
  for (let i = 0; i < 15; i++) {
    cases.push({ id: `tn-${i}`, label: false, signals: { ...weak, registeredDaysAgo: 100 + i } });
  }
  for (let i = 0; i < 5; i++) {
    cases.push({ id: `fp-${i}`, label: false, signals: { ...falsePositive, registeredDaysAgo: i } });
  }
  return cases;
}

export function precisionAt(cases: LabelledCase[], threshold = 40): number {
  let tp = 0;
  let fp = 0;
  for (const item of cases) {
    const score = scoreLookalike(item.signals).confidence;
    const predicted = score >= threshold;
    if (predicted && item.label) tp += 1;
    if (predicted && !item.label) fp += 1;
  }
  return tp + fp === 0 ? 0 : tp / (tp + fp);
}
