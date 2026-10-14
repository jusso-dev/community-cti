const RULES: Array<[string, RegExp]> = [
  ["health", /health|medical|clinic|hospital|\bams\b/i],
  ["community services", /community|acco|aboriginal|indigenous/i],
  ["land management", /land council|ranger|native title/i],
  ["government", /government|council|shire/i],
];

export function tagSector(text: string): string[] {
  return RULES.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
}
