const SECTORS: Array<{ sector: string; words: string[] }> = [
  { sector: "health", words: ["health", "medical", "clinic", "hospital", "aboriginal medical"] },
  { sector: "community services", words: ["community", "acco", "housing", "family"] },
  { sector: "land management", words: ["land council", "ranger", "native title", "country"] },
  { sector: "government", words: ["government", "council", "shire", "department"] },
];

export function tagSectors(text: string): string[] {
  const haystack = text.toLowerCase();
  return SECTORS.filter((sector) => sector.words.some((word) => haystack.includes(word))).map((sector) => sector.sector);
}
