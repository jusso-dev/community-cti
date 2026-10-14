function syllables(word: string): number {
  const cleaned = word.toLowerCase().replace(/[^a-z]/g, "");
  if (!cleaned) return 1;
  const groups = cleaned.match(/[aeiouy]+/g);
  let count = groups?.length ?? 1;
  if (cleaned.endsWith("e") && count > 1) count -= 1;
  return Math.max(1, count);
}

/** Flesch-Kincaid grade. Year 8 is about grade 8. */
export function fleschKincaidGrade(text: string): number {
  const sentences = text.split(/[.!?]+/).map((part) => part.trim()).filter(Boolean);
  const words = text.split(/\s+/).map((part) => part.trim()).filter(Boolean);
  if (sentences.length === 0 || words.length === 0) return 0;
  const syllableCount = words.reduce((sum, word) => sum + syllables(word), 0);
  return 0.39 * (words.length / sentences.length) + 11.8 * (syllableCount / words.length) - 15.59;
}

export function wordCount(text: string): number {
  return text.split(/\s+/).filter(Boolean).length;
}
