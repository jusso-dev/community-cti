const FOLD: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "6": "g",
  "7": "t",
  "8": "b",
  "9": "g",
  "а": "a",
  "е": "e",
  "о": "o",
  "р": "p",
  "с": "c",
  "у": "y",
  "х": "x",
  "і": "i",
};

export function foldHomoglyphs(value: string): string {
  const lower = value.toLowerCase().replaceAll("rn", "m").replaceAll("vv", "w");
  let out = "";
  for (const char of lower) out += FOLD[char] ?? char;
  return out;
}

export function homoglyphVariants(domain: string): string[] {
  const [label, ...rest] = domain.toLowerCase().split(".");
  const suffix = rest.join(".");
  const variants = new Set<string>();
  const reverse = new Map<string, string[]>();
  for (const [from, to] of Object.entries(FOLD)) {
    const list = reverse.get(to) ?? [];
    list.push(from);
    reverse.set(to, list);
  }
  for (let i = 0; i < label.length; i++) {
    const swaps = reverse.get(label[i]!) ?? [];
    for (const swap of swaps) {
      variants.add(`${label.slice(0, i)}${swap}${label.slice(i + 1)}.${suffix}`);
    }
  }
  variants.delete(domain.toLowerCase());
  return [...variants];
}
