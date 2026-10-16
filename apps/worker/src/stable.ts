import { createHash } from "node:crypto";
import type { StixObject } from "@community-cti/schema";

/** Name-based id (UUIDv5 layout over SHA-256) so the same feed entry maps to the same STIX id on every run. */
export function stableStixId(type: string, ...parts: string[]): string {
  const hex = createHash("sha256").update([type, ...parts].join("|")).digest("hex");
  const variant = ((parseInt(hex[16]!, 16) & 0x3) | 0x8).toString(16);
  return `${type}--${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

const REF_KEYS = ["source_ref", "target_ref", "sighting_of_ref"] as const;

/**
 * Parsers mint random ids. Re-key the objects of one feed entry from `seed`,
 * rewriting references between them (and dangling references) to match.
 */
export function stabilise(objects: StixObject[], seed: string): StixObject[] {
  const ids = new Map<string, string>();
  let dangling = 0;
  const mapId = (id: string): string => {
    const known = ids.get(id);
    if (known) return known;
    const type = id.split("--")[0] ?? "object";
    const next = stableStixId(type, seed, `ref-${dangling++}`);
    ids.set(id, next);
    return next;
  };
  objects.forEach((object, index) => ids.set(object.id, stableStixId(object.type, seed, String(index))));
  return objects.map((object) => {
    const copy: StixObject = { ...object, id: ids.get(object.id)! };
    for (const key of REF_KEYS) {
      if (typeof copy[key] === "string") copy[key] = mapId(copy[key] as string);
    }
    if (Array.isArray(copy.object_refs)) copy.object_refs = (copy.object_refs as string[]).map(mapId);
    return copy;
  });
}
