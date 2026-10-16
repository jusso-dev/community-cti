import { randomUUID } from "node:crypto";
import type pg from "pg";
import { audit, withTenant } from "@community-cti/db";
import {
  validateFinding,
  type ConfidenceFactor,
  type Finding,
  type FindingKind,
  type IntelStore,
  type Provenance,
  type StixObject,
  type TlpMarking,
} from "@community-cti/schema";

export interface EvidenceDraft {
  label: string;
  url: string | null;
  objectKey: string | null;
  sourceId: string;
  licence: string;
  tlp: TlpMarking;
  collectedAt: string;
}

export interface FindingDraft {
  tenantId: string;
  kind: FindingKind;
  dedupeKey: string;
  title: string;
  summary: string;
  confidence: number;
  factors: ConfidenceFactor[];
  provenance: Provenance[];
  stixRefs: string[];
  /** Tenant-scoped STIX the finding points at, stored before the finding. */
  stixObjects: StixObject[];
  evidence: EvidenceDraft[];
}

export type PersistOutcome = "inserted" | "updated" | "unchanged";

/** Throws when the draft would break the finding contract (provenance, factors, score range). */
export function draftToFinding(draft: FindingDraft, id: string): Finding {
  const finding: Finding = {
    id,
    tenantId: draft.tenantId,
    kind: draft.kind,
    title: draft.title,
    plainEnglishSummary: draft.summary,
    confidence: draft.confidence,
    provenance: draft.provenance,
    status: "open",
    stixRefs: draft.stixRefs,
    confidenceFactors: draft.factors,
  };
  const errors = validateFinding(finding);
  if (draft.factors.length === 0) errors.push("at least one confidence factor is required");
  if (!draft.dedupeKey) errors.push("dedupe key is required");
  if (errors.length > 0) throw new Error(`invalid finding: ${errors.join("; ")}`);
  return finding;
}

export async function findingStatus(db: pg.Pool, tenantId: string, dedupeKey: string): Promise<string | null> {
  const result = await db.query("select status from findings where tenant_id = $1 and dedupe_key = $2", [tenantId, dedupeKey]);
  return result.rows[0] ? String(result.rows[0].status) : null;
}

/**
 * Insert a finding once per (tenant, dedupe key). A repeat only rescores an
 * open or acknowledged finding when the confidence moved. Dismissed findings stay dismissed.
 */
export async function persistFinding(pool: pg.Pool, intel: IntelStore, draft: FindingDraft): Promise<{ id: string | null; outcome: PersistOutcome }> {
  const finding = draftToFinding(draft, randomUUID());
  for (const object of draft.stixObjects) await intel.upsert(object, draft.tenantId);
  return withTenant(pool, draft.tenantId, async (client) => {
    const result = await client.query(
      `insert into findings (id, tenant_id, kind, title, plain_english_summary, confidence, status, confidence_factors, stix_refs, provenance, dedupe_key)
       values ($1, $2, $3, $4, $5, $6, 'open', $7::jsonb, $8::jsonb, $9::jsonb, $10)
       on conflict (tenant_id, dedupe_key) where dedupe_key is not null do update
         set confidence = excluded.confidence,
             confidence_factors = excluded.confidence_factors,
             updated_at = now()
         where findings.confidence <> excluded.confidence and findings.status in ('open', 'acknowledged')
       returning id, (xmax = 0) as inserted`,
      [
        finding.id,
        draft.tenantId,
        draft.kind,
        draft.title,
        draft.summary,
        draft.confidence,
        JSON.stringify(draft.factors),
        JSON.stringify(draft.stixRefs),
        JSON.stringify(draft.provenance),
        draft.dedupeKey,
      ],
    );
    const row = result.rows[0];
    if (!row) return { id: null, outcome: "unchanged" as const };
    const id = String(row.id);
    if (!row.inserted) {
      await audit(client, { tenantId: draft.tenantId, actorId: null, action: "finding.rescored", targetType: "finding", targetId: id, metadata: { confidence: draft.confidence } });
      return { id, outcome: "updated" as const };
    }
    for (const item of draft.evidence) {
      await client.query(
        `insert into finding_evidence (id, tenant_id, finding_id, label, object_key, url, collected_at, source_id, licence, tlp)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [randomUUID(), draft.tenantId, id, item.label, item.objectKey, item.url, item.collectedAt, item.sourceId, item.licence, item.tlp],
      );
    }
    await audit(client, {
      tenantId: draft.tenantId,
      actorId: null,
      action: "finding.created",
      targetType: "finding",
      targetId: id,
      metadata: { kind: draft.kind, confidence: draft.confidence, dedupeKey: draft.dedupeKey },
    });
    return { id, outcome: "inserted" as const };
  });
}
