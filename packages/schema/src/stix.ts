import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import type { TlpMarking, StixObject } from "./index.js";

const require = createRequire(import.meta.url);

interface ValidateFn {
  (data: unknown): boolean;
  errors?: Array<{ instancePath?: string; message?: string }> | null;
}

interface AjvLike {
  addSchema(schema: object): void;
  getSchema(id: string): ValidateFn | undefined;
  compile(schema: object): ValidateFn;
}

export const TLP_MARKING: Record<TlpMarking, string> = {
  "TLP:CLEAR": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
  "TLP:GREEN": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
  "TLP:AMBER": "marking-definition--55d920b0-5e8b-4f79-9ee9-f01b8d7e5f31",
  "TLP:AMBER+STRICT": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
  "TLP:RED": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
};

export const COLLECTOR_IDENTITY = "identity--11111111-1111-4111-8111-111111111111";

const SCHEMA_FILES: Record<string, string> = {
  indicator: "sdos/indicator.json",
  vulnerability: "sdos/vulnerability.json",
  "domain-name": "observables/domain-name.json",
  url: "observables/url.json",
  infrastructure: "sdos/infrastructure.json",
  relationship: "sros/relationship.json",
  sighting: "sros/sighting.json",
  note: "sdos/note.json",
  opinion: "sdos/opinion.json",
  report: "sdos/report.json",
  "observed-data": "sdos/observed-data.json",
  identity: "sdos/identity.json",
};

export interface SourceRef {
  sourceId: string;
  url?: string;
  licence: string;
  tlp: TlpMarking;
  externalId?: string;
}

let validator: Map<string, ValidateFn> | undefined;

function schemaRoot(): string {
  return fileURLToPath(new URL("../stix-schemas", import.meta.url));
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else if (name.endsWith(".json")) out.push(path);
  }
  return out;
}

function buildValidator(): Map<string, ValidateFn> {
  const Ajv2020 = require("ajv/dist/2020") as new (opts?: object) => AjvLike;
  const addFormats = require("ajv-formats") as (ajv: AjvLike) => void;
  const ajv = new Ajv2020({
    strict: false,
    allErrors: true,
    validateSchema: false,
    unicodeRegExp: false,
  });
  addFormats(ajv);
  const root = schemaRoot();
  for (const path of walk(root)) {
    const schema = JSON.parse(readFileSync(path, "utf8")) as { $id?: string };
    if (schema.$id) ajv.addSchema(schema);
  }
  const compiled = new Map<string, ValidateFn>();
  for (const [type, rel] of Object.entries(SCHEMA_FILES)) {
    const schema = JSON.parse(readFileSync(join(root, rel), "utf8")) as { $id: string };
    const check = ajv.getSchema(schema.$id) ?? ajv.compile(schema);
    compiled.set(type, check);
  }
  return compiled;
}

function validators() {
  validator ??= buildValidator();
  return validator;
}

export function validateStix(obj: StixObject): string[] {
  const errors: string[] = [];
  const check = validators().get(obj.type);
  if (!check) errors.push(`no STIX schema registered for ${obj.type}`);
  else if (!check(obj)) {
    for (const err of check.errors ?? []) errors.push(`${err.instancePath || "/"} ${err.message ?? "invalid"}`);
  }
  if (!obj.object_marking_refs || obj.object_marking_refs.length === 0) {
    errors.push("object_marking_refs is required");
  }
  if (!obj.external_references || obj.external_references.length === 0) {
    errors.push("external_references is required");
  }
  if (obj.confidence !== undefined && (!Number.isInteger(obj.confidence) || obj.confidence < 0 || obj.confidence > 100)) {
    errors.push("confidence must be an integer from 0 to 100");
  }
  return errors;
}

function stamp(now?: string): string {
  return now ?? new Date().toISOString();
}

function externalReferences(source: SourceRef): Array<Record<string, string>> {
  const refs: Array<Record<string, string>> = [];
  if (source.externalId && source.sourceId === "cve") {
    refs.push({ source_name: "cve", external_id: source.externalId });
  }
  const extra: Record<string, string> = {
    source_name: source.sourceId === "cve" ? "cisa-kev" : source.sourceId,
    description: source.licence,
  };
  if (source.url) extra.url = source.url;
  if (source.externalId && source.sourceId !== "cve") extra.external_id = source.externalId;
  refs.push(extra);
  return refs;
}

export function stixBase(type: string, source: SourceRef, confidence?: number, now?: string, id?: string): StixObject {
  const at = stamp(now);
  const obj: StixObject = {
    type,
    spec_version: "2.1",
    id: id ?? `${type}--${randomUUID()}`,
    created: at,
    modified: at,
    created_by_ref: COLLECTOR_IDENTITY,
    object_marking_refs: [TLP_MARKING[source.tlp]],
    external_references: externalReferences(source),
  };
  if (confidence !== undefined) obj.confidence = confidence;
  return obj;
}

export function buildIndicator(input: {
  pattern: string;
  name?: string;
  confidence: number;
  source: SourceRef;
  validFrom?: string;
  now?: string;
  id?: string;
}): StixObject {
  const at = stamp(input.now);
  return {
    ...stixBase("indicator", input.source, input.confidence, at, input.id),
    name: input.name ?? input.pattern,
    pattern: input.pattern,
    pattern_type: "stix",
    valid_from: input.validFrom ?? at,
    indicator_types: ["malicious-activity"],
  };
}

export function buildVulnerability(input: {
  cve: string;
  confidence: number;
  source: SourceRef;
  epss?: number;
  kev?: boolean;
  now?: string;
  id?: string;
}): StixObject {
  const obj = stixBase("vulnerability", input.source, input.confidence, input.now, input.id);
  const refs = obj.external_references ?? [];
  obj.external_references = [{ source_name: "cve", external_id: input.cve }, ...refs];
  return {
    ...obj,
    name: input.cve,
    ...(input.epss !== undefined ? { x_epss_score: input.epss } : {}),
    ...(input.kev !== undefined ? { x_kev: input.kev } : {}),
  };
}

export function buildDomainName(input: { value: string; source: SourceRef; now?: string; id?: string }): StixObject {
  return { ...stixBase("domain-name", input.source, undefined, input.now, input.id), value: input.value };
}

export function buildUrl(input: { value: string; source: SourceRef; now?: string; id?: string }): StixObject {
  return { ...stixBase("url", input.source, undefined, input.now, input.id), value: input.value };
}

export function buildInfrastructure(input: { name: string; source: SourceRef; confidence?: number; now?: string; id?: string }): StixObject {
  return { ...stixBase("infrastructure", input.source, input.confidence, input.now, input.id), name: input.name };
}

export function buildRelationship(input: {
  sourceRef: string;
  targetRef: string;
  relationshipType: string;
  source: SourceRef;
  now?: string;
  id?: string;
}): StixObject {
  return {
    ...stixBase("relationship", input.source, undefined, input.now, input.id),
    relationship_type: input.relationshipType,
    source_ref: input.sourceRef,
    target_ref: input.targetRef,
  };
}

export function buildSighting(input: { sightingOfRef: string; source: SourceRef; now?: string; id?: string }): StixObject {
  return { ...stixBase("sighting", input.source, undefined, input.now, input.id), sighting_of_ref: input.sightingOfRef };
}

export function buildNote(input: { content: string; objectRefs: string[]; source: SourceRef; now?: string; id?: string }): StixObject {
  return {
    ...stixBase("note", input.source, undefined, input.now, input.id),
    content: input.content,
    object_refs: input.objectRefs,
    abstract: "Enrichment note",
  };
}

export function buildOpinion(input: {
  opinion: "strongly-disagree" | "disagree" | "neutral" | "agree" | "strongly-agree";
  objectRefs: string[];
  explanation: string;
  source: SourceRef;
  now?: string;
  id?: string;
}): StixObject {
  return {
    ...stixBase("opinion", input.source, undefined, input.now, input.id),
    opinion: input.opinion,
    object_refs: input.objectRefs,
    explanation: input.explanation,
  };
}

export function buildReport(input: {
  name: string;
  objectRefs: string[];
  published?: string;
  source: SourceRef;
  extra?: Record<string, string>;
  now?: string;
  id?: string;
}): StixObject {
  const at = stamp(input.now);
  return {
    ...stixBase("report", input.source, undefined, at, input.id),
    name: input.name,
    published: input.published ?? at,
    object_refs: input.objectRefs,
    report_types: ["threat-report"],
    ...input.extra,
  };
}

export function buildObservedData(input: {
  objectRefs: string[];
  source: SourceRef;
  now?: string;
  id?: string;
}): StixObject {
  const at = stamp(input.now);
  return {
    ...stixBase("observed-data", input.source, undefined, at, input.id),
    first_observed: at,
    last_observed: at,
    number_observed: 1,
    object_refs: input.objectRefs,
  };
}

export function buildIdentity(input: { name: string; source: SourceRef; now?: string; id?: string }): StixObject {
  return {
    ...stixBase("identity", input.source, undefined, input.now, input.id),
    name: input.name,
    identity_class: "organization",
  };
}

/** In-memory graph used when OpenSearch and Postgres are not required. */
export class MemoryIntelStore {
  private objects = new Map<string, { obj: StixObject; tenantId: string | null }>();

  async upsert(obj: StixObject, tenantId: string | null): Promise<void> {
    const errors = validateStix(obj);
    if (errors.length > 0) throw new Error(errors.join("; "));
    this.objects.set(obj.id, { obj, tenantId });
  }

  async get(id: string, tenantId: string | null): Promise<StixObject | null> {
    const row = this.objects.get(id);
    if (!row) return null;
    if (row.tenantId !== null && row.tenantId !== tenantId) return null;
    return row.obj;
  }

  async related(id: string, depth: number, tenantId: string | null): Promise<StixObject[]> {
    const seen = new Set<string>([id]);
    let edge = [id];
    for (let i = 0; i < depth; i++) {
      const next: string[] = [];
      for (const row of this.objects.values()) {
        if (row.tenantId !== null && row.tenantId !== tenantId) continue;
        const source = row.obj.source_ref;
        const target = row.obj.target_ref;
        if (typeof source === "string" && typeof target === "string" && (edge.includes(source) || edge.includes(target))) {
          const other = edge.includes(source) ? target : source;
          if (!seen.has(other)) {
            seen.add(other);
            next.push(other);
          }
          if (!seen.has(row.obj.id)) {
            seen.add(row.obj.id);
            next.push(row.obj.id);
          }
        }
      }
      edge = next;
    }
    const out: StixObject[] = [];
    for (const key of seen) {
      if (key === id) continue;
      const obj = await this.get(key, tenantId);
      if (obj) out.push(obj);
    }
    return out;
  }

  async search(aliasTenantId: string, query: string): Promise<StixObject[]> {
    const needle = query.toLowerCase();
    const out: StixObject[] = [];
    for (const row of this.objects.values()) {
      if (row.tenantId !== null && row.tenantId !== aliasTenantId) continue;
      if (JSON.stringify(row.obj).toLowerCase().includes(needle)) out.push(row.obj);
    }
    return out;
  }
}

export function aliasName(tenantId: string): string {
  return `stix-${tenantId}`;
}
