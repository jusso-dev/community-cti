import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import type { TlpMarking } from "./model.js";

export const PLATFORM_IDENTITY = "identity--c1c0e000-0000-4000-8000-000000000003";
export const INVESTIGATOR_IDENTITY = "identity--b1c0e000-0000-4000-8000-000000000002";
export const COMMUNITY_IDENTITY = "identity--a1c0e000-0000-4000-8000-000000000001";

/** OASIS TLP 2.0 marking-definition identifiers. */
export const TLP_MARKING: Record<TlpMarking, string> = {
  "TLP:CLEAR": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
  "TLP:GREEN": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
  "TLP:AMBER": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
  "TLP:AMBER+STRICT": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
  "TLP:RED": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
};

export interface ExternalRef {
  source_name: string;
  url?: string;
  external_id?: string;
  description?: string;
}

export interface StixObject {
  type: string;
  spec_version: "2.1";
  id: string;
  created?: string;
  modified?: string;
  created_by_ref?: string;
  confidence?: number;
  object_marking_refs?: string[];
  external_references?: ExternalRef[];
  [key: string]: unknown;
}

export interface StixBuildContext {
  sourceId: string;
  licence: string;
  tlp?: TlpMarking;
  sourceUrl?: string;
  externalId?: string;
  collectedAt?: Date;
  confidence?: number;
  id?: string;
  createdByRef?: string;
}

export function stixTime(date: Date = new Date()): string {
  return date.toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

export function stixId(type: string, id?: string): string {
  return id ?? `${type}--${randomUUID()}`;
}

function baseSdo(type: string, ctx: StixBuildContext, extra: Record<string, unknown>): StixObject {
  const when = stixTime(ctx.collectedAt ?? new Date());
  const tlp = ctx.tlp ?? "TLP:CLEAR";
  const confidence = ctx.confidence ?? 50;
  if (!Number.isInteger(confidence) || confidence < 0 || confidence > 100) {
    throw new Error("confidence must be an integer from 0 to 100");
  }
  const external: ExternalRef = {
    source_name: ctx.sourceId,
    description: ctx.licence,
  };
  if (ctx.sourceUrl) external.url = ctx.sourceUrl;
  const refs = [external];
  if (ctx.externalId?.startsWith("CVE-")) {
    refs.push({ source_name: "cve", external_id: ctx.externalId });
  } else if (ctx.externalId) {
    external.external_id = ctx.externalId;
  }
  return {
    type,
    spec_version: "2.1",
    id: stixId(type, ctx.id),
    created: when,
    modified: when,
    created_by_ref: ctx.createdByRef ?? PLATFORM_IDENTITY,
    confidence,
    object_marking_refs: [TLP_MARKING[tlp]],
    external_references: refs,
    ...extra,
  };
}

function baseSco(type: string, ctx: StixBuildContext, extra: Record<string, unknown>): StixObject {
  const tlp = ctx.tlp ?? "TLP:CLEAR";
  const confidence = ctx.confidence ?? 50;
  return {
    type,
    spec_version: "2.1",
    id: stixId(type, ctx.id),
    object_marking_refs: [TLP_MARKING[tlp]],
    created_by_ref: ctx.createdByRef ?? PLATFORM_IDENTITY,
    confidence,
    external_references: [
      {
        source_name: ctx.sourceId,
        description: ctx.licence,
        ...(ctx.sourceUrl ? { url: ctx.sourceUrl } : {}),
      },
    ],
    ...extra,
  };
}

export function buildIndicator(
  ctx: StixBuildContext & { pattern: string; name: string; validFrom?: string },
): StixObject {
  return baseSdo("indicator", ctx, {
    name: ctx.name,
    pattern: ctx.pattern,
    pattern_type: "stix",
    pattern_version: "2.1",
    valid_from: ctx.validFrom ?? stixTime(ctx.collectedAt ?? new Date()),
    indicator_types: ["malicious-activity"],
  });
}

export function buildVulnerability(
  ctx: StixBuildContext & { name: string; description?: string; cve?: string; extra?: Record<string, unknown> },
): StixObject {
  return baseSdo("vulnerability", { ...ctx, externalId: ctx.cve ?? ctx.externalId }, {
    name: ctx.name,
    ...(ctx.description ? { description: ctx.description } : {}),
    ...(ctx.extra ?? {}),
  });
}

export function buildDomainName(ctx: StixBuildContext & { value: string; extra?: Record<string, unknown> }): StixObject {
  return baseSco("domain-name", ctx, { value: ctx.value, ...(ctx.extra ?? {}) });
}

export function buildUrl(ctx: StixBuildContext & { value: string; extra?: Record<string, unknown> }): StixObject {
  return baseSco("url", ctx, { value: ctx.value, ...(ctx.extra ?? {}) });
}

export function buildInfrastructure(ctx: StixBuildContext & { name: string; description?: string }): StixObject {
  return baseSdo("infrastructure", ctx, {
    name: ctx.name,
    ...(ctx.description ? { description: ctx.description } : {}),
    infrastructure_types: ["unknown"],
  });
}

export function buildRelationship(
  ctx: StixBuildContext & { relationshipType: string; sourceRef: string; targetRef: string },
): StixObject {
  return baseSdo("relationship", ctx, {
    relationship_type: ctx.relationshipType,
    source_ref: ctx.sourceRef,
    target_ref: ctx.targetRef,
  });
}

export function buildSighting(ctx: StixBuildContext & { sightingOfRef: string }): StixObject {
  return baseSdo("sighting", ctx, { sighting_of_ref: ctx.sightingOfRef });
}

export function buildNote(ctx: StixBuildContext & { content: string; objectRefs: string[] }): StixObject {
  return baseSdo("note", ctx, {
    content: ctx.content,
    object_refs: ctx.objectRefs,
  });
}

export function buildOpinion(
  ctx: StixBuildContext & { opinion: "strongly-disagree" | "disagree" | "neutral" | "agree" | "strongly-agree"; objectRefs: string[]; explanation: string },
): StixObject {
  return baseSdo("opinion", ctx, {
    opinion: ctx.opinion,
    explanation: ctx.explanation,
    object_refs: ctx.objectRefs,
  });
}

export function buildReport(
  ctx: StixBuildContext & { name: string; published: string; objectRefs: string[]; description?: string; extra?: Record<string, unknown> },
): StixObject {
  return baseSdo("report", ctx, {
    name: ctx.name,
    published: ctx.published,
    object_refs: ctx.objectRefs,
    report_types: ["threat-report"],
    ...(ctx.description ? { description: ctx.description } : {}),
    ...(ctx.extra ?? {}),
  });
}

export function buildObservedData(
  ctx: StixBuildContext & { firstObserved: string; lastObserved: string; objectRefs: string[] },
): StixObject {
  return baseSdo("observed-data", ctx, {
    first_observed: ctx.firstObserved,
    last_observed: ctx.lastObserved,
    number_observed: 1,
    object_refs: ctx.objectRefs,
  });
}

const SCHEMA_DIR = fileURLToPath(new URL("../stix-schemas/", import.meta.url));

let ajv: { getSchema: (id: string) => ((data: unknown) => boolean) & { errors?: { instancePath: string; message?: string }[] } | undefined; addSchema: (s: unknown) => void } | undefined;

function loadAjv() {
  if (ajv) return ajv;
  const require = createRequire(import.meta.url);
  const Ajv2020 = require("ajv/dist/2020.js");
  const addFormats = require("ajv-formats");
  const instance = new Ajv2020({ allErrors: true, strict: false, unicodeRegExp: false });
  addFormats(instance);
  if (!instance.formats["idn-hostname"]) {
    instance.addFormat("idn-hostname", /^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/);
  }
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.name.endsWith(".json")) instance.addSchema(JSON.parse(readFileSync(path, "utf8")));
    }
  };
  walk(SCHEMA_DIR);
  ajv = instance;
  return instance;
}

const SCHEMA_ID: Record<string, string> = {
  indicator: "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sdos/indicator.json",
  vulnerability: "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sdos/vulnerability.json",
  infrastructure: "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sdos/infrastructure.json",
  relationship: "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sros/relationship.json",
  sighting: "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sros/sighting.json",
  note: "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sdos/note.json",
  opinion: "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sdos/opinion.json",
  report: "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sdos/report.json",
  "observed-data": "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sdos/observed-data.json",
  "domain-name": "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/observables/domain-name.json",
  url: "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/observables/url.json",
};

export function validateStix(obj: StixObject): string[] {
  const errors: string[] = [];
  if (!obj.object_marking_refs || obj.object_marking_refs.length === 0) {
    errors.push("object_marking_refs is required");
  }
  if (!obj.external_references || obj.external_references.length === 0) {
    errors.push("external_references is required");
  }
  if (obj.confidence !== undefined && (!Number.isInteger(obj.confidence) || obj.confidence < 0 || obj.confidence > 100)) {
    errors.push("confidence must be an integer from 0 to 100");
  }
  const schemaId = SCHEMA_ID[obj.type];
  if (!schemaId) {
    errors.push(`no STIX schema for type ${obj.type}`);
    return errors;
  }
  const validator = loadAjv().getSchema(schemaId);
  if (!validator) {
    errors.push(`schema ${schemaId} was not loaded`);
    return errors;
  }
  if (!validator(obj)) {
    for (const err of validator.errors ?? []) {
      errors.push(`${err.instancePath || "/"} ${err.message ?? "invalid"}`.trim());
    }
  }
  return errors;
}
