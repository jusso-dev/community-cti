# ADR 0004: STIX 2.1 as the data model

- Status: Accepted
- Date: 2026-10-13

## Decision
Represent shared intelligence as STIX 2.1 objects (indicator, observed-data, vulnerability, campaign, threat-actor, malware, identity, infrastructure, relationship, sighting, note, opinion). Tenant findings are an application object that references STIX ids.

## Reasons
Interoperability with OpenCTI, MISP, TAXII feeds and SIEMs; standard confidence (0 to 100) and marking definitions (TLP 2.0); `opinion` and `note` objects model challenges and dismissals.

## Consequences
- Every stored STIX object keeps `created_by_ref`, `object_marking_refs`, `confidence` and an `external_references` entry pointing to the source.
- Tenant-specific objects carry `tenant_id` in our table and are never exported to shared pools without opt-in.
- Validation against STIX 2.1 JSON schemas in CI.
