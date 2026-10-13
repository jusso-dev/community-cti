# Source licence desk review

Date reviewed: 2026-10-13.

This note records a desk review of `docs/SOURCES.md`. It does not change any Status in that file. It is not a legal opinion, and it is not Justin Middler's sign-off. Rows stay `candidate` or `blocked` until a person with authority accepts them.

## Reviewed from the provider's pages

### NVD
Terms: <https://nvd.nist.gov/developers/terms-of-use>, read 2026-10-13.

The API is a public service. Users are asked to display this notice: "This product uses the NVD API but is not endorsed or certified by the NVD." The NVD name must not be used to imply endorsement. Rate limits apply, and an API key is optional but unauthenticated use is tighter.

Recommendation: approve for Phase 1 only with that notice in the product. Do not mark the row approved in `docs/SOURCES.md` until Justin accepts it.

### abuse.ch (URLhaus and ThreatFox)
Terms: <https://abuse.ch/terms-of-use/>, effective 4 November 2025, read 2026-10-13.

Free access is discretionary. Commercial or for-profit use may need a paid subscription managed by Spamhaus. A commercial user who wants later free access must contribute for six months while paying.

This product has paid tiers in the README hypotheses, so free commercial use is not clearly allowed.

Recommendation: do not approve URLhaus or ThreatFox for unpaid use. A Phase 1 set that includes URLhaus on the free abuse.ch API conflicts with those terms.

### OpenPhish
Terms: <https://openphish.com/terms.html>, read 2026-10-13. The community feed README says non-commercial use and points at the same terms.

The services are for personal use. Academic or personal research is allowed when it does not support an organisation's business. Commercial use, including security operations, threat intelligence, detection, enrichment, and customer protection, needs prior written consent. Redistribution is restricted.

Recommendation: reject OpenPhish for this product unless OpenPhish gives written consent. Do not mark the row rejected in `docs/SOURCES.md` until Justin accepts that.

### Have I Been Pwned domain search
Terms: <https://haveibeenpwned.com/TermsOfUse>, last updated March 2026, read 2026-10-13.

Domain search is a paid commercial API except for small domains that fit the free tier. The domain must be added and verified before search. Terms updated in March 2026 also cover bulk domain verification and restrictions on building a competing breach database.

USD list prices were copied from the Have I Been Pwned support article "What subscription size do I need to search my domain?" (updated 9 September 2026). They are not an AUD quote and were not re-checked on a checkout page.

| Plan | Stealer logs | Max breached addresses | Max domains | Monthly (USD) |
|---|---|---|---|---|
| Free | No | 10 | Unlimited | 0 |
| Core 1 | No | 25 | 1 | 5.29 |
| Core 2 | No | 100 | 3 | 25.99 |
| Core 3 | No | 500 | 5 | 43.99 |
| Core 4 | No | Unlimited | 10 | 189 |
| Core 5 | No | Unlimited | 20 | 379 |
| Pro 1 | Yes | Unlimited | 50 | 449 |

Pro plans expose stealer-log website domains. That is out of scope while stealer-log collection stays blocked. This product stores no passwords.

Recommendation: stay candidate. Use domain search only for verified domains, on a plan that covers the domain size, and never store password material.

### CISA KEV
Catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>, read 2026-10-13.

The page is public and offers CSV and JSON. It has a License heading. This review did not download the licence file body, so the CC0 text was not confirmed from the current file.

Recommendation: approve once the current licence file is saved next to the collector notes and it is still public-domain or CC0. Until then the row stays candidate.

## Not fully read

These stay `candidate`. Nothing below is an approval.

| Id | What this review did | Recommendation |
|---|---|---|
| `crtsh` | No dedicated commercial licence page was retrieved. The site republishes public certificate transparency. | Low-volume lookups, with attribution to crt.sh. No bulk copy. Stay candidate. |
| `certstream` | Terms and the historical endpoint were not read in full. | Stay candidate. |
| `dnstwist` | Treated as the Apache-2.0 permutation tool. The LICENSE file was not opened in this pass. | Confirm the LICENSE file, then it can be a local tool. Stay candidate. |
| `acsc-alerts` | cyber.gov.au copyright terms were not read in full. | Stay candidate. Attribute ACSC if use is later approved. |
| `epss` | FIRST terms for the daily CSV were not read in full. | Stay candidate. |
| `phishtank` | Terms were not read in full. | Stay candidate. Do not assume the feed is free for a security product. |
| `ransomwatch` | ransomware.live terms were not read in full. | Reporting only if later approved. Do not download leak-site data. Stay candidate. |
| `shodan`, `censys` | Commercial terms and current AUD prices were not collected. | Stay candidate. |
| `otx`, `misp-feeds` | Per-feed terms were not read. | Stay candidate. |

## Blocked

`stealer-logs` and `underground` stay blocked. No provider was approved and no collection was started. See `docs/governance/deferred-collection.md`.

## Phase 1 suggestion

This is a suggestion, not a decision.

- NVD, with the attribution sentence, once Justin accepts the row.
- CISA KEV, once the current licence file is saved and Justin accepts the row.
- crt.sh only as a careful, attributed lookup, still candidate.
- Leave OpenPhish out.
- Leave URLhaus and ThreatFox out of unpaid collection.
- Leave HIBP until a plan is chosen, and keep it to verified domains.
- Leave ACSC, EPSS, PhishTank, ransomware.live, Shodan, Censys, OTX, and MISP feeds until their terms are read in full.
