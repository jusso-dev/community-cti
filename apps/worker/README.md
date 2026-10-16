# Worker

Background jobs that turn public feeds into tenant findings. Collectors are deterministic and never call a language model.

The worker connects as the table owner (`DATABASE_URL`) and needs `BYPASSRLS`, because it is the one component that reads across tenants. Tenant writes still go through `withTenant()`. Run `pnpm db:migrate` first (it needs `0005_worker.sql` and `0006_advisories.sql`).

## Run

```bash
pnpm build
# Long-running scheduler with a health endpoint on WORKER_HEALTH_PORT
START_WORKER=1 node apps/worker/dist/index.js
# Every job once, in order, then exit 0 (all jobs ran) or 1 (a job failed)
RUN_ONCE=1 node apps/worker/dist/index.js
```

`GET /healthz` returns the last run of each job with its counts. SIGTERM lets the running job finish (up to 25 seconds), then exits.

## Jobs

| Job | Cadence | What it does |
|---|---|---|
| `sources-sync` | daily, and at start | Mirrors `docs/SOURCES.md` into `sources` |
| `collect:<source>` | from `SOURCE_CRONS` (hourly if unset) | cisa-kev, epss (bulk daily file only), urlhaus, openphish, threatsieve |
| `collect:nvd` | every 2 hours | NVD CVE API 2.0 by lastModified window (since last success less 1 hour, at most 120 days, 7 days on the first run), 2000 per page, paced by `nvdLimit` |
| `advisories` | hourly | `AU_FEEDS`: ACSC alerts, advisories and news (`acsc-alerts`) and CISA advisories (`cisa-advisories`), 50 items each, into `advisories` |
| `collect:ransomwatch` | daily | ransomware.live `v2/countryvictims/AU`, last 365 days, into `au_ransomware_victims` |
| `reverify-domains` | daily | Checks the `cti-verify=` TXT record and lapses domains after 14 days missing |
| `lookalike` | hourly | crt.sh (one query per verified domain per day) and phishing feeds, matched, enriched and scored |
| `lookalike-permutations` | daily | dnstwist-style names for each verified domain (typos, homoglyphs, AU ending swaps, brand combos; up to 600), resolved at 20 queries a second, 10 in flight, 3 s each. Registered names go through the same enrichment and scoring. DNS results are cached a day |
| `ransomware-match` | hourly | Compares AU victims with tenant names; a victim website under a verified domain is the second signal |
| `alerts` | every 5 minutes | Plans one delivery per finding and member, emails immediate alerts |
| `digest` | daily | One summary email per member for digest deliveries |
| `retention` | daily | Deletes expired magic links and sessions, observations older than `RETENTION_DAYS_RAW` with their raw blobs (kept while an open, acknowledged or challenged finding points at them), AU ransomware rows older than 400 days and advisories older than 2 years. Never touches `audit_log`, `findings` or `consents` |

Only `approved` sources run. Last runs live in `collector_runs`, so a restart does not refetch early. Each run logs one JSON line with `fetched`, `inserted`, `duplicates`, `findings` and `errors`.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | required | Table owner connection |
| `PAPERBOY_URL`, `PAPERBOY_API_KEY` | unset | PaperBoy HTTP API, used first when both are set. A 429 pauses alert and digest sending until its Retry-After passes, without using up attempts |
| `SMTP_URL`, `MAIL_FROM` | unset | Used when PaperBoy is not set. With neither, mail goes to an in-memory sink and is logged as disabled |
| `EMAIL_REGION` | `ap-southeast-2` | Must be an Australian region |
| `PORTAL_BASE_URL` | `http://localhost:3000` | Links in emails |
| `RAW_DIR` | `./data/raw` | Raw evidence blobs |
| `THREATSIEVE_TAXII_URL`, `THREATSIEVE_API_KEY` | unset | ThreatSieve is skipped unless both are set |
| `FINDING_MIN_CONFIDENCE` | `40` | Lookalike threshold. Ransomware mentions need at least 60 |
| `NVD_API_KEY` | unset | Sent as the `apiKey` header; raises the NVD pace from 5 to 50 requests per 30 seconds |
| `RETENTION_DAYS_RAW` | `90` | |
| `EPSS_TOP_N` | `1000` | EPSS rows kept besides KEV entries |
| `USER_AGENT` | `community-cti-worker/0.1` | Sent on every request. cyber.gov.au silently drops agents with a comment or URL in them |
| `WORKER_HEALTH_PORT` | `8090` | |
| `RUN_ONCE`, `START_WORKER` | unset | Set one to `1` to start |
| `WORKER_JOBS` | unset (all) | Comma list of job names from the table above; unknown names stop startup |
| `CTI_ENV` | `development` | |
| `TEST_APPROVED_SOURCES` | unset | Comma list of `candidate` sources to treat as approved for testing. Refused when `CTI_ENV=production`. Blocked and deferred sources are never lifted |
