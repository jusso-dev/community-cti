# Source inventory

Every collector must have a row here before it is merged. "Status" is one of `candidate`, `approved`, `rejected`, `blocked`. Licence and terms must be checked by a person; values below for candidates are unverified starting points.

| Id | Source | Type | Licence / terms | Commercial use allowed? | Cost | Coverage | TLP / restrictions | Access method | Status | Reviewed by | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `crtsh` | crt.sh certificate transparency | Domain | Public CT logs; check crt.sh fair use | To verify | Free | Global certs | TLP:CLEAR | HTTPS / Postgres | candidate | | Lookalike and new cert detection |
| `certstream` | CertStream | Domain | Check terms | To verify | Free / self-host | Live CT | TLP:CLEAR | WebSocket | candidate | | Real-time lookalikes |
| `dnstwist` | dnstwist (tool) | Domain | Apache-2.0 tool | Yes | Free | Generated permutations | n/a | Library | candidate | | Permutation generation |
| `hibp-domain` | Have I Been Pwned domain search | Credential | Commercial API subscription, terms | To verify | Paid | Known breaches | Restricted | API (verified domains only) | candidate | | Lawful credential exposure |
| `acsc-alerts` | ACSC alerts and advisories | Advisory | Check cyber.gov.au terms | To verify | Free | AU | TLP:CLEAR | RSS | candidate | | AU relevance |
| `cisa-kev` | CISA Known Exploited Vulnerabilities | Vulnerability | Public domain (US Gov) | To verify | Free | Global | TLP:CLEAR | JSON | candidate | | |
| `nvd` | NVD CVE API | Vulnerability | Public, API key | To verify | Free | Global | TLP:CLEAR | API | candidate | | |
| `epss` | FIRST EPSS | Vulnerability | Check terms | To verify | Free | Global | TLP:CLEAR | CSV/API | candidate | | Prioritisation |
| `urlhaus` | abuse.ch URLhaus | Phishing / malware | Check abuse.ch terms | To verify | Free | Global | TLP:CLEAR | API | candidate | | |
| `threatfox` | abuse.ch ThreatFox | IOC | Check abuse.ch terms | To verify | Free | Global | TLP:CLEAR | API | candidate | | |
| `openphish` | OpenPhish community feed | Phishing | Community feed terms | To verify | Free / paid | Global | TLP:CLEAR | Feed | candidate | | |
| `phishtank` | PhishTank | Phishing | Check terms | To verify | Free | Global | TLP:CLEAR | Feed | candidate | | |
| `ransomwatch` | Ransomware leak site trackers (e.g. ransomware.live) | Ransomware | Check terms | To verify | Free / paid | Global | TLP:CLEAR | API | candidate | | Reporting only, no leak data download |
| `shodan` | Shodan | Exposure | Commercial terms | To verify | Paid | Global | Restricted | API | candidate | | Exposed services |
| `censys` | Censys | Exposure | Commercial / research terms | To verify | Free tier / paid | Global | Restricted | API | candidate | | |
| `otx` | AlienVault OTX | IOC | Check terms | To verify | Free | Global | Varies | API | candidate | | |
| `misp-feeds` | MISP default OSINT feeds | IOC | Per feed | Per feed | Free | Global | Per feed | MISP | candidate | | |
| `stealer-logs` | Stealer log datasets | Credential | n/a | n/a | n/a | n/a | n/a | n/a | blocked | | Deferred: blocked on lawful access and procedures |
| `underground` | Underground forums and markets | Cybercrime | n/a | n/a | n/a | n/a | n/a | n/a | blocked | | Deferred: blocked on lawful access and procedures |
