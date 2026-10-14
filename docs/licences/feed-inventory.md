# Feed licence inventory

Draft for Justin. Not completed.

This table lists the public feeds the Phase 1 code can parse. Every row needs legal review. None of these statuses replace `docs/SOURCES.md`, which still says `candidate` until a person checks the terms. Do not treat this draft as approval.

| Feed | What the code uses | Published terms page | Commercial use | Needs legal review |
|---|---|---|---|---|
| CISA KEV | JSON catalogue | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | US government work, to be confirmed | Yes |
| NVD CVE API 2.0 | CVE JSON | https://nvd.nist.gov/general/terms-of-use | To be confirmed | Yes |
| FIRST EPSS | Daily CSV | https://www.first.org/epss | To be confirmed | Yes |
| abuse.ch URLhaus | Recent CSV | https://abuse.ch/terms/ and https://urlhaus.abuse.ch/api/ | To be confirmed | Yes |
| OpenPhish community feed | URL list | https://openphish.com/faq.html | To be confirmed | Yes |
| PhishTank | CSV feed | https://www.phishtank.com/api_info.php | To be confirmed | Yes |
| ACSC alerts | RSS on cyber.gov.au | https://www.cyber.gov.au/about-us/about-asd-acsc | To be confirmed | Yes |
| crt.sh | Certificate search URL | https://crt.sh/ | Fair use to be confirmed | Yes |
| CertStream | Certificate names from the public stream | https://github.com/CaliDog/certstream-server | To be confirmed | Yes |
| ransomware.live | Victim name, group and date only | https://www.ransomware.live/ | Reporting only. Leak content is not collected. To be confirmed | Yes |
| HIBP domain search | Email, breach name, breach date, data classes | https://haveibeenpwned.com/TermsOfUse and https://haveibeenpwned.com/API/v3 | Paid subscription. To be confirmed | Yes |
| Shodan or Censys | Not called. Fixture provider only | https://developer.shodan.io/api/requirements and https://about.censys.io/ | Paid. To be confirmed | Yes |

Blocked rows in `docs/SOURCES.md` (`stealer-logs`, `underground`) are not feeds we use.
