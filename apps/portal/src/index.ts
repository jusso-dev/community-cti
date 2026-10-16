import type { Finding } from "@community-cti/schema";

/** Renders a finding as plain English. */
export function renderFindingText(f: Finding): string {
  return `${f.title}\n${f.plainEnglishSummary}\nConfidence: ${f.confidence}/100. Sources: ${f.provenance.map((p) => p.sourceId).join(", ")}`;
}

export interface PortalFinding extends Finding {
  confidenceFactors?: Array<{ code: string; points: number; reason: string }>;
  evidence?: Array<{ label: string; sourceId: string; licence: string; collectedAt: string; url?: string; redacted?: boolean; note?: string }>;
}

export interface PortalDomain {
  id?: string;
  domain: string;
  status: string;
  token?: string | null;
  txt?: string;
  verifiedAt?: string | null;
}

export interface Advisory {
  id: string;
  sourceId: string;
  title: string;
  url: string;
  summary: string;
  publishedAt: string;
  cves: string[];
  tags: string[];
  attackTechniques: string[];
  licence: string;
  relevance: number;
  reasons: string[];
}

export interface RansomwareSummary {
  days: number;
  total: number;
  similarSectors: number;
  sectors: Array<{ name: string; count: number }>;
  groups: Array<{ name: string; count: number }>;
  summary: string;
}

export interface PageOptions {
  error?: string;
  notice?: string;
}

export interface OnboardingValues {
  name?: string;
  orgType?: string;
  grantorName?: string;
  grantorRole?: string;
}

export const ORG_TYPES: Array<[string, string]> = [
  ["ACCO", "Aboriginal Community Controlled Organisation (ACCO)"],
  ["Land Council", "Land Council"],
  ["AMS", "Aboriginal Medical Service (AMS)"],
  ["Indigenous corporation", "Indigenous corporation"],
  ["other", "Something else"],
];

const FINDING_STATUS: Record<string, string> = {
  open: "Open. Please take a look.",
  acknowledged: "Seen.",
  dismissed: "Dismissed. You told us this is not a problem.",
  challenged: "Challenged. A person will check it again.",
  resolved: "Resolved.",
};

const DOMAIN_STATUS: Record<string, string> = {
  pending: "waiting for you to show you control it",
  email_pending: "waiting for you to open the email we sent",
  verified: "verified. We are watching it",
  lapsed: "no longer verified. Please check it again",
};

export function sortFindings<T extends { confidence: number; createdAt?: string }>(findings: T[]): T[] {
  return [...findings].sort((a, b) => b.confidence - a.confidence || String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char);
}

function pathPart(value: string): string {
  return escapeHtml(encodeURIComponent(value));
}

function alerts(options: PageOptions): string {
  const error = options.error ? `<p class="error" role="alert">${escapeHtml(options.error)}</p>` : "";
  const notice = options.notice ? `<p class="notice" role="status">${escapeHtml(options.notice)}</p>` : "";
  return error + notice;
}

function layout(title: string, main: string, options: PageOptions & { nav?: boolean } = {}): string {
  const nav = options.nav === false ? "" : `
    <nav aria-label="Main">
      <a href="/">Findings</a>
      <a href="/alerts">Australian alerts</a>
      <a href="/domains">Domains</a>
      <a href="/settings/notifications">Alerts</a>
    </nav>
    <form method="post" action="/logout"><button type="submit">Sign out</button></form>`;
  return `<!doctype html>
<html lang="en-AU">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(title)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { margin: 0; font-family: Georgia, serif; background: #ffffff; color: #1a1a1a; line-height: 1.5; }
    a { color: #0b3a82; }
    header, main, footer { padding: 1rem; }
    .skip { position: absolute; left: -999px; }
    .skip:focus { left: 1rem; top: 1rem; background: #ffffff; }
    button, input, select, textarea { font: inherit; }
    label { display: block; margin-top: 0.75rem; }
    textarea { width: 100%; max-width: 32rem; }
    form { margin: 0.75rem 0; }
    code { word-break: break-all; }
    .error { border-left: 4px solid #a4161a; background: #fdecea; padding: 0.5rem 1rem; }
    .notice { border-left: 4px solid #1b5e20; background: #edf7ed; padding: 0.5rem 1rem; }
    .source-hint { font-size: 0.9em; }
    table { border-collapse: collapse; }
    th, td { border: 1px solid #767676; padding: 0.25rem 0.5rem; text-align: left; }
    .stop { margin-top: 2.5rem; border: 2px solid #a4161a; padding: 0 1rem; }
  </style>
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header>
    <p>Community CTI</p>${nav}
  </header>
  <main id="main">
    <h1>${escapeHtml(title)}</h1>
    ${alerts(options)}
    ${main}
  </main>
  <footer><p>You can dismiss or challenge any finding.</p></footer>
  <script src="/app.js" defer></script>
</body>
</html>`;
}

export function renderLoginPage(options: PageOptions & { email?: string } = {}): string {
  return layout("Sign in", `
    <p>We will email you a link to sign in. You do not need a password.</p>
    <form method="post" action="/login">
      <label for="email">Your email address</label>
      <input id="email" name="email" type="email" autocomplete="email" required value="${escapeHtml(options.email ?? "")}">
      <button type="submit">Email me a sign-in link</button>
    </form>
  `, { ...options, nav: false });
}

export function renderCheckEmailPage(): string {
  return layout("Check your email", `
    <p>If this email address can use Community CTI, we have sent it a sign-in link.</p>
    <p>Open the link on this device. It only works once.</p>
    <p>Nothing there? Check your junk folder, or <a href="/login">ask for a new link</a>.</p>
  `, { nav: false });
}

export function renderMessagePage(title: string, message: string, link: { href: string; text: string } = { href: "/", text: "Go to your findings" }): string {
  return layout(title, `
    <p>${escapeHtml(message)}</p>
    <p><a href="${escapeHtml(link.href)}">${escapeHtml(link.text)}</a></p>
  `, { nav: false });
}

export function renderOnboardingPage(options: PageOptions & { needsOrg: boolean; values?: OnboardingValues }): string {
  const values = options.values ?? {};
  const types = ORG_TYPES.map(([value, text]) => `<option value="${escapeHtml(value)}"${values.orgType === value ? " selected" : ""}>${escapeHtml(text)}</option>`).join("");
  const org = options.needsOrg ? `
      <fieldset>
        <legend>Your organisation</legend>
        <label for="org-name">Organisation name</label>
        <input id="org-name" name="name" autocomplete="organization" required maxlength="200" value="${escapeHtml(values.name ?? "")}">
        <label for="org-type">What kind of organisation is it?</label>
        <select id="org-type" name="orgType">${types}</select>
      </fieldset>` : "";
  return layout("Set up your organisation", `
    <p>Before we start, someone who can speak for your organisation needs to give consent.</p>
    <form method="post" action="/onboarding">${org}
      <fieldset>
        <legend>Who is giving consent?</legend>
        <label for="grantor-name">Their full name</label>
        <input id="grantor-name" name="grantorName" autocomplete="name" required maxlength="200" value="${escapeHtml(values.grantorName ?? "")}">
        <label for="grantor-role">Their role, for example CEO or Chairperson</label>
        <input id="grantor-role" name="grantorRole" autocomplete="organization-title" required maxlength="200" value="${escapeHtml(values.grantorRole ?? "")}">
      </fieldset>
      <h2>What you are agreeing to</h2>
      <ul>
        <li>We will watch the domains you add for signs that someone is copying or misusing them.</li>
        <li>We only use public sources and sources we are allowed to use.</li>
        <li>You can ask us to stop at any time.</li>
      </ul>
      <label><input type="checkbox" name="consent" value="yes" required> I agree, on behalf of my organisation, that Community CTI can watch our domains. I know we can stop this at any time.</label>
      <button type="submit">Save and continue</button>
    </form>
  `, options);
}

export function renderFindingsPage(findings: PortalFinding[]): string {
  const rows = sortFindings(findings);
  const list = rows.length === 0
    ? "<p>No findings yet. When we find something about your domains, it will show here.</p>"
    : `<ul>${rows.map((finding) => `<li><a href="/findings/${pathPart(finding.id)}">${escapeHtml(finding.title)}</a> <span>Confidence ${finding.confidence} out of 100. ${escapeHtml(FINDING_STATUS[finding.status] ?? finding.status)}</span></li>`).join("")}</ul>`;
  return layout("Your findings", list);
}

function renderEvidence(item: NonNullable<PortalFinding["evidence"]>[number]): string {
  const safeUrl = item.url && !item.redacted && /^https?:\/\//i.test(item.url) ? item.url : undefined;
  const label = safeUrl ? `<a href="${escapeHtml(safeUrl)}">${escapeHtml(item.label)}</a>` : escapeHtml(item.label);
  const note = item.redacted ? ` ${escapeHtml(item.note ?? "This source cannot be shown in full.")}` : "";
  return `<li>${label}. From ${escapeHtml(item.sourceId)}, ${escapeHtml(item.licence)}, collected ${escapeHtml(item.collectedAt)}.${note}</li>`;
}

export function renderFindingDetail(finding: PortalFinding, options: PageOptions = {}): string {
  const id = pathPart(finding.id);
  const factors = (finding.confidenceFactors ?? []).map((factor) => `<li>${escapeHtml(factor.reason)} (${factor.points})</li>`).join("");
  const sources = finding.provenance.map((item) => `<li>${escapeHtml(item.sourceId)}, ${escapeHtml(item.licence)}, collected ${escapeHtml(item.collectedAt)}</li>`).join("");
  const evidence = (finding.evidence ?? []).map(renderEvidence).join("");
  const active = finding.status === "open" || finding.status === "acknowledged";
  const actions = active ? `
    <section>
      <h2>Dismiss or challenge</h2>
      <form method="post" action="/findings/${id}/dismiss">
        <label for="reason">Why are you dismissing this?</label>
        <select id="reason" name="reason">
          <option value="not_ours">This is not us</option>
          <option value="already_handled">Already handled</option>
          <option value="legitimate_domain">This domain is legitimate</option>
          <option value="not_relevant">Not relevant</option>
          <option value="other">Other</option>
        </select>
        <label for="dismiss-comment">Add a short note. You need one if you choose Other.</label>
        <textarea id="dismiss-comment" name="comment" rows="3" maxlength="2000"></textarea>
        <button type="submit">Dismiss this finding</button>
      </form>
      <form method="post" action="/findings/${id}/challenge">
        <label for="challenge-comment">Think we got this wrong? Tell us why.</label>
        <textarea id="challenge-comment" name="comment" rows="3" maxlength="2000"></textarea>
        <button type="submit">Challenge this finding</button>
      </form>
    </section>` : `
    <section>
      <h2>Changed your mind?</h2>
      <form method="post" action="/findings/${id}/reopen">
        <button type="submit">Reopen this finding</button>
      </form>
    </section>`;
  return layout(finding.title, `
    <p>Status: ${escapeHtml(FINDING_STATUS[finding.status] ?? finding.status)}</p>
    <section>
      <h2>What we found</h2>
      <p>${escapeHtml(finding.plainEnglishSummary)}</p>
    </section>
    <section>
      <h2>Why we think so</h2>
      <p>Confidence: ${finding.confidence} out of 100.</p>
      <ul>${factors}</ul>
    </section>
    <section>
      <h2>Sources</h2>
      <ul>${sources}</ul>
    </section>${evidence ? `
    <section>
      <h2>Evidence</h2>
      <ul>${evidence}</ul>
    </section>` : ""}
    <section>
      <h2>What to do</h2>
      <ol>
        <li>Read the sources above.</li>
        <li>Ask your IT helper if you are unsure.</li>
        <li>Dismiss this if it is not about you.</li>
      </ol>
    </section>${actions}
  `, options);
}

function renderDomain(item: PortalDomain, index: number): string {
  const txt = item.txt ?? (item.token ? `cti-verify=${item.token}` : undefined);
  const verified = item.status === "verified";
  const status = DOMAIN_STATUS[item.status] ?? item.status;
  const record = !verified && txt ? `<p>Add a DNS TXT record to ${escapeHtml(item.domain)} with this value:</p><p><code>${escapeHtml(txt)}</code></p>` : "";
  const id = item.id ? pathPart(item.id) : "";
  const addresses = ["admin", "postmaster", "webmaster"].map((name) => `<option>${escapeHtml(`${name}@${item.domain}`)}</option>`).join("");
  const actions = !verified && item.id ? `
      <form method="post" action="/domains/${id}/check">
        <button type="submit">Check ${escapeHtml(item.domain)} now</button>
      </form>
      <form method="post" action="/domains/${id}/email">
        <label for="domain-email-${index}">Or we can email a link to</label>
        <select id="domain-email-${index}" name="email">${addresses}</select>
        <button type="submit">Send the email</button>
      </form>` : "";
  return `
    <section>
      <h2>${escapeHtml(item.domain)}</h2>
      <p>This domain is ${escapeHtml(status)}.${item.verifiedAt ? ` Verified on ${escapeHtml(longDate(item.verifiedAt))}.` : ""}</p>
      ${record}${actions}
    </section>`;
}

export function renderDomainsPage(domains: PortalDomain[], options: PageOptions = {}): string {
  return layout("Your domains", `
    <p>To start watching a domain, show us you control it. Add a DNS TXT record, or we can email admin, postmaster or webmaster at that domain.</p>
    ${domains.map(renderDomain).join("") || "<p>No domains yet.</p>"}
    <section>
      <h2>Add a domain</h2>
      <form method="post" action="/domains">
        <label for="domain">Domain you control, for example example.org.au</label>
        <input id="domain" name="domain" autocomplete="off" required maxlength="253">
        <button type="submit">Add domain</button>
      </form>
      <p>Need to update who gave consent? Go to <a href="/onboarding">set up</a>.</p>
    </section>
  `, options);
}

function renderStopMonitoring(): string {
  return `
    <section class="stop">
      <h2>Stop watching our domains</h2>
      <p>This stops all monitoring for your organisation. We will not look for new problems or send alerts until someone gives consent again.</p>
      <form method="post" action="/settings/stop-monitoring">
        <label><input type="checkbox" name="confirm" value="yes" required> I understand we will stop getting alerts about our domains.</label>
        <button type="submit">Stop watching our domains</button>
      </form>
    </section>`;
}

export function renderNotificationSettings(mode: string, options: PageOptions & { canStop?: boolean } = {}): string {
  return layout("Alert settings", `
    <form method="post" action="/settings/notifications">
      <fieldset>
        <legend>How should we email you?</legend>
        <label><input type="radio" name="mode" value="immediate" ${mode === "immediate" ? "checked" : ""}> Straight away for high confidence</label>
        <label><input type="radio" name="mode" value="digest" ${mode === "digest" ? "checked" : ""}> A daily summary</label>
        <label><input type="radio" name="mode" value="off" ${mode === "off" ? "checked" : ""}> Do not email me</label>
      </fieldset>
      <button type="submit">Save alert settings</button>
    </form>${options.canStop ? renderStopMonitoring() : ""}
  `, options);
}

function sourceLabel(sourceId: string): string {
  if (sourceId.startsWith("acsc")) return "Australian Cyber Security Centre";
  if (sourceId.startsWith("cisa")) return "US CISA";
  return sourceId;
}

function longDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleDateString("en-AU", { day: "numeric", month: "long", year: "numeric", timeZone: "Australia/Sydney" });
}

function shorten(text: string, limit = 300): string {
  if (text.length <= limit) return text;
  const cut = text.slice(0, limit);
  return `${cut.slice(0, cut.lastIndexOf(" ") > 0 ? cut.lastIndexOf(" ") : limit)}...`;
}

function renderRansomware(report: RansomwareSummary): string {
  const sectors = [...report.sectors].sort((a, b) => b.count - a.count).slice(0, 5);
  const table = sectors.length === 0 ? "" : `
      <table>
        <caption>Sectors with the most reported attacks in the last ${report.days} days</caption>
        <thead><tr><th scope="col">Sector</th><th scope="col">Reported attacks</th></tr></thead>
        <tbody>${sectors.map((sector) => `<tr><td>${escapeHtml(sector.name)}</td><td>${sector.count}</td></tr>`).join("")}</tbody>
      </table>`;
  return `
    <section>
      <h2>Ransomware in Australia</h2>
      <p>${escapeHtml(report.summary)}</p>${table}
    </section>`;
}

function renderAdvisory(item: Advisory): string {
  const safeUrl = /^https?:\/\//i.test(item.url) ? item.url : undefined;
  const title = safeUrl
    ? `<a href="${escapeHtml(safeUrl)}" rel="noopener noreferrer">${escapeHtml(item.title)} <span class="source-hint">(opens the source website)</span></a>`
    : escapeHtml(item.title);
  const reasons = item.reasons.length ? `<ul>${item.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>` : "";
  const cves = item.cves.length ? `<p>Vulnerabilities: ${item.cves.map(escapeHtml).join(", ")}</p>` : "";
  return `
    <article>
      <h3>${title}</h3>
      <p>From ${escapeHtml(sourceLabel(item.sourceId))}, <time datetime="${escapeHtml(item.publishedAt)}">${escapeHtml(longDate(item.publishedAt))}</time>.</p>
      <p>${escapeHtml(shorten(item.summary))}</p>
      ${reasons}${cves}
      <p>Licence: ${escapeHtml(item.licence)}</p>
    </article>`;
}

export function renderAlertsPage(advisories: Advisory[], ransomware: RansomwareSummary): string {
  const list = advisories.length === 0
    ? "<p>No Australian alerts yet. We check the Australian Cyber Security Centre every hour.</p>"
    : advisories.map(renderAdvisory).join("");
  return layout("Australian cyber alerts", `${renderRansomware(ransomware)}
    <section>
      <h2>Latest alerts</h2>
      ${list}
    </section>
  `);
}
