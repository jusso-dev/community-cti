import type { Finding } from "@community-cti/schema";

/** Renders a finding as plain English. */
export function renderFindingText(f: Finding): string {
  return `${f.title}\n${f.plainEnglishSummary}\nConfidence: ${f.confidence}/100. Sources: ${f.provenance.map((p) => p.sourceId).join(", ")}`;
}

export interface PortalFinding extends Finding {
  confidenceFactors?: Array<{ code: string; points: number; reason: string }>;
  evidence?: Array<{ label: string; sourceId: string; licence: string; collectedAt: string; url?: string; redacted?: boolean; note?: string }>;
}

export function sortFindings<T extends { confidence: number; createdAt?: string }>(findings: T[]): T[] {
  return [...findings].sort((a, b) => b.confidence - a.confidence || String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char);
}

function layout(title: string, main: string): string {
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
    button, input, select { font: inherit; }
  </style>
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header>
    <p>Community CTI</p>
    <nav aria-label="Main">
      <a href="/">Findings</a>
      <a href="/domains">Domains</a>
      <a href="/settings/notifications">Alerts</a>
    </nav>
  </header>
  <main id="main">
    <h1>${escapeHtml(title)}</h1>
    ${main}
  </main>
  <footer><p>You can dismiss or challenge any finding.</p></footer>
  <script src="/app.js" defer></script>
</body>
</html>`;
}

export function renderFindingsPage(findings: PortalFinding[]): string {
  const rows = sortFindings(findings);
  const list = rows.length === 0
    ? "<p>No findings yet. When we find something about your domains, it will show here.</p>"
    : `<ul>${rows.map((finding) => `<li><a href="/findings/${escapeHtml(finding.id)}">${escapeHtml(finding.title)}</a> <span>Confidence ${finding.confidence} out of 100</span></li>`).join("")}</ul>`;
  return layout("Your findings", list);
}

export function renderFindingDetail(finding: PortalFinding): string {
  const factors = (finding.confidenceFactors ?? []).map((factor) => `<li>${escapeHtml(factor.reason)} (${factor.points})</li>`).join("");
  const sources = finding.provenance.map((item) => `<li>${escapeHtml(item.sourceId)}, ${escapeHtml(item.licence)}, collected ${escapeHtml(item.collectedAt)}</li>`).join("");
  return layout(finding.title, `
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
    </section>
    <section>
      <h2>What to do</h2>
      <ol>
        <li>Read the sources above.</li>
        <li>Ask your IT helper if you are unsure.</li>
        <li>Dismiss this if it is not about you.</li>
      </ol>
    </section>
    <section>
      <h2>Dismiss or challenge</h2>
      <form method="post" action="/findings/${escapeHtml(finding.id)}/dismiss">
        <label for="reason">Why are you dismissing this?</label>
        <select id="reason" name="reason">
          <option value="not_ours">This is not us</option>
          <option value="already_handled">Already handled</option>
          <option value="legitimate_domain">This domain is legitimate</option>
          <option value="not_relevant">Not relevant</option>
          <option value="other">Other</option>
        </select>
        <button type="submit">Dismiss this finding</button>
      </form>
      <form method="post" action="/findings/${escapeHtml(finding.id)}/challenge">
        <button type="submit">Challenge this finding</button>
      </form>
    </section>
  `);
}

export function renderDomainsPage(domains: Array<{ domain: string; status: string; txt?: string }>): string {
  const items = domains.map((item) => `<li>${escapeHtml(item.domain)} is ${escapeHtml(item.status)}.${item.txt ? ` Add a DNS TXT record with ${escapeHtml(item.txt)}.` : ""}</li>`).join("");
  return layout("Your domains", `
    <p>Add a DNS TXT record, or we can email admin, postmaster or webmaster at that domain.</p>
    <ul>${items || "<li>No domains yet.</li>"}</ul>
    <form method="post" action="/domains">
      <label for="domain">Domain you control</label>
      <input id="domain" name="domain" autocomplete="off">
      <button type="submit">Add domain</button>
    </form>
  `);
}

export function renderNotificationSettings(mode: string): string {
  return layout("Alert settings", `
    <form method="post" action="/settings/notifications">
      <fieldset>
        <legend>How should we email you?</legend>
        <label><input type="radio" name="mode" value="immediate" ${mode === "immediate" ? "checked" : ""}> Straight away for high confidence</label>
        <label><input type="radio" name="mode" value="digest" ${mode === "digest" ? "checked" : ""}> A daily summary</label>
        <label><input type="radio" name="mode" value="off" ${mode === "off" ? "checked" : ""}> Do not email me</label>
      </fieldset>
      <button type="submit">Save alert settings</button>
    </form>
  `);
}
