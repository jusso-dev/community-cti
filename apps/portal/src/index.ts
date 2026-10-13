import type { Finding } from "@community-cti/schema";

/** Placeholder kept for callers. Renders a finding as plain English. */
export function renderFindingText(f: Finding): string {
  return `${f.title}\n${f.plainEnglishSummary}\nConfidence: ${f.confidence}/100. Sources: ${f.provenance.map((p) => p.sourceId).join(", ")}`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[char] ?? char));
}

function latestCollectedAt(finding: Finding): string {
  return finding.provenance.map((item) => item.collectedAt).sort().at(-1) ?? "";
}

/** Higher confidence first. Equal scores use the later collection time. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    return latestCollectedAt(b).localeCompare(latestCollectedAt(a));
  });
}

/** Example only. This is not a pilot finding and not a real organisation. */
export const SAMPLE_FINDINGS: Finding[] = [{
  id: "example-lookalike",
  tenantId: "example",
  kind: "lookalike_domain",
  title: "Example: a website name looks like yours",
  plainEnglishSummary: "A website name looks like yours.",
  confidence: 72,
  confidenceFactors: [{ code: "edit_distance", points: 25, reason: "The name is close to yours." }],
  provenance: [{
    sourceId: "crtsh",
    sourceUrl: "https://crt.sh/",
    collectedAt: "2026-10-13T00:00:00.000Z",
    licence: "public certificate transparency",
    accessRestriction: "TLP:CLEAR",
    evidenceRefs: ["example-evidence"],
  }],
  status: "open",
  stixRefs: [],
}];

function nav(): string {
  return `<nav><a href="/">Findings</a> <a href="/domains">Domains</a> <a href="/settings/notifications">Notifications</a></nav>`;
}

function reasonSelect(id: string): string {
  return `<label for="reason-${id}">Why is this not useful?</label>
    <select id="reason-${id}" name="reason">
      <option value="not_ours">Not our organisation</option>
      <option value="already_handled">Already handled</option>
      <option value="legitimate_domain">This domain is ours</option>
      <option value="not_relevant">Not relevant</option>
      <option value="other">Other</option>
    </select>`;
}

export function dashboardFragment(findings: Finding[]): string {
  const cards = sortFindings(findings).map((finding) => {
    const id = escapeHtml(finding.id);
    return `<article>
      <h2>${escapeHtml(finding.title)}</h2>
      <p>${escapeHtml(finding.plainEnglishSummary)} Do not type your password there. Tell your IT helper.</p>
      <p>Confidence: ${finding.confidence} out of 100.</p>
      <a href="/findings/${id}">Read the detail</a>
      <form method="post" action="/findings/${id}/dismiss">
        ${reasonSelect(id)}
        <button type="submit">Dismiss</button>
      </form>
    </article>`;
  }).join("");
  const empty = findings.length === 0 ? "<p>No findings yet.</p>" : "";
  return `${nav()}<main><h1>Findings</h1>${empty}${cards}</main>`;
}

export function findingDetailFragment(finding: Finding): string {
  const id = escapeHtml(finding.id);
  const factors = finding.confidenceFactors.map((factor) =>
    `<li>${escapeHtml(factor.reason)} (${factor.points})</li>`,
  ).join("");
  const sources = finding.provenance.map((item) => {
    const link = item.sourceUrl ? ` <a href="${escapeHtml(item.sourceUrl)}">Source link</a>` : "";
    return `<li>${escapeHtml(item.sourceId)}. Collected ${escapeHtml(item.collectedAt)}. Licence: ${escapeHtml(item.licence)}. ${escapeHtml(item.accessRestriction)}.${link}</li>`;
  }).join("");
  return `${nav()}<main>
    <h1>${escapeHtml(finding.title)}</h1>
    <h2>What we found</h2>
    <p>${escapeHtml(finding.plainEnglishSummary)} Do not type your password there. Tell your IT helper.</p>
    <h2>Why we think so</h2>
    <p>Confidence: ${finding.confidence} out of 100.</p>
    <ul>${factors}</ul>
    <h2>Sources</h2>
    <ul>${sources}</ul>
    <h2>What to do</h2>
    <p>Do not type your password there. Tell your IT helper.</p>
    <h2>Dismiss or challenge</h2>
    <p>When you are signed in, the API records this choice and you can reopen it.</p>
    <form method="post" action="/findings/${id}/dismiss">
      ${reasonSelect(id)}
      <button type="submit">Dismiss</button>
    </form>
    <form method="post" action="/findings/${id}/challenge">
      <label for="note-${id}">What should we look at again?</label>
      <textarea id="note-${id}" name="note"></textarea>
      <button type="submit">Challenge</button>
    </form>
  </main>`;
}

export function domainsFragment(): string {
  return `${nav()}<main>
    <h1>Domains</h1>
    <p>Add a domain you control. We ask for a TXT record before we watch it.</p>
    <p>Saving a domain needs a signed-in session. This page does not store the name by itself.</p>
    <form method="post" action="/domains">
      <label for="domain">Domain name</label>
      <input id="domain" name="domain" type="text" autocomplete="off" />
      <button type="submit">Add domain</button>
    </form>
  </main>`;
}

export function notificationsFragment(): string {
  return `${nav()}<main>
    <h1>Notifications</h1>
    <p>Choose when we email you. Immediate is for high confidence findings. A digest groups the rest.</p>
    <form method="post" action="/settings/notifications">
      <label for="mode">Email timing</label>
      <select id="mode" name="mode">
        <option value="immediate">Immediate</option>
        <option value="digest">Digest</option>
        <option value="off">Off</option>
      </select>
      <button type="submit">Save</button>
    </form>
  </main>`;
}

export function renderDocument(title: string, body: string): string {
  return `<!doctype html><html lang="en-AU"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head><body>${body}</body></html>`;
}

/** Server-rendered findings page. Forms post without client JavaScript. */
export function renderDashboard(findings: Finding[]): string {
  return renderDocument("Findings", dashboardFragment(findings));
}

export function renderFindingDetail(finding: Finding): string {
  return renderDocument(finding.title, findingDetailFragment(finding));
}

export function renderDomainsPage(): string {
  return renderDocument("Domains", domainsFragment());
}

export function renderNotificationsPage(): string {
  return renderDocument("Notifications", notificationsFragment());
}
