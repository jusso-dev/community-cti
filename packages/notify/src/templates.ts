import type { Finding, FindingKind } from "@community-cti/schema";
import { fleschKincaidGrade, wordCount } from "./readability.js";

export interface AlertEmail {
  subject: string;
  headline: string;
  text: string;
  steps: string[];
  dismissUrl: string;
}

const COPY: Record<FindingKind, { subject: string; found: string; why: string; steps: string[] }> = {
  lookalike_domain: {
    subject: "A website looks like your domain",
    found: "We found a website name that is close to a domain you have checked.",
    why: "People may think the site is yours and type in private details.",
    steps: ["Open the finding and read the source.", "Ask your IT helper to check the site.", "Dismiss it if you know the site is real."],
  },
  credential_exposure: {
    subject: "Staff email showed up in a breach",
    found: "We found staff email addresses from your domain in a known breach.",
    why: "Someone could try those details to sign in to your accounts.",
    steps: ["Ask people to change their password.", "Turn on extra sign-in checks.", "Dismiss this if you have already done that."],
  },
  exposed_service: {
    subject: "A public service has a known flaw",
    found: "A service on a domain you checked matches a known flaw.",
    why: "An attacker can use a known flaw to get into an old service.",
    steps: ["Ask your IT helper to update the service.", "Read the source linked on the finding.", "Dismiss this if the service is already patched."],
  },
  ransomware_mention: {
    subject: "Your name was in a public report",
    found: "A public report names an organisation close to yours.",
    why: "It may be a real incident, or it may be a different group with a similar name.",
    steps: ["Read the report date and the source.", "Ask your IT helper if you were affected.", "Challenge the finding if the name is not you."],
  },
  phishing_campaign: {
    subject: "A phishing link may target you",
    found: "We found a phishing link that mentions your name or domain.",
    why: "People who click the link may be asked for a password.",
    steps: ["Do not open the link on a work computer.", "Warn staff not to enter passwords.", "Dismiss this if the link is not about you."],
  },
};

export function renderAlert(finding: Finding, dismissUrl: string): AlertEmail {
  const copy = COPY[finding.kind];
  const sources = finding.provenance.map((item) => `${item.sourceId} (${item.licence})`).join(", ");
  const headline = copy.subject;
  const text = [
    headline,
    "",
    `What we found: ${copy.found}`,
    "",
    `Why it matters: ${copy.why}`,
    "",
    "What to do now:",
    ...copy.steps.map((step, index) => `${index + 1}. ${step}`),
    "",
    `Confidence: ${finding.confidence} out of 100.`,
    `Sources: ${sources}.`,
    `Dismiss: ${dismissUrl}`,
  ].join("\n");
  return { subject: copy.subject, headline, text, steps: copy.steps, dismissUrl };
}

export function assertReadable(email: AlertEmail): void {
  if (wordCount(email.headline) > 12) throw new Error("headline is too long");
  if (email.steps.length > 3) throw new Error("too many steps");
  if (!email.text.includes("Sources:")) throw new Error("sources missing");
  if (!email.text.includes("Confidence:")) throw new Error("confidence missing");
  if (!email.text.includes(email.dismissUrl)) throw new Error("dismiss link missing");
  const grade = fleschKincaidGrade(email.text);
  if (grade > 8) throw new Error(`reading grade ${grade.toFixed(1)} is above year 8`);
}

export type Delivery = "immediate" | "digest" | "none";

export function deliveryPlan(confidence: number, preference: "immediate" | "digest" | "off"): Delivery {
  if (preference === "off" || confidence < 40) return "none";
  if (confidence >= 70 && preference === "immediate") return "immediate";
  return "digest";
}
