import { readingGrade } from "@community-cti/schema";

export type Preference = "immediate" | "digest" | "off";
export type Channel = "immediate" | "digest" | "none";

/** High confidence can go straight away. Medium waits for the digest. Low stays quiet. */
export function channelFor(confidence: number, preference: Preference): Channel {
  if (preference === "off" || confidence < 40) return "none";
  if (confidence >= 70 && preference === "immediate") return "immediate";
  return "digest";
}

export interface AlertCopy {
  subject: string;
  text: string;
}

const COPY: Record<string, AlertCopy> = {
  lookalike_domain: {
    subject: "A website name looks like yours",
    text: "A website name looks like yours. Do not type your password there. Tell your IT helper.",
  },
  credential_exposure: {
    subject: "A password list may include your team",
    text: "A public breach list may include a work email. Do not send passwords by email. Ask your IT helper to reset it.",
  },
  exposed_service: {
    subject: "A public computer may need a patch",
    text: "A public computer at your organisation may need a security patch. Ask your IT helper to check it.",
  },
  ransomware_mention: {
    subject: "A crime report may name your organisation",
    text: "A public crime report may name your organisation. This is not proof of a break in. Tell your IT helper.",
  },
  phishing_campaign: {
    subject: "A fake website may copy your service",
    text: "A fake website may copy your service. Do not type your password there. Tell your IT helper.",
  },
};

export function alertCopy(kind: string): AlertCopy {
  return COPY[kind] ?? COPY.phishing_campaign!;
}

export function assertPlainAlert(copy: AlertCopy): void {
  const grade = readingGrade(`${copy.subject}. ${copy.text}`);
  if (grade > 8) throw new Error(`alert copy is above Year 8 (${grade.toFixed(1)})`);
}
