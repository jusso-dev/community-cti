export const onboardingCopy = {
  title: "Set up your organisation",
  intro: "Create your organisation. We only watch domains you prove you control.",
  consent: "I am allowed to act for this organisation and I agree to public domain monitoring.",
  domainHelp: "Add a DNS TXT record with the value we give you. We can also email admin, postmaster or webmaster at that domain.",
  monitoringWait: "Monitoring starts after you record consent.",
};

const JARGON = /\b(STIX|IOC|TTP|SIEM|payload|exploit)\b/i;

export function assertPlainCopy(text: string): void {
  if (JARGON.test(text)) throw new Error("copy uses specialist jargon");
  if (text.includes("organization")) throw new Error("use Australian spelling organisation");
}
