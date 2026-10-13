import { findingDetailFragment, SAMPLE_FINDINGS } from "../../../src/index";

export function generateStaticParams() {
  return SAMPLE_FINDINGS.map((finding) => ({ id: finding.id }));
}

export const dynamicParams = false;

export default function FindingPage({ params }: { params: { id: string } }) {
  const { id } = params;
  const finding = SAMPLE_FINDINGS.find((item) => item.id === id);
  if (!finding) {
    return <main><h1>Finding</h1><p>That finding was not found.</p></main>;
  }
  return <div dangerouslySetInnerHTML={{ __html: findingDetailFragment(finding) }} />;
}
