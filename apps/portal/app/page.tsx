import { dashboardFragment, SAMPLE_FINDINGS } from "../src/index";

export default function HomePage() {
  const html = `<p>This list shows an example until you sign in.</p>${dashboardFragment(SAMPLE_FINDINGS)}`;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
