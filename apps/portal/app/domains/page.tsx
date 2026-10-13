import { domainsFragment } from "../../src/index";

export default function DomainsPage() {
  return <div dangerouslySetInnerHTML={{ __html: domainsFragment() }} />;
}
