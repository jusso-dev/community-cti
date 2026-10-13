import { notificationsFragment } from "../../../src/index";

export default function NotificationsPage() {
  return <div dangerouslySetInnerHTML={{ __html: notificationsFragment() }} />;
}
