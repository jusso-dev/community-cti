import { assertAustralianRegion, DEFAULT_EMAIL_REGION } from "@community-cti/schema";
import type { AlertEmail } from "./templates.js";

export interface Mailer {
  send(message: AlertEmail & { to: string }): Promise<{ messageId: string }>;
}

export class SinkMailer implements Mailer {
  readonly sent: Array<AlertEmail & { to: string; messageId: string }> = [];
  async send(message: AlertEmail & { to: string }): Promise<{ messageId: string }> {
    const messageId = `local-${this.sent.length + 1}`;
    this.sent.push({ ...message, messageId });
    return { messageId };
  }
}

/** Production mail must stay in an Australian region. This adapter does not send. */
export function createAuMailer(region = DEFAULT_EMAIL_REGION): Mailer {
  assertAustralianRegion(region);
  return {
    async send() {
      throw new Error("email provider is not configured");
    },
  };
}
