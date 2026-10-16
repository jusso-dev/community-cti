import { createTransport } from "nodemailer";
import { assertAustralianRegion, DEFAULT_EMAIL_REGION } from "@community-cti/schema";

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  /** Stable key so a retried send is not delivered twice, for example `alert:<finding>:<user>`. */
  idempotencyKey?: string;
  /** Short label for delivery reporting, for example `sign_in` or `alert`. */
  category?: string;
}

export interface Mailer {
  send(message: MailMessage): Promise<{ messageId: string }>;
}

export class SinkMailer implements Mailer {
  readonly sent: Array<MailMessage & { messageId: string }> = [];
  async send(message: MailMessage): Promise<{ messageId: string }> {
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

/**
 * SMTP relay, for example Mailpit in a test environment or an Australian
 * relay in production. The caller checks the relay's region; the URL holds
 * any credentials, so it comes from the environment and is never logged.
 */
export function createSmtpMailer(options: { url: string; from: string; region?: string }): Mailer {
  assertAustralianRegion(options.region ?? DEFAULT_EMAIL_REGION);
  const transport = createTransport(options.url);
  return {
    async send(message) {
      const info = await transport.sendMail({ from: options.from, to: message.to, subject: message.subject, text: message.text });
      return { messageId: String(info.messageId) };
    },
  };
}

export class MailSendError extends Error {
  constructor(message: string, readonly status: number, readonly retryAfterSeconds: number | null) {
    super(message);
    this.name = "MailSendError";
  }

  get retryable(): boolean {
    return this.status === 0 || this.status === 429 || this.status >= 500;
  }
}

const TAG = /^[A-Za-z0-9_-]{1,256}$/;
const IDEMPOTENCY = /^[!-~]{1,256}$/;

/**
 * PaperBoy, the self-hosted transactional email service on homelab.
 * The API key decides the organisation and whether mail goes to PaperBoy's
 * test sink (pb_test_) or out through a verified domain (pb_live_).
 */
export function createPaperboyMailer(options: {
  baseUrl: string;
  apiKey: string;
  from: string;
  region?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}): Mailer {
  assertAustralianRegion(options.region ?? DEFAULT_EMAIL_REGION);
  if (!/^pb_(live|test)_/.test(options.apiKey)) throw new Error("PAPERBOY_API_KEY must be a pb_live_ or pb_test_ key");
  const endpoint = new URL("/api/v1/emails", options.baseUrl).toString();
  const fetchImpl = options.fetchImpl ?? fetch;
  return {
    async send(message) {
      const tags = [{ name: "app", value: "community-cti" }];
      if (message.category && TAG.test(message.category)) tags.push({ name: "category", value: message.category });
      const idempotencyKey = message.idempotencyKey && IDEMPOTENCY.test(message.idempotencyKey) ? message.idempotencyKey : undefined;
      let response: Response;
      try {
        response = await fetchImpl(endpoint, {
          method: "POST",
          headers: {
            authorization: `Bearer ${options.apiKey}`,
            "content-type": "application/json",
            ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}),
          },
          body: JSON.stringify({ from: options.from, to: [message.to], subject: message.subject, text: message.text, tags }),
          signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
        });
      } catch (error) {
        throw new MailSendError(`PaperBoy unreachable: ${error instanceof Error ? error.name : "error"}`, 0, null);
      }
      const body = await response.json().catch(() => ({})) as { id?: string; error?: { message?: string } | string };
      if (!response.ok) {
        const retryAfter = Number(response.headers.get("retry-after"));
        const detail = typeof body.error === "string" ? body.error : body.error?.message ?? "";
        throw new MailSendError(`PaperBoy refused the email (${response.status})${detail ? `: ${detail.slice(0, 200)}` : ""}`, response.status, Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null);
      }
      if (!body.id) throw new MailSendError("PaperBoy did not return a message id", response.status, null);
      return { messageId: body.id };
    },
  };
}

export type MailerKind = "paperboy" | "smtp" | "sink";

/**
 * Picks the mail transport from the environment: PaperBoy when
 * PAPERBOY_URL and PAPERBOY_API_KEY are set, else SMTP_URL, else an
 * in-memory sink. Secrets stay inside the returned mailer.
 */
export function mailerFromEnv(env: Record<string, string | undefined>): { mailer: Mailer; kind: MailerKind } {
  const from = env.MAIL_FROM ?? "Community CTI <no-reply@localhost>";
  if (env.PAPERBOY_URL && env.PAPERBOY_API_KEY) {
    return { kind: "paperboy", mailer: createPaperboyMailer({ baseUrl: env.PAPERBOY_URL, apiKey: env.PAPERBOY_API_KEY, from, region: env.EMAIL_REGION }) };
  }
  if (env.SMTP_URL) return { kind: "smtp", mailer: createSmtpMailer({ url: env.SMTP_URL, from, region: env.EMAIL_REGION }) };
  return { kind: "sink", mailer: new SinkMailer() };
}
