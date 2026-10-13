/**
 * SpaceXAI is the model provider. It is served by the xAI API.
 * Live calls stay off until a real Australian residency exception is approved.
 * This file does not grant that exception.
 */
export const MODEL_ID = "grok-4.7";
export const MODEL_BASE_URL = "https://api.x.ai/v1";
export const MODEL_RESIDENCY_APPROVED = false;

export interface ToolCall {
  name: string;
  arguments: unknown;
}

export interface ModelTurn {
  text: string;
  toolCalls: ToolCall[];
  tokensIn: number;
  tokensOut: number;
}

export interface Model {
  id: string;
  complete(input: { system: string; user: string }): Promise<ModelTurn>;
}

export function scriptedModel(turn: ModelTurn): Model {
  return { id: "scripted", async complete() { return turn; } };
}

type FetchLike = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export async function completeWithSpaceXai(apiKey: string, user: string, fetchImpl: FetchLike): Promise<string> {
  const response = await fetchImpl(`${MODEL_BASE_URL}/responses`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: MODEL_ID,
      input: [{ role: "user", content: user }],
    }),
  });
  if (!response.ok) throw new Error(`model request failed (${response.status})`);
  const body = await response.json() as { output?: Array<{ type?: string; content?: Array<{ text?: string }> }> };
  const message = body.output?.find((item) => item.type === "message");
  return message?.content?.map((part) => part.text ?? "").join("") ?? "";
}

/** Returns a live model only when residency has been approved and a key is set. */
export function modelFromEnv(env: { XAI_API_KEY?: string }): Model | null {
  if (!MODEL_RESIDENCY_APPROVED) return null;
  if (!env.XAI_API_KEY) return null;
  return {
    id: MODEL_ID,
    async complete({ user }) {
      const text = await completeWithSpaceXai(env.XAI_API_KEY!, user, (url, init) => fetch(url, init));
      return { text, toolCalls: [], tokensIn: 0, tokensOut: 0 };
    },
  };
}
