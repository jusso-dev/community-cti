import assert from "node:assert/strict";
import { createTestDb, type TestDb } from "@community-cti/db/testing";
import { devEncryptionKey, handle, MemoryObjects, type ApiDeps, type ApiResult } from "./handle.js";

export const FACTORS = JSON.stringify([{ code: "resolves", points: 10, reason: "The name resolves" }]);
export const PROVENANCE = JSON.stringify([{
  sourceId: "crtsh",
  collectedAt: "2026-10-13T00:00:00.000Z",
  licence: "public CT",
  accessRestriction: "TLP:CLEAR",
  evidenceRefs: [],
}]);

export interface InboxMessage {
  to: string;
  subject: string;
  text: string;
}

export interface Harness {
  db: TestDb;
  deps: ApiDeps;
  inbox: InboxMessage[];
  clock: { now: Date };
}

export async function harness(extra: Partial<ApiDeps> = {}): Promise<Harness> {
  const db = await createTestDb();
  const inbox: InboxMessage[] = [];
  const clock = { now: new Date() };
  const deps: ApiDeps = {
    db,
    now: () => clock.now,
    mail: async (message) => { inbox.push(message); },
    resolveTxt: async () => [[]],
    encryptionKey: devEncryptionKey(),
    objects: new MemoryObjects(),
    ...extra,
  };
  return { db, deps, inbox, clock };
}

export async function call(deps: ApiDeps, method: string, url: string, token?: string, body?: unknown): Promise<ApiResult> {
  return handle(deps, {
    method,
    url,
    body,
    ip: "203.0.113.10",
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

export async function login(harness: Harness, email: string): Promise<{ token: string; userId: string }> {
  const before = harness.inbox.length;
  const sent = await call(harness.deps, "POST", "/auth/magic-link", undefined, { email });
  assert.equal(sent.status, 200);
  const message = harness.inbox[before];
  assert.equal(message?.to, email);
  const token = /token=([a-f0-9]+)/.exec(message?.text ?? "")?.[1];
  assert.ok(token);
  const back = await call(harness.deps, "GET", `/auth/callback?token=${token}`);
  assert.equal(back.status, 200);
  return back.body as { token: string; userId: string };
}

export async function createOrg(harness: Harness, token: string, name: string, type = "acco"): Promise<string> {
  const created = await call(harness.deps, "POST", "/orgs", token, { name, type });
  assert.equal(created.status, 200, JSON.stringify(created.body));
  return (created.body as { id: string }).id;
}
