import { test } from "node:test";
import assert from "node:assert/strict";
import { createApp, defaultDeps } from "./index.js";

test("healthz returns ok", async () => {
  const server = createApp(defaultDeps());
  await new Promise<void>((r) => server.listen(0, r));
  const { port } = server.address() as { port: number };
  const body = await (await fetch(`http://127.0.0.1:${port}/healthz`)).json();
  assert.equal(body.ok, true);
  server.close();
});
