import { test } from "node:test";
import assert from "node:assert/strict";
import { attachCertstream, crtshUrl, nextBackoffMs, readCertMessage } from "./ct.js";

test("certificate transparency backoff and crt.sh query stay local", () => {
  assert.equal(nextBackoffMs(0), 1000);
  assert.equal(nextBackoffMs(1), 2000);
  assert.equal(nextBackoffMs(5), 30_000);
  const url = new URL(crtshUrl("council.org.au"));
  assert.equal(url.hostname, "crt.sh");
  assert.equal(url.searchParams.get("q"), "%.council.org.au");
  assert.deepEqual(readCertMessage(JSON.stringify({ data: { leaf_cert: { all_domains: ["a.example"] } } })).allDomains, ["a.example"]);
});

test("certstream uses the injected socket and backs off", async () => {
  const names: string[] = [];
  const sleeps: number[] = [];
  let connects = 0;
  const handle = attachCertstream(() => {
    connects += 1;
    return {
      send() {},
      close() {},
      onMessage(handler) {
        handler(JSON.stringify({ data: { leaf_cert: { all_domains: ["examp1e.org.au"] } } }));
      },
      onClose(handler) {
        handler();
      },
    };
  }, (name) => names.push(name), async (ms) => {
    sleeps.push(ms);
    if (ms >= 1000) queueMicrotask(() => handle.stop());
  });
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.deepEqual(names, ["examp1e.org.au"]);
  assert.equal(connects, 1);
  assert.ok(sleeps.includes(1000));
});
