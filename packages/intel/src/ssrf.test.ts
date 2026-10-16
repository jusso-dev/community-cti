import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { isPrivateAddress, safeFetch } from "./enrich/ssrf.js";

async function listen(handler: Parameters<typeof createServer>[1]): Promise<{ server: Server; port: number; hits: string[] }> {
  const hits: string[] = [];
  const server = createServer((req, res) => {
    hits.push(`${req.headers.host} ${req.url}`);
    handler!(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, port: (server.address() as { port: number }).port, hits };
}

test("private address check covers IPv4 ranges and IPv4 hidden in IPv6", () => {
  const refused = [
    "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255",
    "192.0.0.8", "192.0.2.1", "192.168.1.19", "198.18.0.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "255.255.255.255",
    "::", "::1", "[::1]", "::ffff:127.0.0.1", "::ffff:7f00:1", "::127.0.0.1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1",
    "2002:7f00:1::", "2001:0:4136:e378::1", "2001:db8::1", "fc00::1", "fd12:3456::1", "fe80::1%eth0", "fec0::1", "ff02::1",
    "not-an-ip", "", "1.2.3", "999.1.1.1",
  ];
  for (const ip of refused) assert.equal(isPrivateAddress(ip), true, ip);
  for (const ip of ["1.1.1.1", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "::ffff:1.1.1.1", "64:ff9b::808:808", "2002:0808:0808::"]) {
    assert.equal(isPrivateAddress(ip), false, ip);
  }
});

test("pinned transport dials the address it checked, not a second lookup", async () => {
  const live = await listen((_req, res) => res.end("<html>hello</html>"));
  try {
    let lookups = 0;
    const result = await safeFetch({
      url: `http://pinned.invalid:${live.port}/page`,
      lookup: async () => {
        lookups += 1;
        return ["127.0.0.1"];
      },
      allowAddress: () => true,
    });
    assert.equal(result.ok, true, result.error);
    assert.equal(result.body, "<html>hello</html>");
    assert.equal(lookups, 1, "one resolution per request");
    assert.equal(live.hits[0], `pinned.invalid:${live.port} /page`, "Host header keeps the name");
  } finally {
    live.server.close();
  }
});

test("DNS rebinding to a private address is refused at connect time", async () => {
  const live = await listen((_req, res) => res.end("secret"));
  try {
    // First answer public, every later answer private: the classic rebinding pattern.
    let calls = 0;
    const rebinding = async () => (calls++ === 0 ? ["192.0.2.10"] : ["127.0.0.1"]);
    const allowPublicOnly = (ip: string) => ip === "192.0.2.10";
    const first = await safeFetch({ url: `http://rebind.invalid:${live.port}/`, lookup: rebinding, allowAddress: allowPublicOnly, timeoutMs: 300 });
    assert.notEqual(first.body, "secret");
    const second = await safeFetch({ url: `http://rebind.invalid:${live.port}/`, lookup: rebinding, allowAddress: allowPublicOnly });
    assert.equal(second.error, "private address");
    assert.equal(live.hits.length, 0, "the private server was never reached");
    const mixed = await safeFetch({ url: `http://mixed.invalid:${live.port}/`, lookup: async () => ["192.0.2.10", "127.0.0.1"] });
    assert.equal(mixed.error, "private address");
    assert.equal(live.hits.length, 0);
  } finally {
    live.server.close();
  }
});

test("redirects are re-checked and bodies are capped while streaming", async () => {
  const live = await listen((req, res) => {
    if (req.url === "/redirect") {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end("x".repeat(5000));
  });
  try {
    const lookup = async () => ["127.0.0.1"];
    const allowLocalOnly = (ip: string) => ip === "127.0.0.1";
    const redirected = await safeFetch({ url: `http://site.invalid:${live.port}/redirect`, lookup, allowAddress: allowLocalOnly });
    assert.equal(redirected.error, "private address");
    const big = await safeFetch({ url: `http://site.invalid:${live.port}/big`, lookup, allowAddress: allowLocalOnly, maxBytes: 1000 });
    assert.equal(big.error, "body too large");
  } finally {
    live.server.close();
  }
});

test("literal private IPs, credentials and odd schemes are refused without a request", async () => {
  for (const url of ["http://127.0.0.1/", "http://[::ffff:127.0.0.1]/", "http://2130706433/", "http://0x7f.1/", "http://169.254.169.254/"]) {
    const result = await safeFetch({ url, lookup: async () => { throw new Error("should not resolve"); } });
    assert.equal(result.error, "private address", url);
  }
  assert.equal((await safeFetch({ url: "http://user:pass@example.org/" })).error, "credentials in url refused");
  assert.equal((await safeFetch({ url: "file:///etc/passwd" })).error, "scheme refused");
  assert.equal((await safeFetch({ url: "http://localhost/" })).error, "host refused");
});

test("DNS failure is reported plainly", async () => {
  const result = await safeFetch({ url: "http://nowhere.invalid/", lookup: async () => [] });
  assert.equal(result.error, "dns failed");
});
