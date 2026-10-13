import { createServer } from "node:http";
import { validateFinding } from "@community-cti/schema";

export const server = createServer((req, res) => {
  if (req.url === "/healthz") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, validator: typeof validateFinding === "function" }));
    return;
  }
  res.writeHead(404).end();
});

if (process.env.START_SERVER === "1") {
  server.listen(Number(process.env.PORT ?? 8080));
}
