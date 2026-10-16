import { createPortal } from "./server.js";

const apiUrl = process.env.API_URL;
if (!apiUrl) {
  console.error("API_URL is required, for example http://api:3001");
  process.exit(1);
}

const port = Number(process.env.PORT ?? 3000);
createPortal({ apiUrl }).listen(port, () => console.log(`portal listening on port ${port}`));
