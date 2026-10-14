import { createApp, defaultDeps } from "./app.js";

export { createApp, defaultDeps, ROUTES } from "./app.js";
export { MemoryStore } from "./store.js";
export { onboardingCopy } from "./copy.js";

export const server = createApp(defaultDeps());

if (process.env.START_SERVER === "1") {
  server.listen(Number(process.env.PORT ?? 8080));
}
