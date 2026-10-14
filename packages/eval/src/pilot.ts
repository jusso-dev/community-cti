import { summarisePilot } from "./metrics.js";

const summary = summarisePilot([]);
console.log(JSON.stringify(summary, null, 2));
