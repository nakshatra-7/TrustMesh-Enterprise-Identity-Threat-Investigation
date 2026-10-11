import "dotenv/config";
import { Queue, Worker } from "bullmq";
import { config } from "../lib/config";
import { collectIdentityEvents } from "../lib/collector";
import { db } from "../lib/db";

const url = new URL(config().REDIS_URL);
const connection = { host: url.hostname, port: Number(url.port || 6379), maxRetriesPerRequest: null };
const queue = new Queue("identity-collection", { connection });
const worker = new Worker("identity-collection", async () => {
  const inserted = await collectIdentityEvents();
  console.log(JSON.stringify({ job: "identity-collection", inserted, completedAt: new Date().toISOString() }));
}, { connection, concurrency: 1 });
worker.on("failed", (_job, error) => console.error(JSON.stringify({ job: "identity-collection", status: "failed", kind: error.name })));
worker.on("error", () => console.error("Identity worker connection error; checking infrastructure is required."));
await queue.upsertJobScheduler("poll-keycloak", { every: 5000 }, {
  name: "poll", opts: { attempts: 3, backoff: { type: "exponential", delay: 2000 }, removeOnComplete: 20, removeOnFail: 20 }
});
console.log("Identity collector scheduled every five seconds. No containment actions are enabled.");
let stopping = false;
async function shutdown() {
  if (stopping) return; stopping = true;
  await worker.close(); await queue.close(); await db().end();
}
process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());
