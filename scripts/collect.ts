import "dotenv/config";
import { collectIdentityEvents } from "../src/lib/collector";
import { db } from "../src/lib/db";
try { console.log(`Collected ${await collectIdentityEvents()} new evidence events.`); }
finally { await db().end(); }
