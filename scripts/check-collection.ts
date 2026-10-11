import "dotenv/config";
import assert from "node:assert/strict";
import { collectIdentityEvents } from "../src/lib/collector";
import { db } from "../src/lib/db";
try {
  const first = await collectIdentityEvents();
  const before = await db().query("SELECT id FROM identity_events ORDER BY id");
  const second = await collectIdentityEvents();
  const after = await db().query("SELECT id FROM identity_events ORDER BY id");
  const existing = new Set(after.rows.map(r=>r.id));
  assert.ok(before.rows.every(r=>existing.has(r.id)), "Earlier evidence must persist");
  const duplicates = await db().query("SELECT id FROM identity_events GROUP BY id HAVING count(*)>1");
  assert.equal(duplicates.rowCount, 0);
  const states = await db().query("SELECT source,status FROM connector_state");
  assert.equal(states.rows.length, 2);
  assert.ok(states.rows.every(r=>r.status==='healthy'));
  console.log(JSON.stringify({firstNewEvents:first,secondNewEvents:second,evidencePreserved:true,duplicates:0,bothSourcesHealthy:true}));
} catch { console.error("Collection verification failed; check the local services and event schema."); process.exitCode=1; }
finally { await db().end(); }
