import "dotenv/config";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { config } from "../src/lib/config";
import { db } from "../src/lib/db";
import { identityReader } from "../src/lib/keycloak";
import { identityRunSchema, identityToolNameSchema } from "../src/lib/agents/contracts";
import { createIdentityHandlers, identityHandlersForRun } from "../src/lib/mcp/identity-handlers";
import { createIdentityCursorCodec } from "../src/lib/mcp/identity-cursor";
import { createIdentityEvidenceStore, type EventQuery } from "../src/lib/mcp/identity-store";

// Test fixtures live only in session-local TEMP tables. Never inserts into application tables.
async function checkPostgres() {
  const client = await db().connect();
  try {
    await client.query("CREATE TEMP TABLE identity_events (LIKE public.identity_events INCLUDING ALL)");
    await client.query("CREATE TEMP TABLE connector_state (LIKE public.connector_state INCLUDING ALL)");
    const fixtureRows = [
      ["e1", "keycloak.user", "trustmesh", "alice", null, "2026-09-28T09:00:00.000001Z"],
      ["e2", "keycloak.user", "trustmesh", "alice", null, "2026-09-28T09:00:00.000002Z"],
      ["e3", "keycloak.admin", "trustmesh", "administrator", "users/alice/role-mappings/realm", "2026-09-28T09:00:00.000002Z"],
      ["foreign", "keycloak.user", "trustmesh", "bob", null, "2026-09-28T09:00:00Z"],
      ["prefix", "keycloak.admin", "trustmesh", "administrator", "users/alice-extra", "2026-09-28T09:00:00Z"],
      ["realm", "keycloak.admin", "other", "administrator", "users/alice", "2026-09-28T09:00:00Z"],
      ["old", "keycloak.user", "trustmesh", "alice", null, "2026-09-28T07:00:00Z"],
      ["anonymous", "keycloak.user", "trustmesh", null, null, "2026-09-28T09:00:00Z"],
      ["user-resource", "keycloak.user", "trustmesh", "bob", "users/alice", "2026-09-28T09:00:00Z"]
    ];
    for (const row of fixtureRows) {
      await client.query(`INSERT INTO pg_temp.identity_events (id,source,realm,actor_id,resource,occurred_at,event_type,outcome,received_at)
        VALUES ($1,$2,$3,$4,$5,$6,'LOGIN','success','2026-09-28T09:30:00Z')`, row);
    }
    await client.query(`INSERT INTO pg_temp.identity_events (id,source,realm,actor_id,occurred_at,event_type,outcome,received_at)
      VALUES ('late','keycloak.user','trustmesh','alice','2026-09-28T09:00:00Z','LOGIN','success','2026-09-28T10:02:00Z')`);
    const timeRange = { from: "2026-09-28T08:00:00Z", to: "2026-09-28T10:00:00Z" };
    const query: EventQuery = { scope: { realm: "trustmesh", identityId: "alice", timeRange }, timeRange,
      source: "both", eventTypes: [], relationship: "either", pageSize: 100, asOf: "2026-09-28T10:01:00Z" };
    // Pin reads to the connection holding TEMP tables; do not return it to the pool between reads.
    const pinned = { connect: async () => ({ query: client.query.bind(client), release() {} } as unknown as PoolClient) } as unknown as Pick<Pool, "connect">;
    const store = createIdentityEvidenceStore(pinned);
    const read = (q: EventQuery) => store.read(q, AbortSignal.timeout(10000), 10000);
    assert.deepEqual((await read(query)).rows.map(r => r.id), ["e3", "e2", "e1"]);
    assert.deepEqual((await read({ ...query, relationship: "actor" })).rows.map(r => r.id), ["e2", "e1"]);
    assert.deepEqual((await read({ ...query, relationship: "target" })).rows.map(r => r.id), ["e3"]);
    assert.equal((await read({ ...query, eventId: "foreign" })).rows.length, 0);
    assert.equal((await read({ ...query, eventId: "realm" })).rows.length, 0);
    assert.equal((await read({ ...query, eventTypes: ["LOGIN_ERROR"] })).rows.length, 0);
    assert.equal((await read({ ...query, scope: { ...query.scope, identityId: "alice' OR true --" } })).rows.length, 0);
    assert.equal((await read({ ...query, scope: { ...query.scope, identityId: "ali%" }, relationship: "target" })).rows.length, 0);
    const trustedRun = identityRunSchema.parse({
      contractVersion: "identity.v1", agentId: "identity-investigator", runId: randomUUID(), requestedBy: "fixture-analyst",
      createdAt: timeRange.to, question: "Fixture test", scope: query.scope, initialEventIds: [], allowedTools: identityToolNameSchema.options,
      limits: { maxTokens: 10000 }, promptVersion: "v1", modelConfiguration: { provider: "none", model: "none" }
    });
    const handler = createIdentityHandlers(trustedRun, { realm: "trustmesh", reader: identityReader, store,
      now: () => new Date(query.asOf), cursors: createIdentityCursorCodec(randomBytes(32)) });
    let cursor: string | undefined;
    const ids: string[] = [];
    do {
      const result = await handler.execute({ name: "identity_search_events", arguments: { pageSize: 1, ...(cursor ? { cursor } : {}) } });
      assert.ok(result.status === "ok" && result.tool === "identity_search_events");
      ids.push(...result.data.events.map(e => e.id)); cursor = result.nextCursor ?? undefined;
      assert.ok(ids.length <= 3, "Pagination must terminate without duplicates");
    } while (cursor);
    assert.deepEqual(ids, ["e3", "e2", "e1"]);
    const denied = await handler.execute({ name: "identity_get_event", arguments: { eventId: "foreign" } });
    assert.ok(denied.status === "error" && denied.code === "NOT_FOUND");
    // Demonstrate that PostgreSQL, not just a JavaScript timer, bounds statements.
    await client.query("BEGIN READ ONLY");
    await client.query("SELECT set_config('statement_timeout','10',true)");
    await assert.rejects(client.query("SELECT pg_sleep(0.1)"), (error: unknown) =>
      typeof error === "object" && error !== null && "code" in error && error.code === "57014");
    await client.query("ROLLBACK");
    console.log("PostgreSQL integration passed: scope, actor/target, filters, event lookup, microsecond/tie pagination. Fixtures were TEMP only.");
  } finally {
    // Destroy session: TEMP fixtures disappear without touching any persistent application rows.
    client.release(true);
  }
}

async function checkLiveReads() {
  const c = config();
  const alice = (await identityReader.users()).find(u => u.username === "alice");
  assert.ok(alice, "Alice must exist in the local test realm");
  const created = new Date();
  const run = identityRunSchema.parse({
    contractVersion: "identity.v1", agentId: "identity-investigator", runId: randomUUID(), requestedBy: "local-verification",
    createdAt: created.toISOString(), question: "Read-only handler integration check",
    scope: { realm: c.KEYCLOAK_REALM, identityId: alice.id, timeRange: {
      from: new Date(created.getTime() - 6 * 86400000).toISOString(), to: created.toISOString()
    } },
    initialEventIds: [], allowedTools: identityToolNameSchema.options, limits: { maxTokens: 10000 },
    promptVersion: "verification", modelConfiguration: { provider: "none", model: "none" }
  });
  const handler = identityHandlersForRun(run);
  let eventDetailVerified = false;
  for (const name of ["identity_get_profile", "identity_get_roles", "identity_get_sessions", "identity_search_events"]) {
    const result = await handler.execute({ name, arguments: {} });
    assert.ok(result.status === "ok", `${name} did not return validated evidence`);
    if (result.tool === "identity_search_events" && result.data.events.length) {
      const detail = await handler.execute({ name: "identity_get_event", arguments: { eventId: result.data.events[0].id } });
      assert.ok(detail.status === "ok" && detail.tool === "identity_get_event");
      eventDetailVerified = true;
    }
  }
  console.log(JSON.stringify({ liveReadHandlers: "passed", eventDetailVerified, credentialsAndEvidencePrinted: false }));
}

try { await checkPostgres(); await checkLiveReads(); }
catch (error) { console.error(`Handler integration failed (${error instanceof Error ? error.name : "unknown"}); inspect local dependencies without logging secrets.`); process.exitCode = 1; }
finally { await db().end(); }
