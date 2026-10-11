import { test } from "node:test";
import assert from "node:assert/strict";
import type { Pool, PoolClient } from "pg";
import { createIdentityEvidenceStore, type EventQuery } from "../src/lib/mcp/identity-store";

const timeRange = { from: "2026-09-28T08:00:00Z", to: "2026-09-28T10:00:00Z" };
const query: EventQuery = { scope: { realm: "lab", identityId: "alice", timeRange }, timeRange, source: "both",
  relationship: "either", eventTypes: [], pageSize: 25, asOf: "2026-09-28T10:00:01Z" };

test("store uses a read-only transaction, statement timeout and rollback/release on errors", async () => {
  const commands: string[] = []; let released = false;
  const pool = { connect: async () => ({
    query: async (input: string | { text: string }) => {
      const text = typeof input === "string" ? input : input.text;
      commands.push(text);
      if (text.includes("FROM identity_events")) throw new Error("fixture database error");
      return { rows: [] };
    }, release: () => { released = true; }
  } as unknown as PoolClient) } as unknown as Pick<Pool, "connect">;
  await assert.rejects(createIdentityEvidenceStore(pool).read(query, new AbortController().signal, 1000));
  assert.equal(commands[0], "BEGIN READ ONLY");
  assert.ok(commands[1].includes("statement_timeout"));
  assert.equal(commands.at(-1), "ROLLBACK"); assert.equal(released, true);
});

test("cancelled store reads do not acquire a connection", async () => {
  let connections = 0;
  const pool = { connect: async () => { connections++; throw new Error("must not connect"); } } as unknown as Pick<Pool, "connect">;
  const controller = new AbortController(); controller.abort();
  await assert.rejects(createIdentityEvidenceStore(pool).read(query, controller.signal, 1000));
  assert.equal(connections, 0);
});
