import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { identityRunSchema, identityToolNameSchema } from "../src/lib/agents/contracts";
import { affectedIdentityId, createIdentityHandlers } from "../src/lib/mcp/identity-handlers";
import { createIdentityCursorCodec } from "../src/lib/mcp/identity-cursor";
import { buildIdentityEventQuery, type EventQuery, type EventRow, type IdentityEvidenceStore } from "../src/lib/mcp/identity-store";
import { KeycloakError } from "../src/lib/keycloak";

const now = () => new Date("2026-09-28T10:01:00Z");
const timeRange = { from: "2026-09-28T08:00:00Z", to: "2026-09-28T10:00:00Z" };
function run() {
  return identityRunSchema.parse({
    contractVersion: "identity.v1", agentId: "identity-investigator", runId: "af7a990a-0871-4df1-a14b-e43f3d7b369c",
    requestedBy: "analyst", createdAt: timeRange.to, question: "Investigate activity.",
    scope: { realm: "trustmesh", identityId: "alice", timeRange }, initialEventIds: [],
    allowedTools: identityToolNameSchema.options, limits: { maxTokens: 10000 }, promptVersion: "v1",
    modelConfiguration: { provider: "test", model: "fixture" }
  });
}
function row(id = "e1"): EventRow {
  return {
    id, source: "keycloak.user", realm: "trustmesh", event_type: "LOGIN", occurred_at: new Date("2026-09-28T09:00:00Z"),
    cursor_time: "2026-09-28T09:00:00.000001Z", actor_id: "alice", session_id: null, client_id: null,
    ip_address: null, resource: null, outcome: "success", details: { auth_method: "openid-connect", access_token: "DO_NOT_EXPOSE" }
  };
}
function dependencies() {
  return {
    realm: "trustmesh", now, cursors: createIdentityCursorCodec(randomBytes(32)),
    reader: {
      user: async (id: string) => ({ id, username: "alice", enabled: true }),
      roles: async (_id: string) => [{ name: "employee" }],
      sessions: async (_id: string) => [{ id: "s1", userId: "alice", start: Date.parse(timeRange.from), lastAccess: Date.parse(timeRange.to), clients: { c: "account-console" } }]
    },
    store: { read: async () => ({ rows: [row()], coverage: [] }) } as IdentityEvidenceStore
  };
}

test("all five handlers produce scoped evidence without a model", async () => {
  const handlers = createIdentityHandlers(run(), dependencies());
  for (const name of identityToolNameSchema.options) {
    const result = await handlers.execute({ name, arguments: name === "identity_get_event" ? { eventId: "e1" } : {} });
    assert.equal(result.status, "ok");
    if (result.status !== "ok") continue;
    assert.equal(result.identityId, "alice"); assert.equal(result.runId, run().runId);
    assert.ok(result.evidenceRef); assert.equal(JSON.stringify(result).includes("DO_NOT_EXPOSE"), false);
    if (result.tool === "identity_get_sessions") assert.equal(result.data.sessions[0].startedAt, timeRange.from.replace("Z", ".000Z"));
  }
});

test("arguments and allowlists are enforced before calling dependencies", async () => {
  const deps = dependencies(); let calls = 0;
  deps.reader.user = async id => { calls++; return { id, username: "alice", enabled: true }; };
  const handlers = createIdentityHandlers({ ...run(), allowedTools: ["identity_get_profile"] }, deps);
  for (const call of [
    { name: "identity_get_profile", arguments: { identityId: "bob" } },
    { name: "identity_get_roles", arguments: {} },
    { name: "cloud_get_keys", arguments: {} }
  ]) assert.equal((await handlers.execute(call)).status, "error");
  assert.equal(calls, 0);
  assert.throws(() => createIdentityHandlers({ ...run(), scope: { ...run().scope, realm: "other" } }, deps));
});

test("snapshot responses reject wrong owners, cap rows and record missing values", async () => {
  const deps = dependencies();
  deps.reader.sessions = async () => [{ id: "s", userId: "bob", start: 0, lastAccess: 0, clients: { c: "client" } }];
  assert.equal((await createIdentityHandlers(run(), deps).execute({ name: "identity_get_sessions", arguments: {} })).status, "error");
  deps.reader.roles = async () => Array.from({ length: 101 }, (_, i) => ({ name: `role-${i}` }));
  const result = await createIdentityHandlers(run(), deps).execute({ name: "identity_get_roles", arguments: {} });
  assert.ok(result.status === "ok" && result.tool === "identity_get_roles");
  assert.equal(result.data.roles.length, 100); assert.equal(result.truncated, true); assert.equal(result.nextCursor, null);
});

test("large session payloads are bounded with explicit truncation, not an unbounded model response", async () => {
  const deps = dependencies();
  const reader = { ...deps.reader, sessions: async () => Array.from({ length: 100 }, (_, i) => ({
    id: `s${i}`, clients: Object.fromEntries(Array.from({ length: 100 }, (_, j) => [`c${j}`, "x".repeat(250)]))
  })) };
  const result = await createIdentityHandlers(run(), { ...deps, reader }).execute({ name: "identity_get_sessions", arguments: {} });
  assert.ok(result.status === "ok" && result.tool === "identity_get_sessions");
  assert.ok(result.truncated); assert.ok(result.data.sessions.length < 100);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) <= 65536);
  assert.equal(result.data.sessions[0].startedAt, null);
});

test("unexpected repository rows fail closed instead of exposing unrelated evidence", async () => {
  const deps = dependencies();
  for (const wrong of [{ ...row(), actor_id: "bob" }, { ...row(), realm: "other" }, { ...row(), occurred_at: new Date("2026-09-28T07:00:00Z") }]) {
    deps.store.read = async () => ({ rows: [wrong], coverage: [] });
    const result = await createIdentityHandlers(run(), deps).execute({ name: "identity_search_events", arguments: {} });
    assert.equal(result.status, "error");
  }
  deps.store.read = async () => ({ rows: [row("different-event")], coverage: [] });
  assert.equal((await createIdentityHandlers(run(), deps).execute({ name: "identity_get_event", arguments: { eventId: "e1" } })).status, "error");
});

test("admin resource matching uses exact path segments, not prefixes or decoded guesses", () => {
  assert.equal(affectedIdentityId("keycloak.admin", "users/alice/role-mappings/realm"), "alice");
  assert.equal(affectedIdentityId("keycloak.admin", "users/alice-extra"), "alice-extra");
  for (const path of ["users/", "other/users/alice", "users/%61lice", "users/../alice"]) {
    assert.equal(affectedIdentityId("keycloak.admin", path), null);
  }
  assert.equal(affectedIdentityId("keycloak.user", "users/alice"), null);
});

test("empty scoped event reads are NOT_FOUND while empty search has coverage warnings", async () => {
  const deps = dependencies(); deps.store.read = async () => ({ rows: [], coverage: [] });
  const handlers = createIdentityHandlers(run(), deps);
  const missing = await handlers.execute({ name: "identity_get_event", arguments: { eventId: "other-identity-event" } });
  assert.ok(missing.status === "error" && missing.code === "NOT_FOUND");
  const empty = await handlers.execute({ name: "identity_search_events", arguments: {} });
  assert.ok(empty.status === "ok" && empty.tool === "identity_search_events");
  assert.equal(empty.data.events.length, 0); assert.ok(empty.coverageWarnings.some(w => w.includes("stale")));
});

test("provider errors are sanitized and authorization failures are not retried", async () => {
  const deps = dependencies();
  for (const error of [new KeycloakError(403), new KeycloakError(404), new Error("secret=DO_NOT_EXPOSE")]) {
    deps.reader.user = async () => { throw error; };
    const result = await createIdentityHandlers(run(), deps).execute({ name: "identity_get_profile", arguments: {} });
    assert.equal(result.status, "error"); assert.equal(JSON.stringify(result).includes("DO_NOT_EXPOSE"), false);
    if (result.status === "error" && error instanceof KeycloakError) assert.equal(result.retryable, false);
  }
});

test("timeouts abort provider work and cancellation is non-retryable", async () => {
  const deps = dependencies(); let aborted = false;
  const reader = { ...deps.reader, user: async (_id: string, signal?: AbortSignal): Promise<never> => new Promise((_, reject) => {
    signal!.addEventListener("abort", () => { aborted = true; reject(new DOMException("aborted", "AbortError")); }, { once: true });
  }) };
  const handlers = createIdentityHandlers({ ...run(), limits: { ...run().limits, toolTimeoutMs: 10 } }, { ...deps, reader });
  const result = await handlers.execute({ name: "identity_get_profile", arguments: {} });
  assert.ok(result.status === "error" && result.code === "TIMEOUT"); assert.equal(aborted, true);
  const controller = new AbortController(); controller.abort();
  const cancelled = await handlers.execute({ name: "identity_get_profile", arguments: {} }, controller.signal);
  assert.ok(cancelled.status === "error" && cancelled.retryable === false);
});

test("cursor is encrypted, query/run-bound, tamper-evident and expires", () => {
  const codec = createIdentityCursorCodec(randomBytes(32));
  const binding = { runId: run().runId, query: "same" };
  const token = codec.encode(binding, now().toISOString(), { time: row().cursor_time, id: "private-event-id" }, now().getTime() + 1000);
  assert.equal(token.includes("private-event-id"), false);
  assert.equal(codec.decode(token, binding, now().getTime()).position.time, row().cursor_time);
  assert.throws(() => codec.decode(token, { ...binding, query: "other" }, now().getTime()));
  assert.throws(() => codec.decode(`${token.slice(0, 20)}${token[20] === "A" ? "B" : "A"}${token.slice(21)}`, binding, now().getTime()));
  assert.throws(() => codec.decode(token, binding, now().getTime() + 1000));
});

test("handler pagination preserves microseconds and rejects changed filters, target, caller and run", async () => {
  const deps = dependencies(); let query: EventQuery | undefined;
  deps.store.read = async q => { query = q; return { rows: q.position ? [row("older")] : [row("newer"), row("older")], coverage: [] }; };
  const handler = createIdentityHandlers(run(), deps);
  const first = await handler.execute({ name: "identity_search_events", arguments: { pageSize: 1 } });
  assert.ok(first.status === "ok" && first.nextCursor);
  const second = await handler.execute({ name: "identity_search_events", arguments: { pageSize: 1, cursor: first.nextCursor } });
  assert.equal(second.status, "ok"); assert.equal(query!.position!.time, row().cursor_time);
  for (const args of [{ pageSize: 2 }, { pageSize: 1, source: "admin" }, { pageSize: 1, relationship: "actor" }]) {
    assert.equal((await handler.execute({ name: "identity_search_events", arguments: { ...args, cursor: first.nextCursor } })).status, "error");
  }
  for (const changed of [
    { ...run(), runId: "da91ec65-4cbe-424e-a30f-78576f8c1e93" },
    { ...run(), requestedBy: "other-analyst" }, { ...run(), scope: { ...run().scope, identityId: "bob" } }
  ]) assert.equal((await createIdentityHandlers(changed, deps).execute({ name: "identity_search_events", arguments: { pageSize: 1, cursor: first.nextCursor } })).status, "error");
});

test("SQL scopes both actor and target branches and binds untrusted values", () => {
  const query: EventQuery = { scope: { ...run().scope, identityId: "alice' OR true --" }, timeRange, source: "both", relationship: "either", eventTypes: ["LOGIN"], pageSize: 25, asOf: now().toISOString() };
  const sql = buildIdentityEventQuery(query);
  assert.equal(sql.text.includes(query.scope.identityId), false);
  assert.ok(sql.text.includes("realm=$1")); assert.ok(sql.text.includes("actor_id=$2 OR"));
  assert.equal(sql.text.includes("LIKE"), false); assert.equal(sql.values[1], query.scope.identityId);
  assert.equal(sql.values.at(-1), 26);
});
