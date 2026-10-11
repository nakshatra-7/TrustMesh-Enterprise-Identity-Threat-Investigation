import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeEvent } from "../src/lib/events";
const event = { id: "e1", time: 1789999999999, type: "LOGIN", userId: "alice", sessionId: "reference", clientId: "account-console", details: { auth_method: "openid-connect", password: "DO_NOT_STORE", access_token: "DO_NOT_STORE", redirect_uri: "https://example.test/?token=DO_NOT_STORE" } };
test("evidence uses an allowlist and never preserves complete provider payloads", () => {
  const result = normalizeEvent({ ...event, representation: "DO_NOT_STORE" }, "user", "lab");
  assert.deepEqual(result.details, { auth_method: "openid-connect" });
  assert.ok(!JSON.stringify(result).includes("DO_NOT_STORE"));
  assert.equal(result.sessionId, "reference");
});
test("provider IDs are stable and namespaced by realm and event source", () => {
  assert.equal(normalizeEvent(event,"user","lab").id, normalizeEvent(event,"user","lab").id);
  assert.notEqual(normalizeEvent(event,"user","lab").id, normalizeEvent(event,"user","other").id);
});
test("events without IDs have deterministic fingerprints", () => {
  const input = { ...event, id: undefined };
  assert.equal(normalizeEvent(input,"user","lab").id, normalizeEvent(input,"user","lab").id);
  assert.notEqual(normalizeEvent(input,"user","lab").id, normalizeEvent({ ...input, time: input.time+1 },"user","lab").id);
});
test("failures and missing telemetry are represented honestly", () => {
  const failed = normalizeEvent({ time: event.time, type: "LOGIN_ERROR", error: "invalid_user_credentials" }, "user", "lab");
  assert.equal(failed.outcome, "failure");
  assert.equal(failed.actorId, undefined);
  assert.throws(() => normalizeEvent({ type: "LOGIN" }, "user", "lab"));
});
test("admin events use authenticated actor rather than affected resource identity", () => {
  const result = normalizeEvent({ time: event.time, operationType: "UPDATE", resourceType: "USER", resourcePath: "users/alice", authDetails: { userId: "administrator", clientId: "admin-cli" } }, "admin", "lab");
  assert.equal(result.actorId, "administrator"); assert.equal(result.resource, "users/alice");
});
