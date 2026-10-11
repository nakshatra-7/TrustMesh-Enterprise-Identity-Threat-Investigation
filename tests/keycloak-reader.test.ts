import { test } from "node:test";
import assert from "node:assert/strict";
import { KeycloakReader, KeycloakError } from "../src/lib/keycloak";

// File-isolated Node test process: synthetic configuration, no local secrets loaded.
Object.assign(process.env, {
  APP_URL: "http://localhost:3000", KEYCLOAK_URL: "http://localhost:8080", KEYCLOAK_REALM: "test",
  KEYCLOAK_CONSOLE_ID: "console", KEYCLOAK_CONSOLE_SECRET: "fixture-secret-only", KEYCLOAK_READER_ID: "reader",
  KEYCLOAK_READER_SECRET: "fixture-secret-only", DATABASE_URL: "not-used", REDIS_URL: "redis://localhost:6379", COOKIE_SECRET: "a".repeat(64)
});

test("targeted user lookup encodes IDs and reuses a machine token without listing users", async () => {
  const urls: string[] = [];
  const reader = new KeycloakReader(async (input, init) => {
    const url = String(input); urls.push(url);
    if (url.endsWith("/token")) return Response.json({ access_token: "fixture-token", expires_in: 300 });
    assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer fixture-token");
    return Response.json({ id: "a/b", username: "test", credentials: ["must-not-pass"] });
  });
  assert.deepEqual(await reader.user("a/b"), { id: "a/b", username: "test" });
  await reader.user("a/b");
  assert.equal(urls.filter(u => u.endsWith("/token")).length, 1);
  assert.ok(urls[1].endsWith("/users/a%2Fb"));
});

test("a rejected machine token is refreshed once, not indefinitely", async () => {
  let tokens = 0, reads = 0;
  const reader = new KeycloakReader(async input => {
    if (String(input).endsWith("/token")) { tokens++; return Response.json({ access_token: "fixture", expires_in: 300 }); }
    reads++; return new Response(null, { status: 401 });
  });
  await assert.rejects(reader.user("alice"), KeycloakError);
  assert.equal(tokens, 2); assert.equal(reads, 2);
});

test("an already cancelled lookup never contacts the provider", async () => {
  let calls = 0;
  const reader = new KeycloakReader(async () => { calls++; return Response.json({}); });
  const controller = new AbortController(); controller.abort();
  await assert.rejects(reader.user("alice", controller.signal));
  assert.equal(calls, 0);
});
