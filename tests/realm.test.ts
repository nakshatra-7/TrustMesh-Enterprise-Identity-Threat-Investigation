import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const realm = JSON.parse(readFileSync(new URL("../infra/keycloak/trustmesh-realm.json", import.meta.url), "utf8"));
test("reader has no containment roles and employee has no analyst role", () => {
  const reader = realm.users.find((u: {username: string}) => u.username === "service-account-trustmesh-reader");
  assert.ok(reader.clientRoles["realm-management"].every((r: string) => r.startsWith("view-") || r.startsWith("query-")));
  const employee = realm.users.find((u: {username: string}) => u.username === "alice");
  assert.deepEqual(employee.realmRoles, ["employee"]);
});
test("login uses authorization code with PKCE and no password grants", () => {
  const consoleClient = realm.clients.find((c: {clientId:string}) => c.clientId === "trustmesh-console");
  assert.equal(consoleClient.attributes["pkce.code.challenge.method"], "S256");
  assert.equal(consoleClient.directAccessGrantsEnabled, false);
  assert.ok(consoleClient.protocolMappers.some((m: {protocolMapper:string;config:Record<string,string>}) => m.protocolMapper === 'oidc-audience-mapper' && m.config['included.client.audience'] === consoleClient.clientId));
  assert.equal(realm.eventsEnabled, true);
  assert.equal(realm.adminEventsEnabled, true);
  assert.equal(realm.adminEventsDetailsEnabled, false);
});
