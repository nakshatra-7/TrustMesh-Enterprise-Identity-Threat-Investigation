import { test } from "node:test";
import assert from "node:assert/strict";
import { allowsLocalHttp, isAnalyst } from "../src/lib/access";
test("employee authentication cannot grant SOC access", () => {
  for (const roles of [undefined, [], ["employee"], "soc-analyst", ["soc-analyst-admin"]]) assert.equal(isAnalyst(roles), false);
  assert.equal(isAnalyst(["employee", "soc-analyst"]), true);
});
test("insecure OIDC transport is restricted to local loopback hosts", () => {
  assert.equal(allowsLocalHttp(new URL("http://localhost:8080")), true);
  for (const url of ["http://localhost.evil.test", "http://10.0.0.1", "http://example.test"]) assert.equal(allowsLocalHttp(new URL(url)), false);
});
