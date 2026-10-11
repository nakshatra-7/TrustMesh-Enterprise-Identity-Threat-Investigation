import "dotenv/config";
import assert from "node:assert/strict";
import { config } from "../src/lib/config";
const base = config().APP_URL;
assert.equal((await fetch(`${base}/api/demo/protected`)).status,401);
assert.equal((await fetch(`${base}/api/demo/protected`,{headers:{Authorization:'Bearer invalid'}})).status,401);
const identity = await fetch(`${base}/api/identity`);
assert.equal(identity.status, 401, "Anonymous requests must not read identity inventory");
const logout = await fetch(`${base}/api/auth/logout`, { method: "POST", headers: { Origin: "https://untrusted.example" }, redirect: "manual" });
assert.equal(logout.status, 403, "Cross-origin requests must not clear a console session");
const callback = await fetch(`${base}/api/auth/callback?code=invalid&state=invalid`, { redirect: "manual" });
assert.equal(callback.status, 307);
assert.equal(new URL(callback.headers.get("location")!).searchParams.get("error"), "login-failed");
console.log(JSON.stringify({ anonymousEvidenceAccess:"denied", crossOriginLogout:"denied", unsolicitedCallback:"rejected" }));
for(const path of ['/api/investigations','/api/investigations/00000000-0000-4000-8000-000000000000'])assert.equal((await fetch(`${base}${path}`)).status,401);
for(const path of ['/api/investigations','/api/investigations/00000000-0000-4000-8000-000000000000','/api/actions/00000000-0000-4000-8000-000000000000']){
  assert.equal((await fetch(`${base}${path}`,{method:'POST',headers:{Origin:'https://untrusted.example','Content-Type':'application/json'},body:'{}'})).status,403);
  assert.equal((await fetch(`${base}${path}`,{method:'POST',headers:{Origin:base,'Content-Type':'application/json'},body:'{}'})).status,401);
}
console.log('Investigation and response endpoints reject anonymous access and cross-origin mutations.');
