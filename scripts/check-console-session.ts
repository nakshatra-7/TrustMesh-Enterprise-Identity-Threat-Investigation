import "dotenv/config";
import { jwtDecrypt, decodeJwt } from "jose";
import * as oidc from "openid-client";
import { db } from "../src/lib/db";
import { config, issuer } from "../src/lib/config";
import { identityReader } from "../src/lib/keycloak";
import { allowsLocalHttp } from "../src/lib/access";
const c = config();
try {
  const result = await db().query("SELECT subject,encrypted_access_token,expires_at FROM console_sessions ORDER BY created_at DESC LIMIT 1");
  if (!result.rows.length) throw new Error("No console login has completed yet.");
  const row = result.rows[0];
  const payload = (await jwtDecrypt(row.encrypted_access_token, Buffer.from(c.COOKIE_SECRET,"hex"), { audience: "console-access-token" })).payload;
  const url = new URL(issuer());
  const client = await oidc.discovery(url,c.KEYCLOAK_CONSOLE_ID,c.KEYCLOAK_CONSOLE_SECRET,undefined,{execute:allowsLocalHttp(url)?[oidc.allowInsecureRequests]:undefined});
  const inspected = await oidc.tokenIntrospection(client,String(payload.token));
  const claims = decodeJwt(String(payload.token));
  const roles = await identityReader.roles(row.subject);
  console.log(JSON.stringify({ storedSession: true, unexpired: new Date(row.expires_at).getTime()>Date.now(), active: inspected.active, subjectMatches: inspected.sub===row.subject, subjectReturned: typeof inspected.sub === "string", analystRole: roles.some(r=>r.name==='soc-analyst'), tokenSecondsRemaining: Number(claims.exp)-Date.now()/1000, issuerMatches: claims.iss===issuer(), audience: claims.aud, clientMatches: claims.azp===c.KEYCLOAK_CONSOLE_ID, claimKeys: Object.keys(claims) }));
} catch (error) {
  // JOSE errors may embed decrypted claims: never print the error object.
  console.error(`Session validation could not complete (${error instanceof Error ? error.name : "unknown"}). Sign in again if the short-lived session expired.`);
  process.exitCode = 1;
} finally { await db().end(); }
