import { createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { EncryptJWT, jwtDecrypt, type JWTPayload } from "jose";
import * as oidc from "openid-client";
import { config, issuer } from "./config";
import { db } from "./db";
import { identityReader } from "./keycloak";
import { allowsLocalHttp, isAnalyst } from "./access";

export const SESSION_COOKIE = "tm_console";
export const LOGIN_COOKIE = "tm_login";
export const hashSession = (value: string) => createHash("sha256").update(value).digest("hex");
export function cookieOptions(maxAge: number) {
  return { httpOnly: true, sameSite: "lax" as const, secure: new URL(config().APP_URL).protocol === "https:", path: "/", maxAge };
}
export async function seal(payload: JWTPayload, lifetime: number, audience: string) {
  return new EncryptJWT(payload).setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt().setAudience(audience).setExpirationTime(`${lifetime}s`)
    .encrypt(Buffer.from(config().COOKIE_SECRET, "hex"));
}
export async function unseal(value: string, audience: string) {
  return (await jwtDecrypt(value, Buffer.from(config().COOKIE_SECRET, "hex"), { audience })).payload;
}
let discovery: Promise<oidc.Configuration> | undefined;
export async function oidcConfig() {
  if (!discovery) {
    const c = config(); const url = new URL(issuer());
    if (url.protocol !== "https:" && !allowsLocalHttp(url)) throw new Error("OIDC requires HTTPS outside loopback development.");
    discovery = oidc.discovery(url, c.KEYCLOAK_CONSOLE_ID, c.KEYCLOAK_CONSOLE_SECRET, undefined,
      { timeout: 10, execute: allowsLocalHttp(url) ? [oidc.allowInsecureRequests] : undefined });
    discovery.catch(() => { discovery = undefined; });
  }
  return discovery;
}
export async function newConsoleSession(subject: string, username: string, accessToken: string, expiresIn: number) {
  const lifetime = Math.max(1, Math.min(expiresIn, 300));
  const session = randomBytes(32).toString("hex");
  await db().query("DELETE FROM console_sessions WHERE expires_at <= now()");
  await db().query(`INSERT INTO console_sessions (token_hash,subject,username,encrypted_access_token,expires_at)
    VALUES ($1,$2,$3,$4,$5)`, [hashSession(session), subject, username,
    await seal({ token: accessToken }, lifetime, "console-access-token"), new Date(Date.now() + lifetime * 1000)]);
  return { session, lifetime };
}
export async function currentAnalyst(): Promise<{ id: string; username: string } | null> {
  const session = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!session || !/^[0-9a-f]{64}$/.test(session)) return null;
  const result = await db().query("SELECT subject,username,encrypted_access_token FROM console_sessions WHERE token_hash=$1 AND expires_at>now()", [hashSession(session)]);
  const record = result.rows[0];
  if (!record) return null;
  let token: JWTPayload;
  try { token = await unseal(record.encrypted_access_token, "console-access-token"); }
  catch { return null; }
  if (typeof token.token !== "string") return null;
  // Verify provider activity on each request. Signature-only JWT validation would miss revocation.
  const introspection = await oidc.tokenIntrospection(await oidcConfig(), token.token);
  if (!introspection.active || introspection.sub !== record.subject) return null;
  const roles = await identityReader.roles(record.subject);
  if (!isAnalyst(roles.map(r => r.name))) return null;
  return { id: record.subject, username: record.username };
}
