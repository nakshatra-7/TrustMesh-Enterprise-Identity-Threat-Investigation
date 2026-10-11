import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import * as oidc from "openid-client";
import { config } from "../../../../lib/config";
import { cookieOptions, LOGIN_COOKIE, SESSION_COOKIE, newConsoleSession, oidcConfig, unseal } from "../../../../lib/auth";
import { isAnalyst } from "../../../../lib/access";
import { identityReader } from "../../../../lib/keycloak";
export async function GET(request: NextRequest) {
  let response: NextResponse;
  let stage = "login-cookie";
  try {
    const cookie = (await cookies()).get(LOGIN_COOKIE)?.value;
    if (!cookie) throw new Error("Missing login transaction");
    stage = "login-transaction";
    const tx = await unseal(cookie, "login-transaction");
    if (typeof tx.verifier !== "string" || typeof tx.state !== "string" || typeof tx.nonce !== "string") throw new Error("Invalid login transaction");
    const callback = new URL("/api/auth/callback", config().APP_URL);
    callback.search = request.nextUrl.search;
    stage = "code-exchange";
    const tokens = await oidc.authorizationCodeGrant(await oidcConfig(), callback, {
      pkceCodeVerifier: tx.verifier, expectedState: tx.state, expectedNonce: tx.nonce, idTokenExpected: true
    });
    const claims = tokens.claims();
    if (!claims?.sub) throw new Error("Missing subject");
    stage = "analyst-role";
    const roles = await identityReader.roles(claims.sub);
    if (!isAnalyst(roles.map(r => r.name))) {
      response = NextResponse.redirect(new URL("/?error=analyst-required", config().APP_URL));
    } else {
      stage = "session-storage";
      const login = await newConsoleSession(claims.sub, typeof claims.preferred_username === "string" ? claims.preferred_username : "Analyst", tokens.access_token, tokens.expires_in ?? 300);
      response = NextResponse.redirect(new URL("/", config().APP_URL));
      response.cookies.set(SESSION_COOKIE, login.session, cookieOptions(login.lifetime));
    }
  } catch (error) {
    // Never log exception objects, messages, claims, callback URLs or authorization codes.
    const code = error && typeof error === "object" && "code" in error && typeof error.code === "string" && /^[A-Z_]{1,64}$/.test(error.code) ? error.code : "UNCLASSIFIED";
    console.warn(JSON.stringify({ component: "analyst-login", stage, code }));
    response = NextResponse.redirect(new URL("/?error=login-failed", config().APP_URL));
  }
  response.cookies.set(LOGIN_COOKIE, "", cookieOptions(0));
  return response;
}
