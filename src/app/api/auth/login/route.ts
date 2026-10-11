import { NextResponse } from "next/server";
import * as oidc from "openid-client";
import { config } from "../../../../lib/config";
import { cookieOptions, LOGIN_COOKIE, oidcConfig, seal } from "../../../../lib/auth";
export async function GET(request: Request) {
  // Bind the login transaction cookie to the configured callback hostname.
  if (new URL(request.url).origin !== new URL(config().APP_URL).origin) {
    return NextResponse.redirect(new URL("/api/auth/login", config().APP_URL));
  }
  try {
    const verifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState(); const nonce = oidc.randomNonce();
    const url = oidc.buildAuthorizationUrl(await oidcConfig(), {
      redirect_uri: `${config().APP_URL}/api/auth/callback`, scope: "openid profile", prompt: "login",
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: "S256", state, nonce
    });
    const response = NextResponse.redirect(url);
    response.cookies.set(LOGIN_COOKIE, await seal({ verifier, state, nonce }, 300, "login-transaction"), cookieOptions(300));
    return response;
  } catch {
    return NextResponse.redirect(new URL("/?error=identity-unavailable", config().APP_URL));
  }
}
