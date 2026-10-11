import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { config } from "../../../../lib/config";
import { db } from "../../../../lib/db";
import { SESSION_COOKIE, cookieOptions, hashSession } from "../../../../lib/auth";
export async function POST(request: NextRequest) {
  if (request.headers.get("origin") !== new URL(config().APP_URL).origin) return new NextResponse("Forbidden", { status: 403 });
  const value = (await cookies()).get(SESSION_COOKIE)?.value;
  if (value) await db().query("DELETE FROM console_sessions WHERE token_hash=$1", [hashSession(value)]);
  const response = NextResponse.json({ signedOut: true }, { headers: { "Cache-Control": "no-store" } });
  response.cookies.set(SESSION_COOKIE, "", cookieOptions(0));
  return response;
}
