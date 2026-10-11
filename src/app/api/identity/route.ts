import { currentAnalyst } from "../../../lib/auth";
import { identityReader } from "../../../lib/keycloak";
export async function GET() {
  try {
    if (!await currentAnalyst()) return Response.json({ error: "Analyst authentication required" }, { status: 401 });
    return Response.json({ users: await identityReader.users() }, { headers: { "Cache-Control": "no-store" } });
  } catch { return Response.json({ error: "Identity provider unavailable" }, { status: 503 }); }
}
