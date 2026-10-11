// Local bootstrap maintenance only. Never imported by the web app, worker or agents.
import "dotenv/config";
import { config } from "../src/lib/config";
import { allowsLocalHttp } from "../src/lib/access";
const c = config();
if (!allowsLocalHttp(new URL(c.KEYCLOAK_URL)) || c.KEYCLOAK_REALM !== "trustmesh") throw new Error("This maintenance script only targets the local trustmesh realm.");
async function main() {
  const auth = await fetch(`${c.KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`, {
    method:"POST", body:new URLSearchParams({ grant_type:"password", client_id:"admin-cli", username:"bootstrap-admin", password:process.env.KEYCLOAK_ADMIN_PASSWORD ?? "" }), signal:AbortSignal.timeout(10000)
  });
  if (!auth.ok) throw new Error("Bootstrap authentication failed");
  const { access_token } = await auth.json();
  const headers = { Authorization:`Bearer ${access_token}`, "Content-Type":"application/json" };
  const base = `${c.KEYCLOAK_URL}/admin/realms/${c.KEYCLOAK_REALM}/clients`;
  const list = await fetch(`${base}?clientId=${encodeURIComponent(c.KEYCLOAK_CONSOLE_ID)}`,{headers});
  if (!list.ok) throw new Error("Client lookup failed");
  const clients = await list.json();
  if (clients.length !== 1) throw new Error("Expected exactly one console client");
  const endpoint = `${base}/${clients[0].id}/protocol-mappers/models`;
  const response = await fetch(endpoint,{headers});
  if (!response.ok) throw new Error("Mapper lookup failed");
  const mappers = await response.json();
  if (mappers.some((m:{name:string})=>m.name==='console-audience')) { console.log("Console audience mapper already exists."); return; }
  const created = await fetch(endpoint,{method:"POST",headers,body:JSON.stringify({name:"console-audience",protocol:"openid-connect",protocolMapper:"oidc-audience-mapper",config:{"included.client.audience":c.KEYCLOAK_CONSOLE_ID,"access.token.claim":"true","id.token.claim":"false"}})});
  if (!created.ok) throw new Error("Mapper creation failed");
  console.log("Added console audience mapper. Sign in again to issue a token for this audience.");
}
main().catch(()=>{console.error("Local audience configuration failed; credentials and provider responses are not logged.");process.exitCode=1;});
