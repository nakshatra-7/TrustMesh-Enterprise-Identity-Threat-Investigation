import 'dotenv/config';
import { decodeJwt } from 'jose';
import { db } from '../src/lib/db';
import { localAdmin,requireLocalDemo,demoClientId,demoClientSecret,encryptProbe } from '../src/lib/investigations/local-admin';
let stage='bootstrap authentication';
async function main(){
  const c=requireLocalDemo(),admin=await localAdmin();
  stage='demo marker schema';const profile=await admin('users/profile');
  if(!profile.attributes.some((a:{name:string})=>a.name==='trustmeshDemo'))await admin('users/profile','PUT',{...profile,attributes:[...profile.attributes,{name:'trustmeshDemo',displayName:'TrustMesh demo identity',multivalued:false,permissions:{view:['admin'],edit:['admin']}}]});
  stage='demo client lookup';const clients=await admin(`clients?clientId=${demoClientId}`);
  if(!clients.length)await admin('clients','POST',{clientId:demoClientId,enabled:true,publicClient:false,secret:demoClientSecret(),standardFlowEnabled:false,directAccessGrantsEnabled:true,serviceAccountsEnabled:false,
    protocol:'openid-connect',attributes:{'access.token.lifespan':'3600'},protocolMappers:[{name:'demo-audience',protocol:'openid-connect',protocolMapper:'oidc-audience-mapper',config:{'included.client.audience':demoClientId,'access.token.claim':'true','id.token.claim':'false'}}]});
  for(const username of ['demo-alice','demo-bob','demo-charlie','demo-dana']){
    stage=`${username}: user provisioning`;
    let users=await admin(`users?username=${username}&exact=true`);
    if(!users.length){await admin('users','POST',{username,enabled:true,email:`${username}@example.invalid`,emailVerified:true,firstName:username.slice(5),lastName:'Demo',attributes:{trustmeshDemo:['true']},credentials:[{type:'password',value:process.env.EMPLOYEE_PASSWORD,temporary:false}]});users=await admin(`users?username=${username}&exact=true`);}
    const user=users[0];if(user.attributes?.trustmeshDemo?.[0]!=='true')throw new Error('Existing username is not a TrustMesh demo identity; preserved without changes.');
    if(!user.firstName||!user.lastName||!user.email)await admin(`users/${encodeURIComponent(user.id)}`,'PUT',{...user,firstName:user.firstName??username.slice(5),lastName:user.lastName??'Demo',email:user.email??`${username}@example.invalid`,emailVerified:true});
    stage=`${username}: registry`;await db().query('INSERT INTO demo_identities(identity_id,username) VALUES($1,$2) ON CONFLICT(identity_id) DO NOTHING',[user.id,username]);
    const existing=await db().query('SELECT session_id FROM demo_session_probes WHERE identity_id=$1 AND expires_at>now()',[user.id]);
    const sessions=await admin(`users/${encodeURIComponent(user.id)}/sessions`);
    if(existing.rows.some(p=>sessions.some((s:any)=>s.id===p.session_id)))continue;
    stage=`${username}: demo session`;const login=await fetch(`${c.KEYCLOAK_URL}/realms/trustmesh/protocol/openid-connect/token`,{method:'POST',body:new URLSearchParams({grant_type:'password',client_id:demoClientId,client_secret:demoClientSecret(),username,password:process.env.EMPLOYEE_PASSWORD??''}),signal:AbortSignal.timeout(10000)});
    if(!login.ok){const failure=await login.json();console.error(JSON.stringify({stage,status:login.status,error:typeof failure.error==='string'?failure.error:'unknown',accountSetupRequired:failure.error_description==='Account is not fully set up',invalidCredentials:failure.error_description==='Invalid user credentials'}));throw new Error('Demo identity login failed');}const token=await login.json();stage=`${username}: protected-resource probe`;const claims=decodeJwt(token.access_token);const sid=String(claims.sid??claims.session_state??'');if(!sid)throw new Error('Provider did not return a session reference');
    await db().query('INSERT INTO demo_session_probes(session_id,identity_id,encrypted_token,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(session_id) DO NOTHING',[sid,user.id,await encryptProbe(token.access_token,token.expires_in),new Date(Date.now()+token.expires_in*1000)]);
  }
  console.log('Four dedicated demo identities and protected-resource sessions are ready. Existing employee/analyst accounts preserved. No credentials printed.');
}
main().catch(error=>{console.error(`Demo seed failed at ${stage} (${error instanceof Error?error.name:'unknown'}). ${error instanceof Error&&/^Local provider operation failed \(\d+\)$/.test(error.message)?error.message:''} No credentials or provider payloads were logged.`);process.exitCode=1;}).finally(()=>db().end());
