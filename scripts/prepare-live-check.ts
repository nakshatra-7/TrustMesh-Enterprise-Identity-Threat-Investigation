import 'dotenv/config';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {decodeJwt} from 'jose';
import {db} from '../src/lib/db';
import {collectIdentityEvents} from '../src/lib/collector';
import {startCase,caseDetail} from '../src/lib/investigations/store';
import {executeCase} from '../src/lib/agents/runtime';
import {localAdmin,requireLocalDemo,demoClientId,demoClientSecret,encryptProbe,probeToken,protectedProbe} from '../src/lib/investigations/local-admin';

// An explicit local drill. Never grants privileges, weakens realm protection, or approves an action.
async function main(){
  const c=requireLocalDemo();const admin=await localAdmin();
  const verifyId=process.argv[2];
  if(verifyId){
    const detail=await caseDetail(verifyId);assert.equal(detail.requested_by,'local-live-containment-drill');
    const action=detail.actions[0];assert.equal(action?.status,'VERIFIED','Approve the pending action in the analyst dashboard first.');assert.equal(action.verification.mode,'live-keycloak');assert.equal(action.verification.tokenInactive,true);
    const probes=await db().query('SELECT * FROM demo_session_probes WHERE identity_id=$1 AND expires_at>now()',[detail.identity_id]);
    let preserved=0;for(const p of probes.rows){const status=await protectedProbe(await probeToken(p.encrypted_token));if(p.session_id===action.target_session)assert.equal(status,401);else{assert.equal(status,200,'An unrelated session lost access');preserved++;}}
    assert.ok(preserved>=1);console.log(JSON.stringify({status:'passed',targetAccessBefore:action.verification.protectedRequestBefore,targetAccessAfter:action.verification.protectedRequestAfter,unrelatedSessionsWithHttp200:preserved,analystApproved:!!action.approved_by}));return;
  }
  const realm=await admin('');if(realm.bruteForceProtected)throw new Error('Realm brute-force protection is enabled. This drill will not weaken it; use a separately reviewed fixture.');
  const identity=(await db().query("SELECT * FROM demo_identities WHERE username='demo-charlie'")).rows[0];assert.ok(identity,'Seed the demo first.');
  const user=await admin(`users/${encodeURIComponent(identity.identity_id)}`);assert.equal(user.attributes?.trustmeshDemo?.[0],'true');assert.equal(user.username,'demo-charlie');
  const tokenRequest=(password:string)=>fetch(`${c.KEYCLOAK_URL}/realms/trustmesh/protocol/openid-connect/token`,{method:'POST',body:new URLSearchParams({grant_type:'password',client_id:demoClientId,client_secret:demoClientSecret(),username:user.username,password}),signal:AbortSignal.timeout(10000)});
  for(let i=0;i<2;i++){
    const response=await tokenRequest(process.env.EMPLOYEE_PASSWORD??'');assert.equal(response.status,200,'Dedicated demo login failed');
    const token=await response.json();const claims=decodeJwt(token.access_token);assert.equal(claims.sub,user.id);const sid=String(claims.sid??claims.session_state??'');assert.ok(sid);
    assert.equal(await protectedProbe(token.access_token),200,'Protected endpoint must allow a valid demo session');
    await db().query('INSERT INTO demo_session_probes(session_id,identity_id,encrypted_token,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(session_id) DO NOTHING',[sid,user.id,await encryptProbe(token.access_token,token.expires_in),new Date(Date.now()+token.expires_in*1000)]);
  }
  // Six bounded invalid-password requests against this one owned lab identity only.
  for(let i=0;i<6;i++){const response=await tokenRequest(`invalid-drill-${randomUUID()}`);assert.ok([400,401].includes(response.status),'Expected a rejected lab login');const body=await response.json();assert.equal(body.error,'invalid_grant','Expected an invalid-password grant rejection');}
  await collectIdentityEvents();
  const now=Date.now();const id=await startCase({mode:'live',engine:'rehearsal',request:{identityId:user.id,question:'Controlled local containment drill: investigate the deliberately generated failed logins. Propose only one observed session for analyst review; do not execute actions.',timeRange:{from:new Date(now-600000).toISOString(),to:new Date(now).toISOString()}}},'local-live-containment-drill');
  const claimed=await db().query("UPDATE investigations SET title='LIVE KEYCLOAK · controlled containment drill',status='RUNNING',lease_until=now()+interval '7 minutes',started_at=now() WHERE id=$1 AND status='QUEUED' RETURNING id",[id]);assert.equal(claimed.rowCount,1,'Stop the agent worker before preparing this isolated drill.');
  await executeCase(id);const detail=await caseDetail(id);assert.equal(detail.status,'COMPLETED');assert.equal(detail.actions[0]?.status,'PENDING','Observed evidence must support a pending proposal; no action was auto-approved.');
  const probe=(await db().query('SELECT * FROM demo_session_probes WHERE session_id=$1 AND expires_at>now()',[detail.actions[0].target_session])).rows[0];assert.ok(probe,'The observed target must have a valid probe');assert.equal(await protectedProbe(await probeToken(probe.encrypted_token)),200);
  console.log(JSON.stringify({caseId:id,status:'AWAITING_ANALYST_APPROVAL',identity:'demo-charlie',realFailedLogins:6,newSessions:2,engine:'deterministic rehearsal, no LLM',next:'Open the LIVE KEYCLOAK controlled containment drill in /investigations, inspect evidence, approve exactly one session, then rerun this command with the case ID.'}));
}
main().catch(error=>{console.error('Live drill stopped:',error instanceof Error?error.message:'unknown');process.exitCode=1;}).finally(()=>db().end());
