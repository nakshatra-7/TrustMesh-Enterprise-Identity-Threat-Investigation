import { z } from 'zod';
import { db } from '../db';
import { loadCase,audit } from './store';
import { identityReader } from '../keycloak';
import { localAdmin,probeToken,inspectProbe,protectedProbe } from './local-admin';
export function actionPolicy(input:{mode:string;approved:boolean;expired:boolean;observed:boolean;demoIdentity:boolean}) {
  if(!input.approved)return {allow:false,reason:'Analyst approval is required.'};
  if(input.expired)return {allow:false,reason:'Approval proposal expired; investigate again.'};
  if(!input.observed)return {allow:false,reason:'Target session was not observed in the identity evidence.'};
  if(input.mode==='live'&&!input.demoIdentity)return {allow:false,reason:'This demo executor only changes explicitly seeded demo identities.'};
  return {allow:true,reason:'Single observed session, explicit analyst approval, bounded target.'};
}
export async function decideAction(id:string,analystId:string,decision:'approve'|'reject') {
  z.uuid().parse(id);const client=await db().connect();let action:any;let row:Awaited<ReturnType<typeof loadCase>>;
  try{await client.query('BEGIN');action=(await client.query('SELECT * FROM response_actions WHERE id=$1 FOR UPDATE',[id])).rows[0];if(!action||action.status!=='PENDING')throw new Error('Action is missing or has already been decided.');
    row=await loadCase(action.investigation_id);if(row.status!=='COMPLETED')throw new Error('Investigation is not completed.');
    if(decision==='reject'){await client.query("UPDATE response_actions SET status='REJECTED',approved_by=$2,decided_at=now() WHERE id=$1",[id,analystId]);await client.query('COMMIT');await audit(row.id,analystId,'ACTION_REJECTED',{actionId:id});return;}
    const identity=row.agents.identity as {observations?:any[]}|undefined;
    const observed=identity?.observations?.some(o=>o.tool==='identity_get_sessions'&&o.status==='ok'&&o.data.sessions.some((s:any)=>s.id===action.target_session))??false;
    const demo=await client.query('SELECT identity_id FROM demo_identities WHERE identity_id=$1',[row.identity_id]);
    const policy=actionPolicy({mode:action.mode,approved:true,expired:new Date(action.expires_at).getTime()<=Date.now(),observed,demoIdentity:!!demo.rowCount});
    if(!policy.allow)throw new Error(policy.reason);
    await client.query("UPDATE response_actions SET status='EXECUTING',approved_by=$2,decided_at=now() WHERE id=$1",[id,analystId]);
    await client.query('INSERT INTO investigation_audit(investigation_id,actor,action,details) VALUES($1,$2,$3,$4)',[row.id,analystId,'ACTION_APPROVED',JSON.stringify({actionId:id,sessionId:action.target_session,mode:action.mode,policy:policy.reason})]);await client.query('COMMIT');
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
  try{
    let verification:Record<string,unknown>;
    if(action.mode==='replay'){
      if(!row!.snapshot!.sessions.some(s=>s.id===action.target_session))throw new Error('Replay session is no longer active.');
      const before=row!.snapshot!.sessions.length;const remaining=row!.snapshot!.sessions.filter(s=>s.id!==action.target_session);
      await db().query("UPDATE investigations SET snapshot=jsonb_set(snapshot,'{sessions}',$2::jsonb) WHERE id=$1",[row!.id,JSON.stringify(remaining)]);
      verification={mode:'simulated',sessionAbsent:remaining.every(s=>s.id!==action.target_session),protectedRequestBefore:200,protectedRequestAfter:remaining.some(s=>s.id===action.target_session)?200:401,unrelatedSessionsPreserved:remaining.length===before-1,limitation:'Local replay session store only. No Keycloak, repository or cloud state was changed.'};
    }else{
      const sessions=await identityReader.sessions(row!.identity_id);if(!sessions.some(s=>s.id===action.target_session))throw new Error('Target session is no longer active.');
      const probe=(await db().query('SELECT * FROM demo_session_probes WHERE session_id=$1 AND identity_id=$2 AND expires_at>now()',[action.target_session,row!.identity_id])).rows[0];
      if(!probe)throw new Error('A valid protected-resource probe is required before live execution. Reseed and reinvestigate.');
      const token=await probeToken(probe.encrypted_token);const before=await inspectProbe(token);if(!before.active||before.subject!==row!.identity_id)throw new Error('Pre-action access verification failed.');
      const httpBefore=await protectedProbe(token);if(httpBefore!==200)throw new Error('Pre-action protected request was not allowed.');
      const admin=await localAdmin();const user=await admin(`users/${encodeURIComponent(row!.identity_id)}`);
      if(user.attributes?.trustmeshDemo?.[0]!=='true'||!user.username.startsWith('demo-'))throw new Error('Target is not a dedicated demo identity.');
      await admin(`sessions/${encodeURIComponent(action.target_session)}`,'DELETE');
      const remaining=await identityReader.sessions(row!.identity_id);const after=await inspectProbe(token);const httpAfter=await protectedProbe(token);
      verification={mode:'live-keycloak',sessionAbsent:!remaining.some(s=>s.id===action.target_session),tokenInactive:!after.active,protectedRequestBefore:httpBefore,protectedRequestAfter:httpAfter,
        unrelatedSessionsPreserved:sessions.filter(s=>s.id!==action.target_session).every(s=>remaining.some(r=>r.id===s.id)),
        limitation:'Measured HTTP access to /api/demo/protected, which uses online token introspection. Offline JWT validation can accept outstanding tokens until expiry.'};
    }
    const verified=verification.sessionAbsent===true&&verification.protectedRequestAfter===401&&verification.unrelatedSessionsPreserved===true&&(action.mode==='replay'||verification.tokenInactive===true);
    await db().query('UPDATE response_actions SET status=$2,verification=$3 WHERE id=$1',[id,verified?'VERIFIED':'FAILED',JSON.stringify(verification)]);
    await audit(row!.id,'executor',verified?'ACTION_VERIFIED':'ACTION_VERIFICATION_FAILED',verification);
  }catch{
    await db().query("UPDATE response_actions SET status='FAILED',verification=$2 WHERE id=$1",[id,JSON.stringify({error:'Execution or verification failed. Inspect current provider state before any retry; automatic retry is disabled.'})]);
    await audit(row!.id,'executor','ACTION_FAILED',{actionId:id});
  }
}
