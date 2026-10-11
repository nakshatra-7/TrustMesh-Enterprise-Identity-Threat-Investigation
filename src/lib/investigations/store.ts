import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { db } from '../db';
import { config } from '../config';
import { identityReader } from '../keycloak';
import { identityRunSchema, identityToolNameSchema, investigationRequestSchema, type IdentityRun } from '../agents/contracts';
import { makeScenario, scenarioId, scenarios, type DemoSnapshot } from './scenarios';
import { detect, featuresFrom } from './risk';
export const startSchema=z.discriminatedUnion('mode',[
  z.strictObject({mode:z.literal('replay'),scenario:scenarioId,engine:z.enum(['rehearsal','openai']).default('rehearsal')}),
  z.strictObject({mode:z.literal('live'),request:investigationRequestSchema,engine:z.enum(['rehearsal','openai']).default('rehearsal')})
]);
export type CaseRecord={id:string;requested_by:string;identity_id:string;title:string;mode:'replay'|'live';engine:'rehearsal'|'openai';status:string;run:IdentityRun;snapshot:DemoSnapshot|null;detection:ReturnType<typeof detect>;report:any;agents:Record<string,unknown>;error:string|null;cancel_requested:boolean;created_at:Date;started_at:Date|null;finished_at:Date|null};
export async function step(id:string,agent:string,kind:string,summary:string,payload:unknown={}) {await db().query('INSERT INTO investigation_steps(investigation_id,agent,kind,summary,payload) VALUES($1,$2,$3,$4,$5)',[id,agent,kind,summary,JSON.stringify(payload)]);}
export async function audit(id:string,actor:string,action:string,details:unknown={}) {await db().query('INSERT INTO investigation_audit(investigation_id,actor,action,details) VALUES($1,$2,$3,$4)',[id,actor,action,JSON.stringify(details)]);}
export async function loadCase(id:string):Promise<CaseRecord> {const r=await db().query('SELECT * FROM investigations WHERE id=$1',[z.uuid().parse(id)]);if(!r.rows[0])throw new Error('Investigation not found');return r.rows[0];}
export async function startCase(input:unknown,analystId:string) {
  const request=startSchema.parse(input);
  if(request.engine==='openai'&&(!process.env.OPENAI_API_KEY||!process.env.OPENAI_MODEL))throw new Error('Configure OPENAI_API_KEY and OPENAI_MODEL before selecting live AI.');
  const c=config(),id=randomUUID(),now=new Date();let snapshot:DemoSnapshot|null=null,identityId:string,title:string,question:string,range:{from:string;to:string},initial:string[]=[];
  if(request.mode==='replay') {
    const scenario=scenarios.find(s=>s.id===request.scenario)!;
    const user=(await db().query('SELECT * FROM demo_identities WHERE username=$1',[scenario.user])).rows[0];
    if(!user)throw new Error('Demo identities are not seeded. Run npm run demo:seed.');
    identityId=user.identity_id;title=scenario.title;question='Investigate authentication, session and permission anomalies. Correlate repository and cloud activity where evidence is available. Consider legitimate explanations.';
    snapshot=makeScenario(request.scenario,identityId,user.username,c.KEYCLOAK_REALM,now.getTime());
    range={from:new Date(now.getTime()-3600000).toISOString(),to:now.toISOString()};
  } else {
    identityId=request.request.identityId;const profile=await identityReader.user(identityId);title=`Identity review · ${profile.username}`;
    question=request.request.question;range=request.request.timeRange;initial=request.request.initialEventIds;
  }
  const run=identityRunSchema.parse({contractVersion:'identity.v1',agentId:'identity-investigator',runId:id,requestedBy:analystId,createdAt:now.toISOString(),question,
    scope:{realm:c.KEYCLOAK_REALM,identityId,timeRange:range},initialEventIds:initial,allowedTools:identityToolNameSchema.options,
    limits:{maxTokens:24000},promptVersion:'identity-demo-v1',modelConfiguration:{provider:request.engine,model:request.engine==='openai'?process.env.OPENAI_MODEL!:'deterministic-rehearsal'}});
  const detection=detect(snapshot?featuresFrom(snapshot):{failures:0,networks:0,roleChanges:0,bulkReads:0,privilegedCloud:0,mfa:false});
  const client=await db().connect();
  try {await client.query('BEGIN');await client.query('SELECT pg_advisory_xact_lock(7829342)');
    const active=await client.query("SELECT count(*)::int AS n FROM investigations WHERE status IN ('QUEUED','RUNNING')");
    if(active.rows[0].n>=10)throw new Error('Investigation queue is full. Wait for an active run to finish.');
    await client.query('INSERT INTO investigations(id,requested_by,identity_id,title,mode,engine,run,snapshot,detection) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[id,analystId,identityId,title,request.mode,request.engine,JSON.stringify(run),snapshot?JSON.stringify(snapshot):null,JSON.stringify(detection)]);
    await client.query('INSERT INTO investigation_audit(investigation_id,actor,action) VALUES($1,$2,$3)',[id,analystId,'INVESTIGATION_REQUESTED']);await client.query('COMMIT');
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
  return id;
}
export async function caseDetail(id:string) {
  const row=await loadCase(id);
  const [steps,actions,audits]=await Promise.all([db().query('SELECT * FROM investigation_steps WHERE investigation_id=$1 ORDER BY id',[id]),db().query('SELECT * FROM response_actions WHERE investigation_id=$1',[id]),db().query('SELECT * FROM investigation_audit WHERE investigation_id=$1 ORDER BY id',[id])]);
  const {snapshot:_snapshot,...safe}=row;
  return {...safe,steps:steps.rows,actions:actions.rows,audit:audits.rows};
}
