import 'dotenv/config';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {db} from '../src/lib/db';
import {startCase,loadCase,caseDetail} from '../src/lib/investigations/store';
import {executeCase,recoverExpiredRuns,type RuntimeServices} from '../src/lib/agents/runtime';
import {connectSharedMcp,type SharedMcp} from '../src/lib/mcp/client';
import {decideAction} from '../src/lib/investigations/actions';
import {identityRunSchema,type IdentityRun} from '../src/lib/agents/contracts';

type Respond=NonNullable<RuntimeServices['respond']>;
const call=(name:string,args:unknown):Awaited<ReturnType<Respond>>=>({output:[{type:'function_call',name,arguments:typeof args==='string'?args:JSON.stringify(args),call_id:randomUUID()}],usage:undefined});
const empty:Respond=async()=>({output:[],usage:undefined});
const report={assessment:'INSUFFICIENT_EVIDENCE',summary:'Controlled runtime test double; not a real model assessment.',findings:[],alternativeExplanations:[],limitations:['Scripted test responses, not an LLM.'],recommendation:{type:'ANALYST_REVIEW',reason:'Runtime verification only.',evidenceRefs:[]}};
async function claimed(name:string,limits:Partial<IdentityRun['limits']>={},model=true){
  const id=await startCase({mode:'replay',scenario:'normal',engine:'rehearsal'},'runtime-fault-test');
  const row=await loadCase(id);const run=identityRunSchema.parse({...row.run,limits:{...row.run.limits,...limits},modelConfiguration:{provider:'test-double',model:'scripted-no-api'}});
  const result=await db().query("UPDATE investigations SET title=$2,engine=$3,run=$4,status='RUNNING',started_at=now(),lease_until=now()+interval '7 minutes' WHERE id=$1 AND status='QUEUED' RETURNING id",[id,`TEST DOUBLE · ${name}`,model?'openai':'rehearsal',JSON.stringify(run)]);
  assert.equal(result.rowCount,1,'Stop the agent worker while running isolated integration checks.');return id;
}
async function main(){
  const mcp=await connectSharedMcp();let passed=0;
  const verify=async(name:string,id:string,status:string)=>{const detail=await caseDetail(id);assert.equal(detail.status,status,name);assert.equal(detail.actions.length,0,'Failed/test-only runs must not authorize containment');passed++;console.log(`${name}: passed (${status})`);return detail;};
  const run=async(name:string,respond:Respond,expected:string,limits:Partial<IdentityRun['limits']>={})=>{const id=await claimed(name,limits);await executeCase(id,mcp,{respond});return verify(name,id,expected);};
  try{
    await run('provider failure',async()=>{throw new Error('injected provider outage');},'FAILED');
    await run('model turn budget',empty,'LIMIT_REACHED',{maxModelTurns:2});
    await run('token budget',async()=>({output:[],usage:{total_tokens:101,input_tokens:100,output_tokens:1,input_tokens_details:{cached_tokens:0,cache_write_tokens:0},output_tokens_details:{reasoning_tokens:0}}}),'LIMIT_REACHED',{maxTokens:100});
    const invalid=await run('malformed arguments',async()=>call('relationship_get_graph','{broken'),'LIMIT_REACHED',{maxModelTurns:2});
    assert.equal(invalid.steps.filter(s=>s.kind==='VALIDATION_REJECTED').length,2);
    await run('out-of-role tool',async()=>call('identity_get_profile',{}),'LIMIT_REACHED',{maxModelTurns:2});
    await run('tool call budget',async()=>call('relationship_get_graph',{}),'LIMIT_REACHED',{maxToolCalls:1,maxModelTurns:3});
    const deadlineStart=Date.now();await run('in-flight model deadline',async()=>new Promise(()=>{}),'LIMIT_REACHED',{maxDurationMs:100,toolTimeoutMs:50});assert.ok(Date.now()-deadlineStart<5000);
    const id=await claimed('in-flight cancellation');let requested=false;
    const cancelStart=Date.now();await executeCase(id,mcp,{respond:async()=>{if(!requested){requested=true;await db().query('UPDATE investigations SET cancel_requested=true WHERE id=$1',[id]);}return new Promise(()=>{});}});
    await verify('in-flight cancellation',id,'CANCELLED');assert.ok(Date.now()-cancelStart<5000);
    const count:Record<string,number>={};
    const routing:Respond=async(agent)=>{const n=count[agent]=(count[agent]??0)+1;
      if(agent==='lead')return n<=3?call(`delegate_${['identity','saas','cloud'][n-1]}`,{}):n===4?call('relationship_get_graph',{}):call('finish_report',report);
      const names=agent==='identity'?['identity_get_profile','identity_search_events','identity_get_roles','identity_get_sessions']:agent==='saas'?['saas_get_activity']:['cloud_get_activity'];
      return n<=names.length?call(names[n-1],{}):call('finish_report',report);
    };
    const routed=await run('four-role Responses tool loop',routing,'COMPLETED');assert.equal(Object.keys(routed.agents).length,4);
    const fabricated:Respond=async(agent,request,signal)=>agent==='identity'?call('finish_report',{...report,findings:[{kind:'observation',claim:'Fabricated evidence must not pass.',evidenceRefs:[randomUUID()]}]}):routing(agent,request,signal);
    for(const key of Object.keys(count))delete count[key];
    const badReport=await run('fabricated report citation',fabricated,'LIMIT_REACHED',{maxModelTurns:2});assert.ok(badReport.steps.some(s=>s.kind==='VALIDATION_REJECTED'));
    const lost=await claimed('worker lease expiration',{},false);await db().query("UPDATE investigations SET lease_until=now()-interval '1 second' WHERE id=$1",[lost]);await recoverExpiredRuns();await verify('worker restart recovery',lost,'FAILED');
    assert.equal((await mcp.call(lost,'identity','identity_get_profile',{})).status,'error');
    const disconnected=await claimed('MCP disconnect',{},false);const closed=await connectSharedMcp();await closed.close();await executeCase(disconnected,closed);await verify('MCP disconnect',disconnected,'FAILED');
    const stalled=await claimed('MCP tool timeout',{maxDurationMs:1000,toolTimeoutMs:50},false);
    const hanging:SharedMcp={...mcp,call:async()=>new Promise(()=>{})};await executeCase(stalled,hanging);await verify('MCP tool timeout',stalled,'LIMIT_REACHED');
    const responseCase=await startCase({mode:'replay',scenario:'session-abuse',engine:'rehearsal'},'runtime-fault-test');await db().query("UPDATE investigations SET title='REPLAY TEST · concurrent approval',status='RUNNING',lease_until=now()+interval '7 minutes' WHERE id=$1",[responseCase]);await executeCase(responseCase,mcp);
    const action=(await caseDetail(responseCase)).actions[0];assert.ok(action);
    const decisions=await Promise.allSettled([decideAction(action.id,'test-analyst-A','approve'),decideAction(action.id,'test-analyst-B','approve')]);assert.equal(decisions.filter(r=>r.status==='fulfilled').length,1);assert.equal((await caseDetail(responseCase)).actions[0].status,'VERIFIED');passed++;
    await db().query("UPDATE response_actions SET status='EXECUTING',decided_at=now()-interval '3 minutes' WHERE id=$1",[action.id]);await recoverExpiredRuns();const interrupted=(await caseDetail(responseCase)).actions[0];assert.equal(interrupted.status,'FAILED');assert.match(interrupted.verification.error,/uncertain/);await assert.rejects(()=>decideAction(action.id,'test-analyst-A','approve'));passed++;
    console.log(JSON.stringify({passed,realModelCalls:0,liveIdentityMutations:0,scope:'Fault tests and scripted Responses loop; not an LLM quality evaluation.'}));
  }finally{await mcp.close();await db().end();}
}
main().catch(error=>{console.error('Runtime check failed:',error instanceof Error?error.message:'unknown');process.exitCode=1;});
