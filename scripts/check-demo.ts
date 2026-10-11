import 'dotenv/config';
import assert from 'node:assert/strict';
import { db } from '../src/lib/db';
import { startCase,loadCase,caseDetail } from '../src/lib/investigations/store';
import { executeCase } from '../src/lib/agents/runtime';
import { connectSharedMcp } from '../src/lib/mcp/client';
import { decideAction } from '../src/lib/investigations/actions';
import { scenarios } from '../src/lib/investigations/scenarios';
import { evaluateModel } from '../src/lib/investigations/risk';
async function main(){
  const mcp=await connectSharedMcp();
  try{
    assert.equal((await mcp.list()).tools.length,8);
    for(const scenario of scenarios){
      const id=await startCase({mode:'replay',scenario:scenario.id,engine:'rehearsal'},'automated-demo-check');
      const claimed=await db().query("UPDATE investigations SET status='RUNNING',started_at=now(),lease_until=now()+interval '7 minutes' WHERE id=$1 AND status='QUEUED' RETURNING id",[id]);
      assert.equal(claimed.rowCount,1,'Run this check before starting the investigation worker.');
      const denied=await mcp.call(id,'saas','identity_get_profile',{});assert.equal(denied.status,'error');
      await executeCase(id,mcp);const row=await loadCase(id);assert.equal(row.status,'COMPLETED',`${scenario.id}: ${row.error}`);
      assert.equal(Object.keys(row.agents).length,4);assert.equal(row.report.engine,'rehearsal');assert.equal(row.report.containmentExecuted,false);
      assert.equal(row.report.assessment,['normal','legitimate-travel'].includes(scenario.id)?'NO_SUSPICIOUS_EVIDENCE_OBSERVED':'SUSPICIOUS_ACTIVITY');
      const detail=await caseDetail(id);assert.ok(detail.steps.some(s=>s.kind==='TOOL'));
      if(detail.actions.length){const action=detail.actions[0];assert.equal(action.status,'PENDING');
        const decision=scenario.id==='privilege-escalation'?'reject':'approve';
        await decideAction(action.id,'automated-demo-check',decision);
        const decided=(await caseDetail(id)).actions[0];assert.equal(decided.status,decision==='approve'?'VERIFIED':'REJECTED');
        await assert.rejects(()=>decideAction(action.id,'automated-demo-check','approve'));
      }
      assert.equal((await mcp.call(id,'identity','identity_get_profile',{})).status,'error','Completed runs cannot use capabilities');
      console.log(JSON.stringify({scenario:scenario.id,status:'passed',fourAgents:true,sharedMcp:true,approvalGate:true}));
    }
    console.log(JSON.stringify({syntheticModel:evaluateModel(),note:'Only isolated replay resources were changed. Test cases remain visible for inspection.'}));
  }finally{await mcp.close();await db().end();}
}
main().catch(e=>{console.error('Demo check failed:',e instanceof Error?e.message:'unknown failure');process.exitCode=1;});
