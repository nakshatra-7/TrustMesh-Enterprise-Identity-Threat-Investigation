import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { scenarios,makeScenario } from '../src/lib/investigations/scenarios';
import { detect,featuresFrom,evaluateModel } from '../src/lib/investigations/risk';
import { actionPolicy } from '../src/lib/investigations/actions';
import { rehearsalReport,validateAgentReport } from '../src/lib/agents/runtime';
import { identityRunSchema,identityToolNameSchema } from '../src/lib/agents/contracts';
import { replayIdentityHandlers,domainEvidence } from '../src/lib/mcp/demo-adapter';
import type { CaseRecord } from '../src/lib/investigations/store';

function fixture(scenario:Parameters<typeof makeScenario>[0]):CaseRecord {
  const now=new Date(),id=randomUUID(),snapshot=makeScenario(scenario,'demo-user','demo-alice','trustmesh',now.getTime());
  const run=identityRunSchema.parse({contractVersion:'identity.v1',agentId:'identity-investigator',runId:id,requestedBy:'test-analyst',createdAt:now.toISOString(),question:'Investigate evidence',scope:{realm:'trustmesh',identityId:'demo-user',timeRange:{from:new Date(now.getTime()-3600000).toISOString(),to:now.toISOString()}},initialEventIds:[],allowedTools:identityToolNameSchema.options,limits:{maxTokens:24000},promptVersion:'test',modelConfiguration:{provider:'rehearsal',model:'test'}});
  return {id,requested_by:'test-analyst',identity_id:'demo-user',title:'Test',mode:'replay',engine:'rehearsal',status:'RUNNING',run,snapshot,detection:detect(featuresFrom(snapshot)),report:null,agents:{},error:null,cancel_requested:false,created_at:now,started_at:now,finished_at:null};
}
for(const scenario of scenarios)test(`replay scenario: ${scenario.id} has evidence-backed identity conclusions`,async()=>{
  const row=fixture(scenario.id),handlers=replayIdentityHandlers(row),observations=[];
  for(const name of ['identity_get_profile','identity_search_events','identity_get_roles','identity_get_sessions'])observations.push(await handlers.execute({name,arguments:{}}));
  assert.ok(observations.every(o=>o.status==='ok'));
  const report=rehearsalReport('identity',observations);validateAgentReport(row,'identity',report,observations,{});
  assert.equal(report.assessment,['normal','legitimate-travel'].includes(scenario.id)?'NO_SUSPICIOUS_EVIDENCE_OBSERVED':'SUSPICIOUS_ACTIVITY');
  assert.equal(report.recommendation.type,['normal','legitimate-travel'].includes(scenario.id)?'NO_ACTION_RECOMMENDED':'PROPOSE_SESSION_REVOCATION');
  assert.ok(!JSON.stringify(row.snapshot).includes(scenario.id),'Expected scenario label must not leak into evidence');
});
test('policy denies unapproved, expired, unobserved and non-demo live actions',()=>{
  const valid={mode:'live',approved:true,expired:false,observed:true,demoIdentity:true};assert.equal(actionPolicy(valid).allow,true);
  for(const patch of [{approved:false},{expired:true},{observed:false},{demoIdentity:false}])assert.equal(actionPolicy({...valid,...patch}).allow,false);
});
test('synthetic baseline is reproducible and legitimate MFA anomaly has low rules risk',()=>{
  assert.deepEqual(evaluateModel(),evaluateModel());assert.equal(detect(featuresFrom(fixture('legitimate-travel').snapshot!)).ruleRisk,0);
  assert.ok(detect(featuresFrom(fixture('cross-domain').snapshot!)).ruleRisk>=80);
});
test('unconnected domains never return replay evidence for live cases',()=>{
  const row=fixture('cross-domain');row.mode='live';row.snapshot=null;const result=domainEvidence(row,'cloud_get_activity');assert.equal(result.source,'unconnected');assert.deepEqual('events' in result.data?result.data.events:undefined,[]);assert.match(result.coverageWarnings.join(' '),/not configured/);
});
test('domain agents cannot invent evidence references or session proposals',()=>{
  const row=fixture('normal'),observations=[domainEvidence(row,'saas_get_activity')],report=rehearsalReport('saas',observations);
  assert.doesNotThrow(()=>validateAgentReport(row,'saas',report,observations,{}));
  report.findings[0].evidenceRefs=['invented'];assert.throws(()=>validateAgentReport(row,'saas',report,observations,{}));
});
test('replay event lookup is identity/time scoped and does not mutate live storage',async()=>{
  const row=fixture('session-abuse'),handlers=replayIdentityHandlers(row);const result=await handlers.execute({name:'identity_get_event',arguments:{eventId:'not-in-snapshot'}});assert.equal(result.status,'error');if(result.status==='error')assert.equal(result.code,'NOT_FOUND');
});
