import { randomBytes, randomUUID } from 'node:crypto';
import { createIdentityHandlers } from './identity-handlers';
import { createIdentityCursorCodec } from './identity-cursor';
import type { CaseRecord } from '../investigations/store';
import type { EventRow } from './identity-store';
const cursorKey=randomBytes(32);
export function replayIdentityHandlers(row:CaseRecord) {
  const snapshot=row.snapshot!;
  return createIdentityHandlers(row.run,{realm:row.run.scope.realm,cursors:createIdentityCursorCodec(cursorKey),reader:{
    user:async()=>snapshot.profile,roles:async()=>snapshot.roles.map(name=>({name})),sessions:async()=>snapshot.sessions
  },store:{read:async(q)=>{
    const rows=snapshot.events.map(e=>({...e,occurred_at:new Date(e.occurred_at),cursor_time:e.occurred_at} as EventRow))
      .filter(e=>e.realm===q.scope.realm&&(q.source==='both'||e.source===`keycloak.${q.source}`)&&(!q.eventId||e.id===q.eventId)&&(!q.eventTypes.length||q.eventTypes.includes(e.event_type))&&
        e.occurred_at>=new Date(q.timeRange.from)&&e.occurred_at<=new Date(q.timeRange.to)&&
        (q.relationship==='target'?e.resource?.split('/')[1]===q.scope.identityId:q.relationship==='actor'?e.actor_id===q.scope.identityId:e.actor_id===q.scope.identityId||e.resource?.split('/')[1]===q.scope.identityId))
      .sort((a,b)=>b.occurred_at.getTime()-a.occurred_at.getTime()||(a.id<b.id?1:-1))
      .filter(e=>!q.position||e.occurred_at<new Date(q.position.time)||(e.occurred_at.getTime()===Date.parse(q.position.time)&&e.id<q.position.id));
    return {rows:rows.slice(0,q.eventId?1:q.pageSize+1),coverage:[]};
  }}});
}
export function domainEvidence(row:CaseRecord,tool:string) {
  const events=row.snapshot?.domainEvents??[];
  const graph=tool==='relationship_get_graph';
  const filtered=events.filter(e=>graph||e.domain===(tool==='saas_get_activity'?'saas':'cloud'));
  const nodes=[{id:row.identity_id,label:row.snapshot?.profile.username??row.identity_id,type:'identity'},...filtered.map(e=>({id:e.resource,label:e.resource,type:e.domain}))];
  return {status:'ok',tool,runId:row.id,evidenceRef:randomUUID(),identityId:row.identity_id,realm:row.run.scope.realm,retrievedAt:new Date().toISOString(),
    source:row.mode==='replay'?'synthetic-replay':'unconnected',temporalBasis:'historical_events',truncated:false,
    coverageWarnings:[row.mode==='replay'?'SIMULATED: local replay evidence, not GitHub or AWS telemetry.':'SaaS and cloud connectors are not configured. Absence of records is a coverage gap.'],
    data:graph?{nodes:[...new Map(nodes.map(n=>[n.id,n])).values()],edges:filtered.map(e=>({from:row.identity_id,to:e.resource,relationship:e.action,eventId:e.id,provenance:row.mode==='replay'?'simulated':'observed'}))}:{events:filtered}};
}
