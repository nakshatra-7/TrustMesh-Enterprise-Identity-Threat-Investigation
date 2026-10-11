import { randomUUID } from 'node:crypto';
import { z } from 'zod';
export const scenarioId = z.enum(['session-abuse','privilege-escalation','cross-domain','legitimate-travel','normal']);
export type ScenarioId = z.infer<typeof scenarioId>;
export const scenarios = [
  { id: 'session-abuse', title: 'One session, two networks', description: 'Repeated failures followed by overlapping use of one session from two networks.', user: 'demo-alice' },
  { id: 'privilege-escalation', title: 'Unexpected privilege expansion', description: 'A role change followed by administrative use and repository access.', user: 'demo-bob' },
  { id: 'cross-domain', title: 'Identity → repository → cloud', description: 'Suspicious sign-in, bulk repository downloads and an unusual cloud credential.', user: 'demo-charlie' },
  { id: 'legitimate-travel', title: 'The legitimate anomaly', description: 'A new network with successful MFA and ordinary application activity.', user: 'demo-dana' },
  { id: 'normal', title: 'A normal working day', description: 'Routine authentication and low-volume application activity.', user: 'demo-alice' }
] as const;
export type DomainEvent = { id: string; domain: 'saas'|'cloud'; action: string; resource: string; ip: string; occurredAt: string; volume: number; privileged: boolean };
export type DemoSnapshot = {
  profile: {id:string; username:string; enabled:boolean}; roles: string[];
  sessions: {id:string;userId:string;ipAddress:string;start:number;lastAccess:number;clients:Record<string,string>}[];
  events: {id:string;source:'keycloak.user'|'keycloak.admin';realm:string;event_type:string;occurred_at:string;actor_id:string;session_id:string;client_id:string;ip_address:string;resource:string|null;outcome:'success'|'failure';details:Record<string,string>}[];
  domainEvents: DomainEvent[];
};
export function makeScenario(id: ScenarioId, identityId:string, username:string, realm:string, now=Date.now()): DemoSnapshot {
  const sessionId = `replay-session-${randomUUID()}`;
  const at = (minutes:number) => new Date(now - minutes*60000).toISOString();
  const snapshot: DemoSnapshot = {profile:{id:identityId,username,enabled:true}, roles:['employee'],
    sessions:[{id:sessionId,userId:identityId,ipAddress:'192.0.2.10',start:now-3600000,lastAccess:now-60000,clients:{portal:'employee-portal'}}],events:[],domainEvents:[]};
  const event = (event_type:string, minute:number, ip='192.0.2.10', failure=false, admin=false, details:Record<string,string>={}) => snapshot.events.push({
    id:randomUUID(),source:admin?'keycloak.admin':'keycloak.user',realm,event_type,occurred_at:at(minute),actor_id:identityId,
    session_id:sessionId,client_id:'employee-portal',ip_address:ip,resource:admin?`users/${identityId}/role-mappings/realm`:null,
    outcome:failure?'failure':'success',details
  });
  event('LOGIN',55); event('TOKEN_REFRESH',45);
  if (id==='session-abuse'||id==='cross-domain') {
    for(let i=0;i<6;i++) event('LOGIN_ERROR',20+i,'198.51.100.24',true);
    event('LOGIN',19,'198.51.100.24'); event('TOKEN_REFRESH',18,'192.0.2.10'); event('TOKEN_REFRESH',17,'198.51.100.24');
    snapshot.sessions[0].ipAddress='198.51.100.24';
  }
  if(id==='privilege-escalation') { snapshot.roles.push('realm-admin'); event('ROLE_MAPPING_CREATE',15,'198.51.100.24',false,true); event('ADMIN_ACCESS',14,'198.51.100.24'); }
  if(id==='legitimate-travel') { event('LOGIN',15,'203.0.113.50',false,false,{auth_method:'mfa',reason:'MFA verification recorded'}); event('TOKEN_REFRESH',10,'203.0.113.50'); }
  const domain = (domain:'saas'|'cloud',action:string,resource:string,volume:number,privileged=false) => snapshot.domainEvents.push({id:randomUUID(),domain,action,resource,volume,privileged,ip:privileged?'198.51.100.24':'192.0.2.10',occurredAt:at(domain==='saas'?12:8)});
  domain('saas','REPOSITORY_READ','repo:internal-docs',id==='cross-domain'?420:3,id==='cross-domain');
  if(id==='privilege-escalation') domain('saas','REPOSITORY_PERMISSION_CHANGE','repo:operations',1,true);
  domain('cloud',id==='cross-domain'?'ACCESS_KEY_CREATED':'OBJECT_READ',id==='cross-domain'?'cloud:demo-access-key':'bucket:demo-documents',id==='cross-domain'?100:2,id==='cross-domain');
  return snapshot;
}
