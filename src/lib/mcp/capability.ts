import { createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { config } from '../config';
export const agentName=z.enum(['lead','identity','saas','cloud']);
export type AgentName=z.infer<typeof agentName>;
const claims=z.strictObject({runId:z.uuid(),agent:agentName,expires:z.number().int().positive()});
export function signCapability(runId:string,agent:AgentName,now=Date.now()) {
  const body=Buffer.from(JSON.stringify(claims.parse({runId,agent,expires:now+10*60000}))).toString('base64url');
  return `${body}.${createHmac('sha256',config().COOKIE_SECRET).update('mcp:'+body).digest('base64url')}`;
}
export function verifyCapability(token:string,now=Date.now()) {
  if(token.length>2000)throw new Error('Unauthorized MCP capability');
  const [body,signature,...extra]=token.split('.');const expected=createHmac('sha256',config().COOKIE_SECRET).update('mcp:'+body).digest();
  const received=Buffer.from(signature??'','base64url');
  if(extra.length||received.length!==expected.length||!timingSafeEqual(received,expected))throw new Error('Unauthorized MCP capability');
  const result=claims.parse(JSON.parse(Buffer.from(body,'base64url').toString()));
  if(result.expires<=now)throw new Error('Expired MCP capability');return result;
}
export const agentTools:Record<AgentName,readonly string[]>={lead:['relationship_get_graph'],identity:['identity_get_profile','identity_get_roles','identity_get_sessions','identity_search_events','identity_get_event'],saas:['saas_get_activity','relationship_get_graph'],cloud:['cloud_get_activity','relationship_get_graph']};
