import 'dotenv/config';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { identityToolContracts } from '../lib/mcp/identity-contracts';
import { identityHandlersForRun } from '../lib/mcp/identity-handlers';
import { agentTools,verifyCapability } from '../lib/mcp/capability';
import { replayIdentityHandlers,domainEvidence } from '../lib/mcp/demo-adapter';
import { loadCase } from '../lib/investigations/store';
import { db } from '../lib/db';
// dotenv must not reintroduce mutation/model credentials excluded by the parent.
// This is defense in depth, not OS isolation: the local process still shares the workspace.
for(const name of ['OPENAI_API_KEY','KEYCLOAK_ADMIN_PASSWORD','EMPLOYEE_PASSWORD','ANALYST_PASSWORD'])delete process.env[name];
const server=new McpServer({name:'trustmesh-shared-evidence',version:'1.0.0'});
const definitions:Record<string,{description:string;inputSchema:z.ZodType}>={...identityToolContracts,
  saas_get_activity:{description:'Read scoped repository activity; explicitly simulated until a SaaS connector is configured.',inputSchema:z.strictObject({})},
  cloud_get_activity:{description:'Read scoped cloud activity; explicitly simulated until a cloud connector is configured.',inputSchema:z.strictObject({})},
  relationship_get_graph:{description:'Read evidence-linked identity, repository and cloud relationships. Shared addresses do not prove compromise.',inputSchema:z.strictObject({})}};
for(const [name,definition]of Object.entries(definitions))server.registerTool(name,{description:definition.description,
  inputSchema:z.strictObject({capability:z.string().max(2000),arguments:definition.inputSchema}),annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},async(input)=>{
  try {
    const claims=verifyCapability(input.capability);
    if(!agentTools[claims.agent].includes(name))throw new Error('Tool outside agent scope');
    const row=await loadCase(claims.runId);
    const claimed=await db().query("UPDATE investigations SET mcp_calls=mcp_calls+1 WHERE id=$1 AND status='RUNNING' AND NOT cancel_requested AND lease_until>now() AND mcp_calls<48 RETURNING id",[row.id]);
    if(!claimed.rowCount)throw new Error('Investigation is not active or budget exhausted');
    let result:Record<string,unknown>;
    if(name.startsWith('identity_')) {
      const handlers=row.mode==='replay'?replayIdentityHandlers(row):identityHandlersForRun(row.run);
      result=await handlers.execute({name,arguments:input.arguments});
      if(row.mode==='replay'&&result.status==='ok')result={...result,coverageWarnings:['SIMULATED: all identity evidence in this run is replay data.',...(result.coverageWarnings as string[])]};
    }else result=domainEvidence(row,name);
    return {content:[{type:'text' as const,text:JSON.stringify(result)}],structuredContent:result,isError:result.status==='error'};
  }catch{return {content:[{type:'text' as const,text:JSON.stringify({status:'error',code:'UNAVAILABLE',retryable:false,safeMessage:'MCP request denied or evidence unavailable.'})}],isError:true};}
});
await server.connect(new StdioServerTransport());
process.stdin.on('end',()=>void db().end());
