import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { signCapability,type AgentName } from './capability';
export async function connectSharedMcp() {
  const transport=new StdioClientTransport({command:process.execPath,args:['--import','tsx','src/mcp/main.ts'],cwd:process.cwd(),
    env:Object.fromEntries(Object.entries(process.env).filter((entry):entry is [string,string]=>typeof entry[1]==='string'&&!['OPENAI_API_KEY','KEYCLOAK_ADMIN_PASSWORD','EMPLOYEE_PASSWORD','ANALYST_PASSWORD'].includes(entry[0]))),stderr:'inherit'});
  const client=new Client({name:'trustmesh-investigation-runtime',version:'1.0.0'});
  await client.connect(transport);
  return {list:()=>client.listTools(),call:async(runId:string,agent:AgentName,name:string,args:Record<string,unknown>,signal?:AbortSignal)=>{
    const result=await client.callTool({name,arguments:{capability:signCapability(runId,agent),arguments:args}},undefined,{timeout:12000,signal});
    if(result.structuredContent)return result.structuredContent as Record<string,any>;
    const content=result.content as {type:string;text?:string}[];
    return JSON.parse(content.find(c=>c.type==='text')?.text??'{}') as Record<string,any>;
  },close:()=>client.close()};
}
export type SharedMcp=Awaited<ReturnType<typeof connectSharedMcp>>;
