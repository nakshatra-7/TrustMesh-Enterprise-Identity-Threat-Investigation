import 'dotenv/config';
import { claimNext,executeCase } from '../lib/agents/runtime';
import { connectSharedMcp } from '../lib/mcp/client';
import { db } from '../lib/db';
let stopping=false;process.on('SIGTERM',()=>{stopping=true;});process.on('SIGINT',()=>{stopping=true;});
const shared=await connectSharedMcp();console.log('Investigation worker ready. One shared MCP process; containment requires analyst approval.');
const heartbeat=async()=>{await db().query("INSERT INTO runtime_health(name,updated_at,details) VALUES('investigations',now(),$1) ON CONFLICT(name) DO UPDATE SET updated_at=now(),details=EXCLUDED.details",[JSON.stringify({mcpTools:(await shared.list()).tools.length,engine:process.env.OPENAI_API_KEY&&process.env.OPENAI_MODEL?'openai-ready':'rehearsal-only'})]);};
await heartbeat();const heartbeatTimer=setInterval(()=>void heartbeat().catch(()=>{}),10000);
try{while(!stopping){try{const id=await claimNext();if(id)await executeCase(id,shared);else await new Promise(r=>setTimeout(r,1000));}catch{console.error('Investigation worker dependency unavailable; retrying.');await new Promise(r=>setTimeout(r,3000));}}}
finally{clearInterval(heartbeatTimer);await shared.close();await db().end();}
