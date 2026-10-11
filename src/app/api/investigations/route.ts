import { db } from '../../../lib/db';
import { startCase } from '../../../lib/investigations/store';
import { scenarios } from '../../../lib/investigations/scenarios';
import { evaluateModel } from '../../../lib/investigations/risk';
import { authorized,jsonBody,apiError,noStore } from '../../../lib/investigations/http';
export const dynamic='force-dynamic';
export async function GET(request:Request){try{await authorized(request);const [cases,identities,health]=await Promise.all([
  db().query("SELECT id,title,identity_id,mode,engine,status,detection,created_at,finished_at,run->'modelConfiguration'->>'provider' AS provider FROM investigations ORDER BY created_at DESC LIMIT 100"),
  db().query('SELECT identity_id,username FROM demo_identities ORDER BY username'),db().query("SELECT updated_at,details FROM runtime_health WHERE name='investigations'")]);
  return Response.json({cases:cases.rows,identities:identities.rows,scenarios,evaluation:evaluateModel(),modelConfigured:!!process.env.OPENAI_API_KEY&&!!process.env.OPENAI_MODEL,
    runtime:{healthy:!!health.rows[0]&&Date.now()-new Date(health.rows[0].updated_at).getTime()<30000,...health.rows[0]}},{headers:noStore});
}catch(e){return apiError(e);}}
export async function POST(request:Request){try{const analyst=await authorized(request,true);const id=await startCase(await jsonBody(request),analyst.id);return Response.json({id},{status:202,headers:noStore});}catch(e){return apiError(e);}}
