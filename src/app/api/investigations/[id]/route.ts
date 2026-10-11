import { z } from 'zod';
import { db } from '../../../../lib/db';
import { caseDetail,audit } from '../../../../lib/investigations/store';
import { authorized,jsonBody,apiError,noStore } from '../../../../lib/investigations/http';
type Context={params:Promise<{id:string}>};
export async function GET(request:Request,context:Context){try{await authorized(request);const {id}=await context.params;return Response.json(await caseDetail(z.uuid().parse(id)),{headers:noStore});}catch(e){return apiError(e);}}
export async function POST(request:Request,context:Context){try{const analyst=await authorized(request,true);z.strictObject({action:z.literal('cancel')}).parse(await jsonBody(request));const {id}=await context.params;z.uuid().parse(id);
  const result=await db().query("UPDATE investigations SET cancel_requested=true,status=CASE WHEN status='QUEUED' THEN 'CANCELLED' ELSE status END,finished_at=CASE WHEN status='QUEUED' THEN now() ELSE finished_at END WHERE id=$1 AND status IN ('QUEUED','RUNNING') RETURNING id",[id]);
  if(result.rowCount)await audit(id,analyst.id,'CANCELLATION_REQUESTED');return Response.json({accepted:!!result.rowCount},{headers:noStore});}catch(e){return apiError(e);}}
