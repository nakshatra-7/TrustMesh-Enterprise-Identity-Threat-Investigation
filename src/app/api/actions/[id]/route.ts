import { z } from 'zod';
import { decideAction } from '../../../../lib/investigations/actions';
import { authorized,jsonBody,apiError,noStore } from '../../../../lib/investigations/http';
export async function POST(request:Request,context:{params:Promise<{id:string}>}){try{const analyst=await authorized(request,true);const body=z.strictObject({decision:z.enum(['approve','reject'])}).parse(await jsonBody(request));const {id}=await context.params;await decideAction(id,analyst.id,body.decision);return Response.json({accepted:true},{headers:noStore});}catch(e){return apiError(e);}}
