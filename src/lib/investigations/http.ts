import { currentAnalyst } from '../auth';
import { config } from '../config';
import { z } from 'zod';
export async function authorized(request:Request,write=false){
  if(write&&request.headers.get('origin')!==new URL(config().APP_URL).origin)throw new HttpError(403,'Same-origin request required.');
  const analyst=await currentAnalyst();if(!analyst)throw new HttpError(401,'Analyst sign-in required.');return analyst;
}
export class HttpError extends Error{constructor(public status:number,message:string){super(message);}}
export async function jsonBody(request:Request){
  if(!request.headers.get('content-type')?.startsWith('application/json'))throw new HttpError(415,'JSON request required.');
  const reader=request.body?.getReader();if(!reader)throw new HttpError(400,'Request body missing.');let size=0;const chunks:Uint8Array[]=[];
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16384){await reader.cancel();throw new HttpError(413,'Request too large.');}chunks.push(value);}
  try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw new HttpError(400,'Invalid JSON.');}
}
export function apiError(error:unknown){if(error instanceof HttpError)return Response.json({error:error.message},{status:error.status});if(error instanceof z.ZodError)return Response.json({error:'Request does not match the allowed schema.'},{status:400});return Response.json({error:'Operation unavailable. Check dependencies, model configuration, demo setup, or whether the action has expired/already been decided.'},{status:503});}
export const noStore={'Cache-Control':'no-store'};
