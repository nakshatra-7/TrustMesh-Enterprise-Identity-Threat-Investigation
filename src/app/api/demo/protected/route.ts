import { db } from '../../../../lib/db';
import { demoClientId,inspectProbe,requireLocalDemo } from '../../../../lib/investigations/local-admin';
export const dynamic='force-dynamic';
export async function GET(request:Request){
  const headers={'Cache-Control':'no-store'};
  try{
    requireLocalDemo();const bearer=request.headers.get('authorization');
    if(!bearer?.startsWith('Bearer ')||bearer.length>16384)return Response.json({access:'denied'},{status:401,headers});
    const identity=await inspectProbe(bearer.slice(7));
    if(!identity.active||!identity.subject||identity.clientId!==demoClientId)return Response.json({access:'denied'},{status:401,headers});
    const demo=await db().query('SELECT 1 FROM demo_identities WHERE identity_id=$1',[identity.subject]);
    if(!demo.rowCount)return Response.json({access:'denied'},{status:401,headers});
    return Response.json({access:'allowed',resource:'non-sensitive demo document'},{headers});
  }catch{return Response.json({access:'unavailable'},{status:503,headers});}
}
