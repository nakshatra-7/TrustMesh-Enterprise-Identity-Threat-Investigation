// Deliberately local-demo-only. Never expose this adapter as an MCP tool.
import { createHmac } from 'node:crypto';
import { EncryptJWT,jwtDecrypt } from 'jose';
import { config } from '../config';
import { allowsLocalHttp } from '../access';
export function requireLocalDemo() {
  const c=config();if(c.KEYCLOAK_REALM!=='trustmesh'||!allowsLocalHttp(new URL(c.KEYCLOAK_URL))||!allowsLocalHttp(new URL(c.APP_URL)))throw new Error('Demo administration is restricted to the local trustmesh lab.');return c;
}
export const demoClientId='trustmesh-demo-probe';
export function demoClientSecret(){return createHmac('sha256',config().COOKIE_SECRET).update('demo-protected-resource').digest('hex');}
export async function localAdmin() {
  const c=requireLocalDemo();const auth=await fetch(`${c.KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`,{method:'POST',body:new URLSearchParams({grant_type:'password',client_id:'admin-cli',username:'bootstrap-admin',password:process.env.KEYCLOAK_ADMIN_PASSWORD??''}),signal:AbortSignal.timeout(10000)});
  if(!auth.ok)throw new Error('Local demo administration unavailable');const {access_token}=await auth.json();
  return async(path:string,method='GET',body?:unknown)=>{
    const response=await fetch(`${c.KEYCLOAK_URL}/admin/realms/trustmesh/${path}`,{method,headers:{Authorization:`Bearer ${access_token}`,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
    if(!response.ok)throw new Error(`Local provider operation failed (${response.status})`);
    return response.status===204||response.status===201?null:response.json();
  };
}
export async function encryptProbe(token:string,seconds:number){return new EncryptJWT({token}).setProtectedHeader({alg:'dir',enc:'A256GCM'}).setAudience('trustmesh-demo-probe').setIssuedAt().setExpirationTime(`${seconds}s`).encrypt(Buffer.from(config().COOKIE_SECRET,'hex'));}
export async function probeToken(encrypted:string){return (await jwtDecrypt(encrypted,Buffer.from(config().COOKIE_SECRET,'hex'),{audience:'trustmesh-demo-probe'})).payload.token as string;}
export async function inspectProbe(token:string) {
  const c=requireLocalDemo();const r=await fetch(`${c.KEYCLOAK_URL}/realms/trustmesh/protocol/openid-connect/token/introspect`,{method:'POST',body:new URLSearchParams({token,client_id:demoClientId,client_secret:demoClientSecret()}),signal:AbortSignal.timeout(10000)});
  if(!r.ok)throw new Error('Probe introspection unavailable');const result=await r.json();return {active:result.active===true,subject:result.sub as string|undefined,clientId:result.client_id as string|undefined};
}
export async function protectedProbe(token:string) {
  const c=requireLocalDemo();
  const response=await fetch(`${c.APP_URL}/api/demo/protected`,{headers:{Authorization:`Bearer ${token}`},redirect:'error',signal:AbortSignal.timeout(10000),cache:'no-store'});
  if(![200,401].includes(response.status))throw new Error('Protected demo resource unavailable');
  return response.status;
}
