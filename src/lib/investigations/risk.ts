import type { DemoSnapshot } from './scenarios';
export type Features = { failures:number; networks:number; roleChanges:number; bulkReads:number; privilegedCloud:number; mfa:boolean };
export function featuresFrom(snapshot: DemoSnapshot):Features {
  return {failures:snapshot.events.filter(e=>e.outcome==='failure').length,
    networks:new Set(snapshot.events.map(e=>e.ip_address)).size,
    roleChanges:snapshot.events.filter(e=>e.event_type.includes('ROLE_MAPPING')).length,
    bulkReads:snapshot.domainEvents.filter(e=>e.domain==='saas').reduce((n,e)=>n+e.volume,0),
    privilegedCloud:snapshot.domainEvents.filter(e=>e.domain==='cloud'&&e.privileged).length,
    mfa:snapshot.events.some(e=>e.details.auth_method==='mfa')};
}
const vector=(f:Features)=>[1,Math.min(f.failures,10)/10,Math.max(0,Math.min(f.networks-1,3))/3,Math.min(f.roleChanges,2)/2,Math.min(f.bulkReads,500)/500,Math.min(f.privilegedCloud,2)/2,f.mfa?1:0];
const sigmoid=(x:number)=>1/(1+Math.exp(-Math.max(-30,Math.min(30,x))));
function data(seed:number,count:number) {
  let s=seed;const random=()=>((s=(Math.imul(s,1664525)+1013904223)>>>0)/4294967296);
  return Array.from({length:count},()=>{
    const attack=random()<0.5, kind=Math.floor(random()*3);
    const f:Features={failures:attack&&kind===0?5+Math.floor(random()*5):Math.floor(random()*3),networks:attack?2+Math.floor(random()*2):1+Math.floor(random()*2),
      roleChanges:attack&&kind===1?1:0,bulkReads:attack&&kind===2?250+Math.floor(random()*250):Math.floor(random()*15),privilegedCloud:attack&&kind===2?1:0,mfa:!attack&&random()<0.7};
    return {f,label:attack?1:0};
  });
}
// Small reproducible logistic baseline. Synthetic metrics are not production fraud accuracy.
const training=data(4281,300), weights=Array(7).fill(0) as number[];
for(let epoch=0;epoch<350;epoch++) {const gradient=Array(7).fill(0);for(const row of training){const x=vector(row.f),err=sigmoid(x.reduce((n,v,i)=>n+v*weights[i],0))-row.label;x.forEach((v,i)=>gradient[i]+=err*v);}weights.forEach((w,i)=>weights[i]=w-0.5*(gradient[i]/training.length+0.002*w));}
export function modelScore(f:Features) {return sigmoid(vector(f).reduce((n,v,i)=>n+v*weights[i],0));}
export function detect(f:Features) {
  const signals:{name:string;weight:number}[]=[];
  if(f.failures>=5) signals.push({name:'Repeated authentication failures',weight:35});
  if(f.networks>1&&!f.mfa) signals.push({name:'Multiple networks without observed MFA',weight:20});
  if(f.roleChanges) signals.push({name:'Realm role change',weight:55});
  if(f.bulkReads>=100) signals.push({name:'Bulk repository reads',weight:45});
  if(f.privilegedCloud) signals.push({name:'Privileged cloud activity',weight:45});
  const ruleRisk=Math.min(100,signals.reduce((n,s)=>n+s.weight,0)),anomalyScore=Math.round(modelScore(f)*100);
  return {features:f,signals,ruleRisk,anomalyScore,risk:Math.round(0.8*ruleRisk+0.2*anomalyScore),model:'synthetic-logistic-v1',modelDisclaimer:'Trained on synthetic feature vectors; not a calibrated threat probability.'};
}
export function evaluateModel() {
  let tp=0,tn=0,fp=0,fn=0;for(const r of data(93147,120)){const p=modelScore(r.f)>=0.5;if(p&&r.label)tp++;else if(p)fp++;else if(r.label)fn++;else tn++;}
  const precision=tp/(tp+fp||1),recall=tp/(tp+fn||1);
  return {dataset:'Held-out synthetic feature vectors (separate random seed)',trainingSamples:300,testSamples:120,tp,tn,fp,fn,precision,recall,f1:2*precision*recall/(precision+recall||1),falsePositiveRate:fp/(fp+tn||1),disclaimer:'Generator-based smoke evaluation, not independent real-world validation.'};
}
