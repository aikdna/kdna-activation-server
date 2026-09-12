import assert from 'node:assert/strict';
import { Readable, Writable } from 'node:stream';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { admitNode } from '@aikdna/kdna-core/node';
import { inspectSnapshot } from '@aikdna/kdna-core/read-boundary';
import { admitReadRequest, project } from '@aikdna/kdna-read';
import { createTrustedReadControlProvider } from '@aikdna/kdna-read/embedding';
import { createRemoteReadHandler } from '@aikdna/kdna-remote-server';
import { tuple } from '../current-fixture.mjs';
const role=process.argv[2]??'remote';assert.ok(['remote','activation'].includes(role));
const activation=role==='activation'?await import('@aikdna/kdna-activation-server'):null;
const output=process.argv[3];const fixtureRoot=new URL('./fixtures/',import.meta.url);
const control=createTrustedReadControlProvider(()=>({admission_response_limit_bytes:4096}));
const records=[];let sequence=0;
const names=['independent-mechanisms.kdna','explicit-empty-candidate-set.kdna','no-parent-method-is-absent.kdna','presence-declared-undeclared.kdna','presence-undeclared-undeclared.kdna','old-asset.kdna'];
const badCases={'known-component-definition-mismatch.kdna':'READ_COMPONENT_DECLARATION_INVALID','presence-with-no-parent.kdna':'READ_METHOD_PRESENCE_INVALID','taxonomy-cycle.kdna':'READ_COMPONENT_GRAPH_CYCLE'};
const request=(view,judgment,extra={})=>({request_id:'request:components-'+(++sequence),tuple,budget_bytes:1000000,mode:'exact_selection',selection:{asset_id:view.asset.asset_id,asset_version:view.asset.asset_version,judgment_id:judgment},handle:null,...extra});
async function streamCall(handler,body,options={}){
 const data=Buffer.from(JSON.stringify(body));const req=Readable.from([data]);req.url=options.url??'/read';req.method='POST';req.headers={'content-type':'application/json','content-length':String(data.length),authorization:options.bearer??'SYNTHETIC-COMPONENT-BEARER'};
 const chunks=[];const res=new Writable({write(chunk,enc,done){chunks.push(Buffer.from(chunk));done();}});res.statusCode=0;res.headers={};res.setHeader=(name,value)=>{res.headers[name]=value;};
 if(options.breakSink){res.end=()=>{res.destroy();return res;};}
 if(options.beforeFinish){const end=res.end.bind(res);res.end=(...args)=>{options.beforeFinish();return end(...args);};}
 const local=await handler(req,res);const bytes=Buffer.concat(chunks);let parsed=null;try{parsed=JSON.parse(bytes);}catch{}
 return {status:res.statusCode,bytes,body:parsed,local,headers:res.headers};
}
async function setup(bytes,view,options={}){
 const context=Object.freeze({synthetic:true});let allowed=true,observations=0;let observer=null,store=null,binding=null;
 const scope=options.scope??view.ir.nodes.map(n=>n.id);let cfg={resolveContext:()=>context,verifyContext:c=>c===context,observePolicy:options.defaultDeny?undefined:()=>({decision:allowed?'allow':'deny',scope,epoch:'epoch:components',policyId:'policy:components'})};
 if(activation){const dir=mkdtempSync(join(process.env.KDNA_TEST_DIR??tmpdir(),'activation-components-'));store=activation.makeStore(dir);const row=store.create({domain:'kdna:synthetic:components',license_id:'license:components',license_key:'SYNTHETIC-COMPONENT-BEARER',ttl_days:1,require_machine_binding:false});binding={licenseId:row.license_id,legacyDomain:'kdna:synthetic:components',snapshot:(await admitNode(bytes)).snapshot,scope,epoch:'epoch:components',policyId:'policy:components'};observer=activation.createActivationObserver({store,binding,readBinding:()=>binding});cfg={resolveContext:req=>observer.authenticate(req.headers.authorization),verifyContext:observer.verifyContext,observePolicy:options.defaultDeny?undefined:observer.observePolicy};}
 const original=cfg.observePolicy;cfg.observePolicy=original?(async value=>{observations++;return original(value);}):undefined;
 const handler=createRemoteReadHandler({assetBytes:bytes,bindingId:'binding:components',authorizationDomainId:'domain:components',...cfg});
 return {handler,observer,get observations(){return observations;},revoke(){if(store)store.revoke(binding.licenseId,{reason:'synthetic current revocation'});else allowed=false;},dispose(){handler.dispose();observer?.dispose();}};
}
function compareContent(body,pure,view,selection){
 assert.equal(body.status,'ready');const expected=pure.body.content;const actual={...body.content,expansion_handles:[]};assert.deepEqual(actual,expected);
 const closure=view.ir.mandatory_closures.find(x=>x.selection.judgment_id===selection.judgment_id);assert.ok(closure);const map=new Map(view.ir.nodes.map(n=>[n.id,n]));assert.deepEqual(body.content.closure,closure.node_ids.map(id=>map.get(id)));
 assert.equal(body.states.action_authorization,'not_evaluated');assert.ok(['not_evaluated','claimed_unverified'].includes(body.states.confirmation));
}
for(const name of names){
 const bytes=readFileSync(new URL(name,fixtureRoot));const admitted=await admitNode(bytes);assert.equal(admitted.status,'accepted',name);const view=inspectSnapshot(admitted.snapshot);assert.deepEqual(view.tuple,tuple);
 for(const item of view.ir.catalog){const req=request(view,item.judgment_id),ar=admitReadRequest(req,control);assert.equal(ar.channel,'admitted_request');const pure=project(ar.admitted_request,admitted.snapshot);assert.equal(pure.status,'projected');const s=await setup(bytes,view);
  try{const result=await streamCall(s.handler,req);assert.equal(result.status,200);compareContent(result.body,pure,view,req.selection);assert.equal(Number(result.body.budget.actual_bytes),result.bytes.length);assert.equal(result.local.envelope.status,'ready');
   const methods=result.body.content.closure.filter(n=>n.role==='method').map(n=>n.value);
   if(name==='independent-mechanisms.kdna'){const parts=methods.flatMap(x=>x.component_interpretations);assert.equal(parts.length,4);assert.deepEqual([...new Set(parts.map(x=>x.body.kind))].sort(),['candidate-set','discriminator-set','taxonomy']);assert.equal(parts.find(x=>x.body.kind==='taxonomy').body.broader.length,4);assert.ok(JSON.stringify(parts).includes('证据来源'));}
   if(name==='explicit-empty-candidate-set.kdna')assert.deepEqual(methods[0].component_interpretations[0].body,{kind:'candidate-set',items:[]});
   if(name==='no-parent-method-is-absent.kdna')assert.deepEqual(methods,[]);
   if(name.startsWith('presence-'))assert.equal(methods[0].declaration_presence.components_state,name.includes('declared-undeclared')&&!name.startsWith('presence-undeclared')?'declared':'undeclared');
   records.push({name,judgment:item.judgment_id,sha256:createHash('sha256').update(bytes).digest('hex'),bytes:result.bytes.length,body:result.body,methodCount:methods.length,policyObservations:s.observations,mode:'actual-public-handler-in-memory-stream'});
  }finally{s.dispose();}
 }
}
const mainBytes=readFileSync(new URL(names[0],fixtureRoot)),mainAdmitted=await admitNode(mainBytes),view=inspectSnapshot(mainAdmitted.snapshot),judgment=view.ir.catalog[0].judgment_id;
for(const [name,reason]of Object.entries(badCases)){
 const bytes=readFileSync(new URL(name,fixtureRoot)),a=await admitNode(bytes);assert.equal(a.status,'rejected');assert.equal(a.reason,reason);let calls=0;const h=createRemoteReadHandler({assetBytes:bytes,bindingId:'binding:invalid',authorizationDomainId:'domain:invalid',resolveContext:()=>({}),verifyContext:()=>true,observePolicy:()=>{calls++;return{decision:'allow',scope:[],epoch:'e',policyId:'p'};}});
 try{const r=await streamCall(h,request(view,judgment));assert.equal(r.status,422);assert.equal(r.body.diagnostics[0].code,reason);assert.equal(r.body.content,null);assert.equal(calls,0);records.push({name,rejection:reason,publicBody:r.body,policyObservations:calls});}finally{h.dispose();}
}
for(const kind of ['default-deny','scope','revoke','replay','wrong-asset','wrong-version','old-tuple','budget','action','sink-failure']){
 const scope=kind==='scope'?view.ir.nodes.filter(n=>n.role!=='method').map(n=>n.id):undefined;const s=await setup(mainBytes,view,{scope,defaultDeny:kind==='default-deny'});const req=request(view,judgment);let r;
 try{
  if(kind==='revoke'){const first=await streamCall(s.handler,req);assert.equal(first.status,200);s.revoke();r=await streamCall(s.handler,request(view,judgment));}
  else if(kind==='replay'){assert.equal((await streamCall(s.handler,req)).status,200);r=await streamCall(s.handler,req);}
  else if(kind==='wrong-asset')r=await streamCall(s.handler,{...req,selection:{...req.selection,asset_id:'asset:other'}});
  else if(kind==='wrong-version')r=await streamCall(s.handler,{...req,selection:{...req.selection,asset_version:'9.9.9'}});
  else if(kind==='old-tuple')r=await streamCall(s.handler,{...req,tuple:{...tuple,core:'kdna.core/0.2.0'}});
  else if(kind==='budget')r=await streamCall(s.handler,{...req,budget_bytes:1});
  else if(kind==='action')r=await streamCall(s.handler,{...req,action_authorized:true});
  else r=await streamCall(s.handler,req,{breakSink:kind==='sink-failure'});
  if(kind==='sink-failure'){assert.equal(r.local.channel,'transport_failure');assert.equal(s.handler.retentionState().issued_handle_records,0);assert.equal(s.handler.retentionState().state,'closed');}
  else{assert.notEqual(r.status,200);assert.equal(r.body?.content??null,null);assert.equal(r.bytes.includes(Buffer.from('证据来源')),false);}
  records.push({boundary:kind,status:r.status,body:r.body,localChannel:r.local?.channel,retention:s.handler.retentionState()});
 }finally{s.dispose();}
}
const summary={status:'PASS_COMPONENT_HANDLER_STREAMS',role,transport:'in-memory Node Readable/Writable request and response, not actual HTTP or remote acknowledgement',records,ready:records.filter(x=>x.body?.status==='ready').length,rejected:3,boundaries:10};
if(output)writeFileSync(output,JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify({status:summary.status,role,ready:summary.ready,rejected:3,boundaries:10}));
