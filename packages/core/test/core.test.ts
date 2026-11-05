import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm,mkdir,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {SecretVault,redact,resolveWithin,releaseArtifactHash,evaluateReleaseGate,ModelGateway,stages,pipelineSchema,appManifestSchema,BrokerClient} from '../src/index.js';
import type {ReleaseRecord,ApprovalRecord,Principal,ModelCatalog} from '../src/index.js';

const now=new Date('2026-10-10T10:00:00Z');
const owner:Principal={id:'owner',name:'Owner',roles:['platform-owner'],mfa:true,localOwner:true};
function release():ReleaseRecord{const r:ReleaseRecord={id:'release1',appId:'app1',version:'1.0.0',summary:'Initial release',artifactHash:'',commit:'a'.repeat(40),images:['registry:5000/apps/app1@sha256:'+'b'.repeat(64)],schemaVersion:1,compatibleSchemaMin:1,compatibleSchemaMax:2,baseReleaseId:null,status:'ready',evidence:{status:'passed',checkedAt:now.toISOString(),feedUpdatedAt:now.toISOString(),findings:[],checks:stages.map(name=>({name,passed:true,detail:'verified'}))},migrations:[],createdAt:now.toISOString(),publishedAt:null};r.artifactHash=releaseArtifactHash(r);return r;}
function approval(r:ReleaseRecord,action:ApprovalRecord['action']='publish'):ApprovalRecord{return {id:'approval1',appId:r.appId,releaseId:r.id,action,artifactHash:r.artifactHash,impact:['New application'],expiresAt:new Date(now.getTime()+3600000).toISOString(),approvedBy:'owner',approvedAt:now.toISOString(),consumedAt:null,checkpointId:null};}
const context=(r:ReleaseRecord)=>({currentReleaseId:null,currentSchemaVersion:1,action:'publish' as const,principal:owner,approval:approval(r),now});

test('release gate binds the approved action, schema, baseline and every mandatory check',()=>{
 const r=release();assert.equal(evaluateReleaseGate(r,context(r)).allowed,true);
 for(const mutation of [()=>r.images.push('unpinned:latest'),()=>r.evidence.checks.pop(),()=>{r.summary='different release';}]){const x=release();Object.assign(r,x);mutation();assert.equal(evaluateReleaseGate(r,context(x)).allowed,false);}
 const x=release();assert.equal(evaluateReleaseGate(x,{...context(x),currentReleaseId:'different'}).allowed,false);assert.equal(evaluateReleaseGate(x,{...context(x),currentSchemaVersion:3}).allowed,false);
});
test('expired, used, absent MFA and unavailable scans cannot publish',()=>{
 const r=release(),a=approval(r);a.expiresAt=now.toISOString();assert.equal(evaluateReleaseGate(r,{...context(r),approval:a}).allowed,false);a.expiresAt=new Date(now.getTime()+10000).toISOString();a.consumedAt=now.toISOString();assert.equal(evaluateReleaseGate(r,{...context(r),approval:a}).allowed,false);assert.equal(evaluateReleaseGate(r,{...context(r),principal:{...owner,mfa:false}}).allowed,false);r.evidence.status='unavailable';r.artifactHash=releaseArtifactHash(r);assert.equal(evaluateReleaseGate(r,context(r)).allowed,false);
});
test('contradictory, duplicate or extra failed evidence cannot pass independent publication checks',()=>{
 for(const extra of [{name:'security',passed:false,detail:'Scanner failed'},{name:'security',passed:true,detail:'Duplicate coverage'},{name:'additional-review',passed:false,detail:'Permission failure'}]){
  const r=release();r.evidence.checks.push(extra);r.artifactHash=releaseArtifactHash(r);assert.equal(evaluateReleaseGate(r,context(r)).allowed,false);
 }
 const r=release();const current={...r.evidence,checks:[{name:'image',passed:true,detail:'Scanned'},{name:'image',passed:true,detail:'Duplicate'}]};assert.equal(evaluateReleaseGate(r,{...context(r),securityEvidence:current}).allowed,false);
});
test('Medium findings require a distinct emergency action approved by the permanent local owner',()=>{
 const r=release();r.evidence.findings.push({id:'CVE-test',severity:'MEDIUM',package:'fixture',installedVersion:'1.0.0',source:'test',description:'finding'});r.artifactHash=releaseArtifactHash(r);assert.equal(evaluateReleaseGate(r,context(r)).allowed,false);const ctx={...context(r),action:'emergency_rollback' as const,approval:approval(r,'emergency_rollback')};assert.equal(evaluateReleaseGate(r,ctx).allowed,true);assert.equal(evaluateReleaseGate(r,{...ctx,principal:{...owner,localOwner:false}}).allowed,false);
});
test('emergency approval cannot bypass unclassified security findings',()=>{
 const r=release();r.evidence.findings.push({id:'unclassified',severity:'UNKNOWN',package:'fixture',installedVersion:'1',source:'fixture',description:'Missing advisory severity'});r.artifactHash=releaseArtifactHash(r);
 assert.equal(evaluateReleaseGate(r,{...context(r),action:'emergency_rollback',approval:approval(r,'emergency_rollback')}).allowed,false);
});
test('fresh target security evidence permits historical rollback without mutating the artifact',()=>{
 const r=release(),hash=r.artifactHash;r.evidence.checkedAt='2025-01-01T00:00:00Z';r.evidence.feedUpdatedAt=r.evidence.checkedAt;r.artifactHash=releaseArtifactHash(r);
 const ctx={...context(r),action:'rollback' as const,approval:approval(r,'rollback')};assert.equal(evaluateReleaseGate(r,ctx).allowed,false);
 const current={status:'passed' as const,checkedAt:now.toISOString(),feedUpdatedAt:now.toISOString(),checks:[{name:'image',passed:true,detail:'exact target image scanned'}],findings:[]};
 assert.equal(evaluateReleaseGate(r,{...ctx,securityEvidence:current}).allowed,true);assert.equal(r.artifactHash,releaseArtifactHash(r));assert.notEqual(r.artifactHash,hash);
 const found={...current,status:'failed' as const,findings:[{id:'CVE-current',severity:'MEDIUM' as const,package:'p',installedVersion:'1',source:'scanner',description:'finding'}]};
 assert.equal(evaluateReleaseGate(r,{...ctx,securityEvidence:found}).allowed,false);
 const emergency={...ctx,action:'emergency_rollback' as const,approval:approval(r,'emergency_rollback'),securityEvidence:found};assert.equal(evaluateReleaseGate(r,emergency).allowed,true);
 assert.equal(evaluateReleaseGate(r,{...emergency,securityEvidence:{...found,checks:[{name:'image',passed:false,detail:'unavailable'}]}}).allowed,false);
});
test('vault ciphertext is bound to its application context and wrong keys fail closed',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'autosoft-vault-'));try{const vault=new SecretVault(randomBytes(32),root),ref=await vault.put('connection-secret','app1:connection1');assert.equal(await vault.get(ref,'app1:connection1'),'connection-secret');assert.ok(!(await readFile(path.join(root,ref+'.json'),'utf8')).includes('connection-secret'));await assert.rejects(vault.get(ref,'app2:connection1'));await assert.rejects(new SecretVault(randomBytes(32),root).get(ref,'app1:connection1'));await assert.rejects(vault.get('../escape','app1'));}finally{await rm(root,{recursive:true,force:true});}
});
test('project paths reject traversal, drive paths and backslashes',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'autosoft-path-'));try{await mkdir(path.join(root,'src'));assert.equal(await resolveWithin(root,'src/server.mjs'),path.join(root,'src/server.mjs'));for(const p of ['../other','C:/windows/secret','C:relative','src/file:stream','src\\other','src/./x','/absolute','src//x','src/line\nbreak'])await assert.rejects(resolveWithin(root,p));}finally{await rm(root,{recursive:true,force:true});}
});
test('diagnostics redact structured secrets and pasted credential assignments',()=>{
 const value=redact({api_key:'raw',message:'password="correct horse" client_secret=opaque Bearer abc123 foo=bar'});assert.equal(value.api_key,'[REDACTED]');assert.ok(!value.message.includes('correct horse'));assert.ok(!value.message.includes('opaque'));assert.ok(!value.message.includes('abc123'));assert.ok(value.message.includes('foo=bar'));
});
test('Stripe signing, private and restricted credentials are redacted while public identities remain',()=>{
 const secrets=['whsec_'+ 'S'.repeat(24)+'+/=',...['sk_live_','sk_test_','rk_live_','rk_test_'].map(prefix=>prefix+'S'.repeat(24))];
 for(const secret of secrets){const value=redact({message:`Credential "${secret}"`,nested:[secret],publicKey:'pk_test_public',eventId:'evt_example',account:'acct_example'});assert.equal(value.message,'Credential "[REDACTED]"');assert.deepEqual(value.nested,['[REDACTED]']);assert.equal(value.publicKey,'pk_test_public');assert.equal(value.eventId,'evt_example');assert.equal(value.account,'acct_example');}
});
function catalog(provider:'openai'|'anthropic'='openai'):ModelCatalog{return {schemaVersion:1,pricesVerifiedAt:now.toISOString(),sources:['https://official.example/pricing'],models:[{id:'tested-model',provider,tier:'strong',inputUsdPerMillion:2,outputUsdPerMillion:10,cachedInputUsdPerMillion:.1,cacheWriteUsdPerMillion:2.5,effort:'high',qualified:true,maxInputTokens:90000,maxOutputTokens:32768}]};}
test('OpenAI routing reserves worst-case spending before execution and settles actual cached token cost',async()=>{
 let reserved=0,actual=0,calls=0;const gateway=new ModelGateway({catalog:catalog(),now:()=>now,apiKeys:{openai:'secret-config'},fetch:async(_url,init)=>{calls++;assert.ok(reserved>0);assert.ok(!String(init?.body).includes('secret-config'));return Response.json({service_tier:'default',output:[{type:'message',content:[{type:'output_text',text:'{"ok":true}'}]}],usage:{input_tokens:1000,output_tokens:100,input_tokens_details:{cached_tokens:500}}});}});const result=await gateway.complete({stage:'review',jobId:'job1',system:'review',prompt:'secret-config api_key=secret-config'}, {reserve:async cost=>{reserved=cost;return 'r1';},settle:async(_id,cost)=>{actual=cost;}});assert.equal(calls,1);assert.equal(result.text,'{"ok":true}');assert.equal(actual,(500*2+500*.1+100*10)/1e6);assert.ok(reserved>=actual);
});
test('Claude message extraction and cache accounting use the provider billing fields',async()=>{
 let actual=0;const gateway=new ModelGateway({catalog:catalog('anthropic'),now:()=>now,apiKeys:{anthropic:'secret'},fetch:async()=>Response.json({content:[{type:'text',text:'result'}],usage:{service_tier:'standard',input_tokens:100,output_tokens:50,cache_read_input_tokens:1000,cache_creation_input_tokens:200}})});const result=await gateway.complete({stage:'design',jobId:'job',system:'system',prompt:'prompt'},{reserve:async()=> 'r',settle:async(_id,cost)=>{actual=cost;}});assert.equal(result.text,'result');assert.equal(actual,(100*2+50*10+1000*.1+200*2.5)/1e6);
});
test('budget refusal, unqualified catalog and ambiguous provider outcomes never quietly retry',async()=>{
 let calls=0,settled=0;const base={catalog:catalog(),now:()=>now,apiKeys:{openai:'secret'},fetch:async()=>{calls++;throw new Error('timeout');}};const gateway=new ModelGateway(base);await assert.rejects(gateway.complete({stage:'design',jobId:'job',system:'s',prompt:'p'},{reserve:async()=>{throw new Error('Monthly limit');},settle:async()=>{settled++;}}));assert.equal(calls,0);await assert.rejects(gateway.complete({stage:'design',jobId:'job',system:'s',prompt:'p'},{reserve:async()=> 'r',settle:async()=>{settled++;}}),/reservation remains held/);assert.equal(calls,1);assert.equal(settled,0);base.catalog.models[0]!.qualified=false;await assert.rejects(new ModelGateway(base).complete({stage:'design',jobId:'job',system:'s',prompt:'p'},{reserve:async()=> 'r',settle:async()=>{}}),/qualified/);
});
test('pipeline cannot omit or duplicate a mandatory stage',()=>{const p={schemaVersion:1,template:'node-api',stages:stages.map(name=>({name,commands:[],timeoutSeconds:60}))};assert.equal(pipelineSchema.safeParse(p).success,true);p.stages[0]=p.stages[1]!;assert.equal(pipelineSchema.safeParse(p).success,false);});
test('hosted MCP identity and templates require authentication independently of the requested app kind',()=>{
 const manifest={schemaVersion:1,id:'app1',slug:'documents',name:'Documents',kind:'mcp',template:'node-mcp',auth:'public',permissions:['mcp.read'],connections:[],resources:{cpu:1,memoryMb:128,pids:32},health:{path:'/healthz',port:8080},storage:[]};
 assert.equal(appManifestSchema.safeParse(manifest).success,false);
 for(const auth of ['sso','local'])assert.equal(appManifestSchema.safeParse({...manifest,auth}).success,true);
 assert.equal(appManifestSchema.safeParse({...manifest,kind:'api'}).success,false);
 assert.equal(appManifestSchema.safeParse({...manifest,template:'python-api'}).success,false);
 assert.equal(appManifestSchema.safeParse({...manifest,kind:'web',template:'node-web'}).success,true);
});
test('company-managed pipeline stages reject commands while custom acceptance remains executable',()=>{for(const name of ['dependencies','security','image_packaging','preview','migration_rehearsal','acceptance']){const p={schemaVersion:1,template:'node-api',stages:stages.map(stage=>({name:stage,commands:stage===name?['npm test']:[],timeoutSeconds:60}))};assert.equal(pipelineSchema.safeParse(p).success,name==='acceptance',name);}});
test('broker requires and transmits the durable worker fence',async()=>{
 let payload:Record<string,unknown>={},calls=0;const broker=new BrokerClient({url:'https://broker:8090',token:'token',approvalKey:randomBytes(32),fetch:async(_url,init)=>{calls++;payload=JSON.parse(String(init?.body));return Response.json({});}});
 const input={app:{id:'app1',slug:'app1',name:'App',description:'',kind:'api' as const,status:'draft' as const,activeReleaseId:null,url:null,previewUrl:null,createdAt:now.toISOString(),updatedAt:now.toISOString()},job:{id:'job1',runtimeFence:7},attemptId:'attempt1',workspacePath:'/workspace/app1',pipeline:{schemaVersion:1,template:'node-api',stages:stages.map(name=>({name,commands:[],timeoutSeconds:60}))},filesHash:'a'.repeat(64)};
 await broker.verify(input);assert.equal(payload.sourceBindingVersion,1);assert.equal(payload.filesHash,input.filesHash);assert.equal(payload.fence,7);assert.equal(payload.appId,'app1');assert.equal(payload.attemptId,'attempt1');
 for(const runtimeFence of [undefined,0,-1,Number.MAX_SAFE_INTEGER+1])assert.throws(()=>broker.verify({...input,job:{id:'job1',runtimeFence}}),/durable worker fence/);
 assert.equal(calls,1);
});
for(const [label,command] of [['high surrogate','echo \ud800'],['low surrogate','echo \udc00'],['NUL','echo \0']] as const){
 test(`broker refuses ${label} pipeline commands before transport`,()=>{
  let calls=0;const broker=new BrokerClient({url:'https://broker:8090',token:'token',approvalKey:randomBytes(32),fetch:async()=>{calls++;throw new Error('Malformed pipeline must not reach transport');}});
  const pipeline={schemaVersion:1,template:'node-api',stages:stages.map(name=>({name,commands:name==='build'?[command]:[],timeoutSeconds:60}))};
  const input={app:{id:'app1',slug:'app1',name:'App',description:'',kind:'api' as const,status:'draft' as const,activeReleaseId:null,url:null,previewUrl:null,createdAt:now.toISOString(),updatedAt:now.toISOString()},job:{id:'job1',runtimeFence:7},attemptId:'attempt1',workspacePath:'/workspace/app1',pipeline,filesHash:'a'.repeat(64)};
  assert.throws(()=>broker.verify(input),/exact UTF-8 strings without NUL/);assert.equal(calls,0);
 });
}

test('broker signs the exact deployment body independently from the bearer token',async()=>{let headers:Record<string,string>={};const broker=new BrokerClient({url:'https://broker:8090',token:'token',approvalKey:randomBytes(32),fetch:async(_url,init)=>{headers=init?.headers as Record<string,string>;return Response.json({url:'https://app.example',healthy:true});}});const r=release();await broker.deploy({app:{id:'app1',slug:'app1',name:'App',description:'',kind:'api',status:'draft',activeReleaseId:null,url:null,previewUrl:null,createdAt:now.toISOString(),updatedAt:now.toISOString()},release:r,approval:approval(r),operationId:'op1',action:'publish'});assert.match(headers['x-autosoft-proof']!,/^[a-f0-9]{64}$/);assert.equal(headers.authorization,'Bearer token');});
