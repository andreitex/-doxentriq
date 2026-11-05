import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { sourceFilesHash, pipelineDefinitionHash } from '../../../packages/core/src/source-hash.ts';
import { writeScopedFiles, WorkflowEngine } from '../src/engine.ts';
import { JsonStore } from '../src/store.ts';
import { BudgetManager } from '../src/budget.ts';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';
import { validatedVerification } from '../src/verification.ts';
import { snapshotFixture } from '../../../packages/core/test/migration-snapshot-fixture.ts';
import { stages } from '../../../packages/core/src/schemas.ts';
const sharedVectors = JSON.parse(String.raw`[{"name":"empty","files":[],"hash":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"},{"name":"basic","files":[{"path":"a.txt","content":"x\n"},{"path":"empty.txt","content":""}],"hash":"ab8634c7c735ccf6792c22ffd7c2387e39cb390eb574361c378570514871953a"},{"name":"html-and-separators","files":[{"path":"<>&\u2028\u2029.txt","content":"<>&\u2028\u2029"}],"hash":"cedb2de6b3895d35077e79e53b0c90f66649face49bb616fa61ba7fef92d98c3"},{"name":"utf8-order","files":[{"path":"\ud800\udc00.txt","content":"supplementary"},{"path":"\ue000.txt","content":"bmp"},{"path":"\u00e9.txt","content":"accent"}],"hash":"784d572d5d240d18577a24c3b296cc14d5de9af9a1ba0a0c3f834c64f02bc89c"},{"name":"nul-single","files":[{"path":"a","content":"x\u0000b\u0000y"}],"hash":"e9c0e4f9704fe03ac2e05dcec8ec71b158531e4187a46b75984ecb9e1b9ee1ed"},{"name":"nul-pair","files":[{"path":"a","content":"x"},{"path":"b","content":"y"}],"hash":"f7cb1e2c431a7dc6460ce02493a2efacf2212eb8d0961d8c9857b747f0ea607a"}]`) as {name:string;files:{path:string;content:string}[];hash:string}[];
for (const v of sharedVectors) test(`canonical source shared vector: ${v.name}`,()=>{
  assert.equal(sourceFilesHash(v.files),v.hash);
  assert.equal(sourceFilesHash([...v.files].reverse()),v.hash);
});
test('NUL content cannot alias a second file in the canonical input digest',()=>{
 const old=(files:{path:string;content:string}[])=>{const h=createHash('sha256');for(const f of files)h.update(f.path).update('\0').update(f.content).update('\0');return h.digest('hex');};
 const a=sharedVectors.find(v=>v.name==='nul-single')!,b=sharedVectors.find(v=>v.name==='nul-pair')!;
 assert.equal(old(a.files),old(b.files));assert.notEqual(sourceFilesHash(a.files),sourceFilesHash(b.files));
});
test('source hash rejects non-roundtripping paths, aliases and capacity overflow',()=>{
 for(const path of ['../a','a//b','a\\b','a:b','/a','a\0b','a\ud800'])assert.throws(()=>sourceFilesHash([{path,content:''}]));
 assert.throws(()=>sourceFilesHash([{path:'a',content:''},{path:'a',content:'x'}]));
 assert.throws(()=>sourceFilesHash(Array.from({length:601},(_,i)=>({path:`f${i}`,content:''}))));
 assert.throws(()=>sourceFilesHash([{path:'a',content:'x'.repeat(20*1024**2+1)}]));
});
test('writeScopedFiles binds exact UTF-8 bytes on disk and rejects malformed paths before root creation',async()=>{
 const root=await mkdtemp(join(tmpdir(),'autosoft-source-hash-'));
 try{const files=[{path:'src/a.txt',content:'x\0y\n'},{path:'empty',content:''},{path:'replacement.txt',content:'a\ud800b'}];
  assert.equal(await writeScopedFiles(join(root,'good'),files),sourceFilesHash(files));
  for(const f of files)assert.deepEqual(await readFile(join(root,'good',f.path)),Buffer.from(f.content));
  await assert.rejects(writeScopedFiles(join(root,'bad'),[{path:'a\ud800',content:''}]));
  await assert.rejects(readFile(join(root,'bad','a')),(e:NodeJS.ErrnoException)=>e.code==='ENOENT');
 }finally{await rm(root,{recursive:true,force:true});}
});
const pipeline={schemaVersion:1,template:'node-api',stages:stages.map(name=>({name,commands:name==='build'?['echo <>&\u2028\u2029']:[],timeoutSeconds:60}))};
test('pipeline hash uses Go JSON field order and escaping',()=>{
 assert.equal(pipelineDefinitionHash(pipeline),'024548cb9a57601133fe055d77bb6566ea077537da76e10b3f9356d57010a81c');
 assert.equal(pipelineDefinitionHash({stages:pipeline.stages,template:pipeline.template,schemaVersion:1}),pipelineDefinitionHash(pipeline));
 assert.throws(()=>pipelineDefinitionHash({...pipeline,schemaVersion:2}));
});
test('pipeline commands reject lossy surrogates and NUL while preserving valid scalar pairs',()=>{
 for(const command of ['echo \ud800','echo \udc00','echo \0']) {
  const p=structuredClone(pipeline);p.stages[1]!.commands=[command];assert.throws(()=>pipelineDefinitionHash(p),/UTF-8/);
 }
 const p=structuredClone(pipeline);p.stages[1]!.commands=['echo \ud83d\ude00'];assert.match(pipelineDefinitionHash(p),/^[a-f0-9]{64}$/);
});
test('lossy pipeline pauses workflow before source writes or broker execution',async()=>{
 const root=await mkdtemp(join(tmpdir(),'autosoft-pipeline-wire-'));let calls=0;
 try {const store=new JsonStore();const now=new Date().toISOString();
  const app:AppRecord={id:'app1',slug:'app',name:'App',description:'',kind:'api',status:'draft',activeReleaseId:null,url:null,previewUrl:null,createdAt:now,updatedAt:now};
  const job:JobRecord={id:'job1',appId:app.id,request:'Build API',stage:'queued',baseReleaseId:null,costUsd:0,budgetUsd:1,attempts:0,createdAt:now,updatedAt:now};
  await store.transaction(state=>{state.apps[app.id]=app;state.jobs[job.id]=job;});const p=structuredClone(pipeline);p.stages[1]!.commands=['echo \ud800'];
  const engine=new WorkflowEngine(store,{planAndGenerate:async()=>({specification:{},files:[{path:'server.mjs',content:'export const ok=true;'}],pipeline:p,summary:'fixture'}),verify:async()=>{calls++;throw new Error('Broker must never run');}},new BudgetManager(store,1,5),root);
  await engine.run(job.id);assert.equal(calls,0);assert.equal(await store.read(state=>state.jobs[job.id]?.stage),'needs_attention');assert.deepEqual(await readdir(root),[]);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('passed verification denies legacy, forged input, wrong pipeline and stale final snapshot bindings',()=>{
 const snap=snapshotFixture();const expected={jobId:'job1',attemptId:'attempt1',fence:2,baseReleaseId:null,baseArtifactHash:'',baseImage:'',filesHash:'a'.repeat(64),pipelineHash:pipelineDefinitionHash(pipeline)};
 const v={appId:'app1',attemptId:'attempt1',filesHash:expected.filesHash,sourceBindingVersion:1,inputSourceHash:expected.filesHash,pipelineHash:expected.pipelineHash,sourceHash:snap.binding.sourceHash,schemaVersion:1,compatibleSchemaMin:1,compatibleSchemaMax:1,migrations:[],migrationSnapshot:snap,evidence:{status:'passed',checkedAt:new Date().toISOString(),feedUpdatedAt:new Date().toISOString(),findings:[],checks:stages.map(name=>({name,passed:true,detail:'fixture'}))},images:[`registry.test/app@sha256:${'b'.repeat(64)}`],commit:'a'.repeat(40),previewUrl:null};
 assert.equal(validatedVerification(v,'app1',expected).sourceBindingVersion,1);
 for(const change of [{sourceBindingVersion:undefined},{sourceBindingVersion:true},{sourceBindingVersion:2},{inputSourceHash:'f'.repeat(64)},{filesHash:'f'.repeat(64)},{pipelineHash:'f'.repeat(64)},{sourceHash:'f'.repeat(64)}])assert.throws(()=>validatedVerification({...v,...change},'app1',expected));
});
