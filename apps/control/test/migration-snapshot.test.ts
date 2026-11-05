import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validatedVerification } from '../src/verification.ts';
import { hashArtifact,releaseArtifactHash } from '../../../packages/core/src/security.ts';
import { snapshotFixture } from '../../../packages/core/test/migration-snapshot-fixture.ts';
import { pipelineDefinitionHash } from '../../../packages/core/src/source-hash.ts';
import { stages } from '../../../packages/core/src/schemas.ts';
import { mkdtemp,rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { JsonStore } from '../src/store.ts';
import { WorkflowEngine } from '../src/engine.ts';
import { BudgetManager } from '../src/budget.ts';
import type { AppRecord,JobRecord } from '../../../packages/core/src/types.ts';
const boundPipeline={schemaVersion:1,template:'node-api',stages:stages.map(name=>({name,commands:[],timeoutSeconds:60}))};
const context={jobId:'job1',attemptId:'attempt1',fence:2,baseReleaseId:null,baseArtifactHash:'',baseImage:'',filesHash:'a'.repeat(64),pipelineHash:pipelineDefinitionHash(boundPipeline)};
const value=()=>({appId:'app1',attemptId:'attempt1',filesHash:context.filesHash,sourceBindingVersion:1 as const,inputSourceHash:context.filesHash,pipelineHash:context.pipelineHash,sourceHash:'c'.repeat(64),template:'node-api',schemaVersion:1,compatibleSchemaMin:1,compatibleSchemaMax:1,migrations:[],migrationSnapshot:snapshotFixture(),evidence:{status:'passed' as const,checkedAt:new Date().toISOString(),feedUpdatedAt:new Date().toISOString(),findings:[],checks:stages.map(name=>({name,passed:true,detail:'fixture'}))},commit:'a'.repeat(40),images:[`registry.test/app@sha256:${'b'.repeat(64)}`],previewUrl:'https://preview.test'});
test('actual broker-shaped genesis passes; passed health cannot replace absent capture',()=>{
  assert.equal(validatedVerification(value(),'app1',context).migrationSnapshot?.dataPreservation,'no_previous_release');
  assert.throws(()=>validatedVerification({...value(),migrationSnapshot:undefined},'app1',context),/capture/);
  assert.throws(()=>validatedVerification(value(),'app1'),/capture/);
  for(const change of [{fence:3},{baseReleaseId:'other'},{filesHash:'b'.repeat(64)}]) assert.throws(()=>validatedVerification(value(),'app1',{...context,...change}));
});
test('valid capture cannot finish after lease, fence, base or cancellation changes during verification',async()=>{
  const root=await mkdtemp(join(tmpdir(),'autosoft-capture-fence-'));
  try {for(const drift of ['lease','fence','base','cancelled']) {
    const store=new JsonStore();const now=new Date().toISOString();const app:AppRecord={id:'app1',name:'App',slug:'app',description:'',kind:'web',status:'draft',activeReleaseId:null,url:null,previewUrl:null,createdAt:now,updatedAt:now};const job:JobRecord={id:`job_${drift}`,appId:app.id,request:'Create records',stage:'queued',baseReleaseId:null,costUsd:0,budgetUsd:1,attempts:0,createdAt:now,updatedAt:now};
    await store.transaction(state=>{state.apps[app.id]=app;state.jobs[job.id]=job;});let verified=false;
    const engine=new WorkflowEngine(store,{planAndGenerate:async()=>({specification:{},files:[{path:'src/main.ts',content:'export const ready=true;'}],pipeline:boundPipeline,summary:'fixture'}),verify:async input=>{
      const receipt=snapshotFixture();receipt.binding={...receipt.binding,appId:app.id,jobId:job.id,attemptId:input.attemptId,fence:input.job.runtimeFence!};receipt.requestHash=hashArtifact(receipt.binding);
      const proof={...value(),attemptId:input.attemptId,filesHash:input.filesHash,inputSourceHash:input.filesHash,migrationSnapshot:receipt};
      assert.equal(validatedVerification(proof,app.id,{...context,jobId:job.id,attemptId:input.attemptId,fence:input.job.runtimeFence!,filesHash:input.filesHash}).migrationSnapshot?.status,'no_previous_release');verified=true;
      await store.transaction(state=>{if(drift==='lease') state.leases[job.id]!.until=new Date(Date.now()-1).toISOString();if(drift==='fence') state.apps[app.id]!.runtimeFence!++;if(drift==='base') state.apps[app.id]!.activeReleaseId='foreign_release';if(drift==='cancelled') state.jobs[job.id]!.stage='cancelled';});
      return proof;
    }},new BudgetManager(store,1,5),root);
    await engine.run(job.id);assert.equal(verified,true,drift);assert.equal(await store.read(state=>Object.keys(state.releases).length),0,drift);assert.equal(await store.read(state=>state.apps[app.id]?.previewUrl),null,drift);
  }}finally{await rm(root,{recursive:true,force:true});}
});
test('captured pending migrations and fabricated epoch advancement never create ready releases',()=>{
  const r=snapshotFixture('release1');const migration={id:'add1',destructive:false,impact:'Add field',checksum:'d'.repeat(64)};r.binding.migrationSetHash=hashArtifact([{id:migration.id,checksum:migration.checksum}]);r.requestHash=hashArtifact(r.binding);
  const pending={...r,unappliedMigrationIds:['add1'],reason:'migration_contract_required'};
  assert.throws(()=>validatedVerification({...value(),migrationSnapshot:pending,migrations:[migration]},'app1',{...context,baseReleaseId:'release1',baseArtifactHash:r.binding.baseArtifactHash,baseImage:r.binding.baseImage}),/compatibility/);
  assert.throws(()=>validatedVerification({...value(),schemaVersion:2},'app1',context),/compatibility/);
});
