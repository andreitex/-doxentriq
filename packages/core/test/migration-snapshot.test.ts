import { test } from 'node:test';
import assert from 'node:assert/strict';
import { snapshotFixture } from './migration-snapshot-fixture.ts';
import { BrokerClient } from '../src/broker.ts';
import { hashArtifact, releaseArtifactHash } from '../src/security.ts';
import { migrationSetHash,migrationSnapshotSchema,validatedMigrationSnapshot,type MigrationSnapshotRequest } from '../src/migration-snapshot.ts';
import type { ReleaseRecord } from '../src/types.ts';

test('capture validates exact context without certifying preserved records or compatibility',()=>{
  for(const base of [null,'release1']) { const receipt=snapshotFixture(base);const expected={appId:'app1',jobId:'job1',attemptId:'attempt1',fence:2,baseReleaseId:base,baseArtifactHash:receipt.binding.baseArtifactHash,baseImage:receipt.binding.baseImage,sourceHash:'c'.repeat(64),migrations:[]};assert.deepEqual(validatedMigrationSnapshot(receipt,expected),receipt);
    for(const change of [{appId:'app2'},{jobId:'job2'},{attemptId:'attempt2'},{fence:3},{baseReleaseId:'other'},{baseArtifactHash:'e'.repeat(64)},{baseImage:`registry.test/foreign@sha256:${'e'.repeat(64)}`},{sourceHash:'a'.repeat(64)},{migrations:[{id:'m1',checksum:'a'.repeat(64)}]}]) assert.throws(()=>validatedMigrationSnapshot(receipt,{...expected,...change}));
    assert.throws(()=>validatedMigrationSnapshot({...receipt,checkedAt:new Date(Date.now()-86400001).toISOString()},expected));
  }
});
test('contradictory eligibility, fake genesis, bad hash and overlimits reject',()=>{
  const captured=snapshotFixture('release1');
  for(const change of [{publicationEligible:true},{dataPreservation:'preserved'},{previousReleaseCompatibility:'passed'},{requestHash:'0'.repeat(64)},{status:'no_previous_release'},{byteCount:0},{tableCount:65},{rowCount:100001},{byteCount:268435457},{unappliedMigrationIds:['m1']},{unexpected:'raw-business-data'}]) assert.equal(migrationSnapshotSchema.safeParse({...captured,...change}).success,false);
  assert.equal(migrationSnapshotSchema.safeParse({...captured,unappliedMigrationIds:['m1'],reason:'migration_contract_required'}).success,true);
});
test('Go/TypeScript golden context hash binds null and ordered migration metadata',()=>{
  const fixture=snapshotFixture();assert.equal(fixture.requestHash,'dada73995c93f5d3c9ee42340a5f56b0af2b5b40b1c7f1583fd1ec7853d2143a');
  const migrations=[{id:'add_a',checksum:'a'.repeat(64)},{id:'add_b',checksum:'b'.repeat(64)}];assert.equal(migrationSetHash(migrations),'3b51ff005b9cd381eeba647dcfc5a39975601f94f2b58fd27e105a8ccfcfc400');
  const request:MigrationSnapshotRequest={...fixture.binding,baseReleaseId:'release1',baseArtifactHash:'d'.repeat(64),baseImage:`registry.test/app@sha256:${'e'.repeat(64)}`,migrationSetHash:migrationSetHash(migrations)};assert.equal(hashArtifact(request),'f177aa42aed8096812b190c02b163f5ae2bd5ba66f0978e49bbf3c076eeb4e55');
  assert.notEqual(migrationSetHash([{id:'a',checksum:'a'.repeat(64)},{id:'b',checksum:'b'.repeat(64)}]),migrationSetHash([{id:'b',checksum:'b'.repeat(64)},{id:'a',checksum:'a'.repeat(64)}]));
});
test('historical artifacts retain their old projection unless capture is explicitly present',()=>{
  const release={appId:'app1',commit:'a'.repeat(40),images:[`registry.test/app@sha256:${'b'.repeat(64)}`],schemaVersion:1,compatibleSchemaMin:1,compatibleSchemaMax:1,migrations:[],baseReleaseId:null,summary:'Historical',evidence:{status:'passed',checkedAt:'2026-01-01T00:00:00Z',feedUpdatedAt:'2026-01-01T00:00:00Z',findings:[],checks:[]}} as unknown as ReleaseRecord;
  const old=hashArtifact({appId:release.appId,commit:release.commit,images:release.images,schemaVersion:release.schemaVersion,compatibleSchemaMin:release.compatibleSchemaMin,compatibleSchemaMax:release.compatibleSchemaMax,migrations:release.migrations,baseReleaseId:release.baseReleaseId,summary:release.summary,evidence:release.evidence});
  assert.equal(releaseArtifactHash(release),old);assert.equal(releaseArtifactHash({...release,migrationSnapshot:undefined}),old);assert.notEqual(releaseArtifactHash({...release,migrationSnapshot:snapshotFixture()}),old);
});
test('capture and readback are signed POSTs to fixed broker routes with no raw rows',async()=>{
  const calls:{url:string;body:any;proof:string}[]=[];const value=snapshotFixture();const client=new BrokerClient({url:'https://broker.test',token:'trusted',approvalKey:Buffer.alloc(32,4),fetch:async(url,options)=>{assert.equal(options?.redirect,'error');calls.push({url:String(url),body:JSON.parse(String(options?.body)),proof:String((options?.headers as Record<string,string>)['x-autosoft-proof'])});return Response.json(value);}});
  await client.migrationSnapshot(value.binding);await client.migrationSnapshotStatus(value.binding);assert.deepEqual(calls.map(c=>new URL(c.url).pathname),['/v1/migrations/snapshot','/v1/migrations/snapshot-status']);assert.ok(calls.every(c=>c.proof.length===64));assert.deepEqual(calls[0]?.body,value.binding);
});
