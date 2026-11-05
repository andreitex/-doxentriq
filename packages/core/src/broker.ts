import { createHmac } from 'node:crypto';
import type { AppRecord, ApprovalRecord, Evidence, ReleaseRecord,Principal,Finding,RecoveryGrant,ReleaseObservationRequest,ReleaseObservation } from './types.js';
import type { Pipeline } from './schemas.js';
import type { MigrationSnapshotRequest,MigrationSnapshotReceipt } from './migration-snapshot.js';
import { sourceBindingVersion, pipelineDefinitionHash } from './source-hash.js';

async function receipt(response: Response, maximum: number): Promise<Record<string, unknown>> {
  const declared = response.headers.get('content-length');
  if (!response.body || declared !== null && (!/^[0-9]{1,12}$/.test(declared) || Number(declared) > maximum)) {
    await response.body?.cancel().catch(() => {});
    throw new Error('Trusted runtime receipt is unavailable or exceeds its byte limit; retain the operation for reconciliation.');
  }
  const reader = response.body.getReader(), chunks: Uint8Array[] = []; let bytes = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > maximum) {
        await reader.cancel().catch(() => {});
        throw new Error('Trusted runtime receipt exceeds its byte limit; retain the operation for reconciliation.');
      }
      chunks.push(part.value);
    }
    if (declared !== null && bytes !== Number(declared)) throw new Error('Incomplete receipt');
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('Invalid receipt');
    return value as Record<string, unknown>;
  } catch {
    await reader.cancel().catch(() => {});
    throw new Error('Trusted runtime receipt is unavailable, malformed or exceeds its byte limit; retain the operation for reconciliation.');
  } finally { reader.releaseLock(); }
}

export class BrokerClient {
  constructor(private readonly config:{url:string;token:string;approvalKey:Buffer|string;fetch?:typeof fetch}){
    let url:URL;
    try { url=new URL(config.url); } catch { throw new Error('Deployment broker requires an exact trusted HTTPS origin or loopback development.'); }
    if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(url.hostname)))throw new Error('Deployment broker requires an exact trusted HTTPS origin or loopback development.');
  }
  private async call<T>(route:string,value:unknown,sign=false):Promise<T>{
    const body=JSON.stringify(value),key=typeof this.config.approvalKey==='string'?Buffer.from(this.config.approvalKey,'base64'):this.config.approvalKey;
    if(sign&&key.length!==32)throw new Error('Publication proof key must contain 32 bytes');
    let result:Response;
    try { result=await (this.config.fetch??fetch)(new URL(route,this.config.url),{method:'POST',redirect:'error',headers:{'content-type':'application/json',authorization:`Bearer ${this.config.token}`,...(sign?{'x-autosoft-proof':createHmac('sha256',key).update(body).digest('hex')}: {})},body,signal:AbortSignal.timeout(route==='/v1/verify'?3600000:300000)}); }
    catch { throw new Error('Trusted runtime request outcome is unavailable; retain the operation for reconciliation.'); }
    const received=await receipt(result,result.status!==200?65536:route==='/v1/source'?128*1024**2:8*1024**2);
    if(result.status!==200)throw Object.assign(new Error(`Trusted runtime rejected or deferred the operation (HTTP ${result.status}); retain its exact operation for reconciliation.`),{confirmedRejected:!result.ok&&received.rejectedBeforeExecution===true});
    return received as T;
  }
  verify(input:{app:AppRecord;job:{id:string;runtimeFence?:number;baseReleaseId?:string|null};attemptId:string;workspacePath:string;pipeline:unknown;filesHash:string}):Promise<{evidence:Evidence;images:string[];commit:string;previewUrl:string|null;schemaVersion:number;compatibleSchemaMin:number;compatibleSchemaMax:number;migrations:ReleaseRecord['migrations'];migrationSnapshot?:MigrationSnapshotReceipt}>{
    if(!Number.isSafeInteger(input.job.runtimeFence)||input.job.runtimeFence!<1)throw new Error('A durable worker fence is required for verification');
    pipelineDefinitionHash(input.pipeline);
    return this.call('/v1/verify',{appId:input.app.id,jobId:input.job.id,attemptId:input.attemptId,fence:input.job.runtimeFence,baseReleaseId:input.job.baseReleaseId??null,pipeline:input.pipeline as Pipeline,filesHash:input.filesHash,sourceBindingVersion});
  }
  migrationSnapshot(input:MigrationSnapshotRequest):Promise<MigrationSnapshotReceipt>{return this.call('/v1/migrations/snapshot',input,true);}
  migrationSnapshotStatus(input:MigrationSnapshotRequest):Promise<MigrationSnapshotReceipt>{return this.call('/v1/migrations/snapshot-status',input,true);}
  deploy(input:{app:AppRecord;release:ReleaseRecord;approval:ApprovalRecord;operationId:string;action:'publish'|'rollback'|'emergency_rollback';principal?:Principal;approvedFindings?:Finding[];recoveryGrant?:RecoveryGrant}):Promise<{url:string;healthy:boolean;schemaVersion?:number}>{
    return this.call('/v1/deploy',input,true);
  }
  telemetry():Promise<{services:Record<string,unknown>[];broker:Record<string,unknown>}>{return this.call('/v1/telemetry',{});}
  operation(input:{operationId:string}):Promise<{status:'running'|'succeeded'|'failed'|'unknown';url?:string;healthy?:boolean;schemaVersion?:number;appId?:string;releaseId?:string}>{return this.call('/v1/operation',input);}
  cancelOperation(input:{operationId:string;appId:string;releaseId:string;approvalId:string;artifactHash:string}):Promise<{status:'failed'|'running'|'unknown';appId?:string;releaseId?:string}>{return this.call('/v1/cancel-operation',input,true);}
  source(input:{appId:string;commit:string}):Promise<{files:{path:string;content:string}[]}>{return this.call('/v1/source',input);}
  observe(input:ReleaseObservationRequest):Promise<ReleaseObservation>{return this.call('/v1/observe',input);}
  recover(input:{operationId:string;app:AppRecord;release:ReleaseRecord;grant:RecoveryGrant;observationIds:string[];evidenceHashes:string[]}):Promise<{url:string;healthy:boolean;schemaVersion?:number}>{return this.call('/v1/recover',input,true);}
  publishedCatalog():Promise<{apps:{appId:string;releaseId:string;artifactHash:string;images:string[];auth:'public'|'local'|'sso'}[]}>{return this.call('/v1/public-catalog',{includeProtected:true});}
  publicCatalog():Promise<{apps:{appId:string;releaseId:string;artifactHash:string;images:string[];auth:'public'}[]}>{return this.call('/v1/public-catalog',{});}
}
