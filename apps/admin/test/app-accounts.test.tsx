import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { appAccountArtifactHash, type AppAccountApproval, type AppAccountSnapshot } from '../../../packages/core/src/app-accounts.ts';
import type { AppAccessSnapshot } from '../../../packages/core/src/access.ts';
import AppAccounts, { AccountOutcomeUncertain, accountReviewHash, accountStateBlocks, canClearAccountAttention, canDisableAppAccount, performAccountDisable, validateAccountReview, validateAccountState, type AcceptedAccount } from '../src/components/AppAccounts';
import type { Principal } from '../src/types';
import { accountFixture } from '../../control/test/app-account-fixture.ts';

const appId='11111111-1111-4111-8111-111111111111', releaseId='22222222-2222-4222-8222-222222222222', invitationId='33333333-3333-4333-8333-333333333333', userId='44444444-4444-4444-8444-444444444444', creationOperationId='55555555-5555-4555-8555-555555555555', approvalId='66666666-6666-4666-8666-666666666666', operationId='77777777-7777-4777-8777-777777777777';
const at=Date.now(), iso=(delta=0)=>new Date(at+delta).toISOString();
const owner:Principal={id:'owner',name:'Owner',localOwner:true,mfa:true,roles:['platform_owner']};
const snapshot:AppAccessSnapshot={appId,releaseId,identityHash:'a'.repeat(64),policyHash:'b'.repeat(64),permissions:['dms.read'],checkedAt:iso(),policy:{schemaVersion:1,appId,invitationsEnabled:true,requireTotp:true,roles:[],groupMappings:[]}};
const account:AcceptedAccount={id:invitationId,appId,email:'reader@example.test',status:'accepted',userId,operationId:creationOperationId};
const evidence:AppAccountSnapshot={schemaVersion:1,appId,invitationId,userId,creationOperationId,releaseId,identityHash:snapshot.identityHash,policyHash:snapshot.policyHash,realm:'app-'+'c'.repeat(24),clientId:'client-app',username:account.email,email:account.email,enabled:true,userEvidenceHash:'d'.repeat(64),tokenPolicyHash:'e'.repeat(64),accessTokenLifespanSeconds:1200,checkedAt:iso()};
const review=():AppAccountApproval=>({id:approvalId,appId,action:'disable_app_account',artifactHash:appAccountArtifactHash(evidence),snapshot:structuredClone(evidence),impact:['Disable exact local user. Preserve business data. Current limit 1200 seconds; issued tokens keep their own expiry.'],createdAt:iso(),expiresAt:iso(300000),approvedBy:null,approvedAt:null,consumedAt:null});
const operation=(approval:AppAccountApproval,status='disabled')=>({operationId,approvalId:approval.id,appId,invitationId,userId,artifactHash:approval.artifactHash,status,createdAt:iso(),checkedAt:iso(),detail:'Exact account/session state confirmed.'});

test('browser recomputes an actual control HTTP review and rejects altered target/lifespan',async()=>{
 const f=await accountFixture();try {const actual=await f.review(); const policy={...snapshot,appId:f.appId,releaseId:f.releaseId,identityHash:f.evidence().identityHash,policyHash:f.evidence().policyHash}; const accepted={...account,id:f.invitationId,appId:f.appId,userId:f.userId,operationId:f.creationOperationId};
  assert.equal((await validateAccountReview(actual,policy,accepted)).artifactHash,actual.artifactHash);assert.equal(await accountReviewHash(actual.snapshot),actual.artifactHash);
  await assert.rejects(validateAccountReview({...actual,snapshot:{...actual.snapshot,accessTokenLifespanSeconds:300}},policy,accepted));await assert.rejects(validateAccountReview(actual,policy,{...accepted,userId}));
 }finally{await f.close()}
});
test('single owner approval and disable dispatch use exact artifact and original account; no secret input',async()=>{
 const original=review(),calls:{path:string;body:unknown}[]=[];
 const result=await performAccountDisable(original,snapshot,account,owner,async<T,>(path:string,options?:{method?:string;body?:unknown;signal?:AbortSignal})=>{calls.push({path,body:options?.body});return (path.includes('/approve')?{approval:{...original,approvedBy:owner.id,approvedAt:iso()}}:{operation:operation(original)})as T},()=>at);
 assert.equal(result.status,'disabled');assert.deepEqual(calls,[{path:`/account-approvals/${approvalId}/approve`,body:{artifactHash:original.artifactHash}},{path:`/apps/${appId}/accounts/disable`,body:{approvalId}}]);assert.doesNotMatch(JSON.stringify(calls),/password|secret|tokenHash/);
});
test('foreign target, changed policy, no MFA/nonowner and expired review perform zero calls',async()=>{
 for(const kind of ['foreign','policy','mfa','owner','expired']){let calls=0;const approval=review(); if(kind==='expired')approval.expiresAt=iso(-1);
 await assert.rejects(performAccountDisable(approval,kind==='policy'?{...snapshot,policyHash:'f'.repeat(64)}:snapshot,kind==='foreign'?{...account,userId:creationOperationId}:account,kind==='mfa'?{...owner,mfa:false}:kind==='owner'?{...owner,localOwner:false}:owner,async<T,>()=>{calls++;return{}as T},()=>at));assert.equal(calls,0)}
});
test('lost approval response prevents disable; lost disable response retains original identity without retry',async()=>{
 for(const phase of ['approval','disable']){let calls=0;const approval=review();await assert.rejects(performAccountDisable(approval,snapshot,account,owner,async<T,>()=>{calls++;if(phase==='approval'||calls===2)throw new Error('private transport error');return{approval:{...approval,approvedBy:owner.id,approvedAt:iso()}}as T},()=>at),error=>error instanceof AccountOutcomeUncertain&&error.approval.id===approvalId);assert.equal(calls,phase==='approval'?1:2)}
});
test('view closing after confirmed approval prevents activation and keeps uncertainty inspectable',async()=>{
 const controller=new AbortController(),approval=review();let calls=0;await assert.rejects(performAccountDisable(approval,snapshot,account,owner,async<T,>()=>{calls++;controller.abort();return{approval:{...approval,approvedBy:owner.id,approvedAt:iso()}}as T},()=>at,controller.signal),AccountOutcomeUncertain);assert.equal(calls,1);
});
test('retained state binds consumed approval and only one original operation; pending and disabled block new dispatch',async()=>{
 const a={...review(),approvedBy:owner.id,approvedAt:iso(),consumedAt:iso()},op=operation(a);const state=await validateAccountState({approvals:[a],operations:[op]},appId);assert.equal(accountStateBlocks(state,userId),true);
 await assert.rejects(validateAccountState({approvals:[a],operations:[{...op,userId:creationOperationId}]},appId));await assert.rejects(validateAccountState({approvals:[{...a,consumedAt:null}],operations:[op]},appId));await assert.rejects(validateAccountState({approvals:[a],operations:[op,{...op,operationId:creationOperationId}]},appId));
 assert.equal(accountStateBlocks(await validateAccountState({approvals:[a],operations:[{...op,status:'failed'}]},appId),userId),false);
});
test('malformed token/user snapshot types and rehashed unknown fields never become browser approvals',async()=>{
 for(const delta of [{accessTokenLifespanSeconds:true},{accessTokenLifespanSeconds:0},{enabled:false},{federatedUser:true},{tokenPolicyHash:'invalid'}]){const a=review(),changed={...a.snapshot,...delta}as AppAccountSnapshot;a.snapshot=changed;a.artifactHash=appAccountArtifactHash(changed);await assert.rejects(validateAccountReview(a,snapshot,account,at))}
});
test('uncertain reviews clear only after exact retained operation or a post-expiry inspection',async()=>{
 const a=review(), state=await validateAccountState({approvals:[a],operations:[]},appId);
 assert.equal(canClearAccountAttention(state,a,at),false);assert.equal(canClearAccountAttention(state,a,at+300001),true);assert.equal(canClearAccountAttention(state,{...a,artifactHash:'f'.repeat(64)},at+300001),false);assert.equal(canClearAccountAttention(state,a,NaN),false);
 const consumed={...a,approvedBy:owner.id,approvedAt:iso(),consumedAt:iso()},op=operation(a,'pending'),confirmed=await validateAccountState({approvals:[consumed],operations:[op]},appId);
 assert.equal(canClearAccountAttention(confirmed,a,at),true);assert.equal(accountStateBlocks(confirmed,userId),true);
});
test('inconsistent approval timestamps and stale disabled readbacks cannot become current browser evidence',async()=>{
 const a={...review(),approvedBy:owner.id,approvedAt:iso(),consumedAt:iso()},op=operation(a);
 for(const approval of [{...a,approvedAt:iso(-1)},{...a,consumedAt:a.expiresAt}])await assert.rejects(validateAccountState({approvals:[approval],operations:[op]},appId));
 for(const checkedAt of [null,iso(-60001),iso(20000)])await assert.rejects(validateAccountState({approvals:[a],operations:[{...op,checkedAt}]},appId));
});
test('render limits account disablement to owner/MFA and states retention; initial unavailable state has disabled controls',()=>{
 const html=renderToStaticMarkup(createElement(AppAccounts,{snapshot,accounts:[account],principal:{...owner,localOwner:false},ready:true}));assert.match(html,/Only the permanent local owner with MFA/);assert.match(html,/Records and business data stay intact/);assert.match(html,/disabled=""[^>]*>Review account disablement/);assert.doesNotMatch(html,/type="password"|Approve and disable this account/);assert.equal(canDisableAppAccount({...owner,mfa:false}),false);
});
