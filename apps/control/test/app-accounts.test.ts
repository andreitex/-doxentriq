import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { AppInvitation, AcceptInvitationRequest } from '../../../packages/core/src/access.ts';
import { appAccountArtifactHash, type AppAccountSnapshot, type DisableAppAccountRequest, type AppAccountStatus } from '../../../packages/core/src/app-accounts.ts';
import type { AppRecord, ReleaseRecord } from '../../../packages/core/src/types.ts';
import { JsonStore } from '../src/store.ts';
import { createServer } from '../src/server.ts';
import type { Config } from '../src/config.ts';
import type { EngineDependencies } from '../src/engine.ts';

import { accountFixture } from './app-account-fixture.ts';

test('exact owner-reviewed account disable binds measured lifespan and preserves invitation/data', async () => {
  const f = await accountFixture(); try { const before = await f.store.read(s => ({ invitation: s.invitations[f.invitationId], release: s.releases[f.releaseId] })), review = await f.review(); assert.equal(review.artifactHash, appAccountArtifactHash(f.evidence())); assert.match(review.impact.join(' '), /1200 seconds/); assert.match(review.impact.join(' '), /older configuration/);
    assert.equal((await f.post(`/api/v1/apps/${f.appId}/accounts/disable`, { approvalId: review.id })).statusCode, 409);
    assert.equal((await f.post(`/api/v1/account-approvals/${review.id}/approve`, { artifactHash: 'e'.repeat(64) })).statusCode, 409);
    assert.equal((await f.post(`/api/v1/account-approvals/${review.id}/approve`, { artifactHash: review.artifactHash })).statusCode, 200);
    const result = await f.post(`/api/v1/apps/${f.appId}/accounts/disable`, { approvalId: review.id }); assert.equal(result.statusCode, 200, result.body); assert.equal(result.json().operation.status, 'disabled'); assert.equal(f.calls(), 1); assert.equal(f.received()!.principal.localOwner, true);
    assert.equal((await f.post(`/api/v1/apps/${f.appId}/accounts/disable`, { approvalId: review.id })).statusCode, 409); assert.equal(f.calls(), 1);
    assert.deepEqual(await f.store.read(s => ({ invitation: s.invitations[f.invitationId], release: s.releases[f.releaseId] })), before);
  } finally { await f.close(); }
});
test('owner, MFA and current session are enforced before and after async evidence reads', async () => {
  for (const change of ['owner', 'mfa', 'expired-after-await']) { const f = await accountFixture(); try {
    const mutate = async () => f.store.transaction(s => { const session = s.sessions[f.sessionId]!; if (change === 'owner') session.principal.localOwner = false; else if (change === 'mfa') session.principal.mfa = false; else session.expiresAt = new Date(Date.now() - 1).toISOString(); });
    if (change === 'expired-after-await') { const original = f.dependencies.appAccountSnapshot!; f.dependencies.appAccountSnapshot = async input => { const value = await original(input); await mutate(); return value; }; } else await mutate();
    assert.equal((await f.post(`/api/v1/apps/${f.appId}/accounts/${f.invitationId}/disable-review`)).statusCode, 403); assert.equal(f.calls(), 0); assert.equal(await f.store.read(s => Object.keys(s.appAccountApprovals).length), 0);
  } finally { await f.close(); } }
});
test('changed user, publication, token settings, foreign invitations and expired reviews never dispatch', async () => {
  for (const kind of ['user', 'release', 'token', 'cross-app', 'expiry']) { const f = await accountFixture(); try { const review = await f.review();
    if (kind === 'user') f.change({ userEvidenceHash: 'd'.repeat(64) }); else if (kind === 'release') f.change({ releaseId: randomUUID() }); else if (kind === 'token') f.change({ tokenPolicyHash: 'e'.repeat(64), accessTokenLifespanSeconds: 300 }); else if (kind === 'cross-app') await f.store.transaction(s => { s.invitations[f.invitationId]!.appId = randomUUID(); }); else await f.store.transaction(s => { s.appAccountApprovals[review.id]!.expiresAt = new Date(Date.now() - 1).toISOString(); });
    const result = await f.post(`/api/v1/account-approvals/${review.id}/approve`, { artifactHash: review.artifactHash }); assert.ok([409,503].includes(result.statusCode), result.body); assert.equal(f.calls(), 0);
  } finally { await f.close(); } }
});
test('competing exact reviews consume one approval; unknown dispatch survives restart and only reads status', async () => {
  const f = await accountFixture(); try { const first = await f.review(), second = await f.review(); assert.equal((await f.post(`/api/v1/account-approvals/${first.id}/approve`, { artifactHash: first.artifactHash })).statusCode, 200); assert.equal((await f.post(`/api/v1/account-approvals/${second.id}/approve`, { artifactHash: second.artifactHash })).statusCode, 409);
    f.uncertain(); const result = await f.post(`/api/v1/apps/${f.appId}/accounts/disable`, { approvalId: first.id }); assert.equal(result.statusCode, 202); assert.equal(result.json().operation.status, 'pending'); assert.equal(f.calls(), 1);
    const persisted = await readFile(f.file, 'utf8'); assert.doesNotMatch(persisted, /synthetic-secret-do-not-persist/); const restored = new JsonStore(f.file); await restored.initialize(); const restarted = await createServer(f.config, restored, f.dependencies);
    try { const session = await restarted.inject({ url: '/api/v1/session' }), cookie = session.cookies[0]!, headers = { cookie: `${cookie.name}=${cookie.value}` }; let state = await restarted.inject({ url: `/api/v1/apps/${f.appId}/accounts`, headers }); assert.equal(state.json().operations[0].status, 'pending'); assert.equal(f.calls(), 1);
      f.setStatus('disabled'); state = await restarted.inject({ url: `/api/v1/apps/${f.appId}/accounts`, headers }); assert.equal(state.json().operations[0].status, 'disabled'); assert.equal(f.calls(), 1);
      f.setStatus('unknown'); state = await restarted.inject({ url: `/api/v1/apps/${f.appId}/accounts`, headers }); assert.equal(state.json().operations[0].status, 'pending'); assert.equal(f.calls(), 1);
    } finally { await restarted.close(); await restored.close(); }
  } finally { await f.close(); }
});
test('malformed snapshots and foreign operation readbacks are unavailable rather than success', async () => {
  const f = await accountFixture(); try { f.change({ accessTokenLifespanSeconds: -1 }); assert.equal((await f.post(`/api/v1/apps/${f.appId}/accounts/${f.invitationId}/disable-review`)).statusCode, 503); f.change({ accessTokenLifespanSeconds: 1200 }); const review = await f.review(); const approved = await f.post(`/api/v1/account-approvals/${review.id}/approve`, { artifactHash: review.artifactHash }); assert.equal(approved.statusCode, 200, approved.body);
    f.dependencies.disableAppAccount = async input => ({ operationId: input.operationId, approvalId: review.id, appId: randomUUID(), invitationId: f.invitationId, userId: f.userId, artifactHash: review.artifactHash, status: 'disabled', checkedAt: new Date().toISOString(), detail: 'Unrelated account.' }); const result = await f.post(`/api/v1/apps/${f.appId}/accounts/disable`, { approvalId: review.id }); assert.equal(result.statusCode, 202, result.body); assert.equal(result.json().operation.status, 'pending');
  } finally { await f.close(); }
});
test('one captured creation timestamp fixes the five-minute review interval even when a later clock read advances', async () => {
  const f = await accountFixture(), originalNow = Date.now;
  try {
    Date.now = () => originalNow() + 1000;
    const review = await f.review(); assert.equal(Date.parse(review.expiresAt) - Date.parse(review.createdAt), 300000);
    const approved = await f.post(`/api/v1/account-approvals/${review.id}/approve`, { artifactHash: review.artifactHash }); assert.equal(approved.statusCode, 200, approved.body);
    const disabled = await f.post(`/api/v1/apps/${f.appId}/accounts/disable`, { approvalId: review.id }); assert.equal(disabled.statusCode, 200, disabled.body); assert.equal(f.calls(), 1);
  } finally { Date.now = originalNow; await f.close(); }
});
