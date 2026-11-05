import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AppRecord, ReleaseRecord } from '../../../packages/core/src/types.ts';
import type { AppAccessPolicy, AppAccessSnapshot, AcceptInvitationRequest } from '../../../packages/core/src/access.ts';
import { accessPolicyHash, reconcileAccessOperations } from '../src/access.ts';
import { createServer } from '../src/server.ts';
import { JsonStore } from '../src/store.ts';
import type { Config } from '../src/config.ts';
import type { EngineDependencies } from '../src/engine.ts';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-access-')), file = join(root, 'state.json'), store = new JsonStore(file); await store.initialize(); const id = randomUUID(), releaseId = randomUUID(), now = new Date().toISOString(), roleId = randomUUID();
  const app: AppRecord = { id, slug: 'documents', name: 'Documents', kind: 'web', description: '', activeReleaseId: releaseId, status: 'published', url: null, previewUrl: null, createdAt: now, updatedAt: now };
  const policy: AppAccessPolicy = { schemaVersion: 1, appId: id, invitationsEnabled: true, requireTotp: true, roles: [{ id: roleId, name: 'Readers', permissions: ['dms.read'] }], groupMappings: [] };
  let snapshot: AppAccessSnapshot = { appId: id, releaseId, identityHash: 'a'.repeat(64), policyHash: accessPolicyHash(policy), permissions: ['dms.read', 'dms.write'], policy, checkedAt: now }, calls = 0, pending = false, received: AcceptInvitationRequest | undefined;
  await store.transaction(state => { state.apps[id] = app; state.releases[releaseId] = { id: releaseId, appId: id } as ReleaseRecord; });
  const dependencies: EngineDependencies = { accessSnapshot: async () => ({ ...snapshot, checkedAt: new Date().toISOString() }), applyAccessPolicy: async input => { snapshot = { ...snapshot, policy: input.policy, policyHash: accessPolicyHash(input.policy) }; return { operationId: input.operationId, appId: id, status: 'succeeded', action: 'access_policy', artifactHash: input.approval.artifactHash, policyHash: snapshot.policyHash }; }, acceptAppInvitation: async input => { calls++; received = structuredClone(input); if (pending) throw new Error('uncertain fixture identity write'); return { operationId: input.operationId, appId: id, status: 'succeeded', action: 'invitation', artifactHash: input.approval.artifactHash, invitationId: input.invitation.id, userId: randomUUID() }; }, accessOperation: async input => ({ operationId: input.operationId, appId: id, status: 'running', action: 'invitation', artifactHash: received!.approval.artifactHash }) };
  const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', appsOrigin: 'https://apps.example.test', dataDir: root, workspaceDir: join(root, 'workspaces'), adminDist: join(root, 'no-build'), oidcClientId: 'test', secretKey: Buffer.alloc(32, 5), requestLimitUsd: 1, monthlyLimitUsd: 5 };
  const server = await createServer(config, store, dependencies), session = await server.inject({ method: 'GET', url: '/api/v1/session' }); const cookie = session.cookies[0]!;
  const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string }, publicHeaders = { host: 'apps.example.test', origin: config.appsOrigin! };
  async function post(path: string, payload: Record<string, unknown>, customHeaders: Record<string, string> = headers) { return server.inject({ method: 'POST', url: path, headers: customHeaders, payload }); }
  async function issue() { const draft = await post(`/api/v1/apps/${id}/access/invitation-approval`, { email: 'reader@example.test', roleIds: [roleId] }); assert.equal(draft.statusCode, 200, draft.body); const approval = draft.json().approval; const approved = await post(`/api/v1/access/approvals/${approval.id}/approve`, { artifactHash: approval.artifactHash }); assert.equal(approved.statusCode, 200, approved.body); const issued = await post(`/api/v1/apps/${id}/access/invitations`, { approvalId: approval.id }); assert.equal(issued.statusCode, 200, issued.body); return { token: new URL(issued.json().link).hash.slice(1), invitation: issued.json().invitation, approval }; }
  return { root, file, store, server, app, policy, roleId, headers, publicHeaders, dependencies, post, issue, calls: () => calls, setPending: () => { pending = true; }, snapshot: () => snapshot, changeSnapshot: (value: AppAccessSnapshot) => { snapshot = value; }, close: async () => { await server.close(); await store.close(); await rm(root, { recursive: true, force: true }); } };
}
test('exact approved app role changes are independent from release approvals and cannot grant foreign permissions', async () => {
  const f = await fixture(); try {
    const path = `/api/v1/apps/${f.app.id}/access/policy-approval`, base = { basePolicyHash: f.snapshot().policyHash, invitationsEnabled: true, roles: [{ id: f.roleId, name: 'Editors', permissions: ['dms.read', 'dms.write'] }] };
    assert.equal((await f.post(path, { ...base, roles: [{ ...base.roles[0], permissions: ['platform-owner'] }] })).statusCode, 400);
    const prepared = await f.post(path, base); assert.equal(prepared.statusCode, 200, prepared.body); const approval = prepared.json().approval;
    assert.equal((await f.post(`/api/v1/apps/${f.app.id}/access/apply`, { approvalId: approval.id })).statusCode, 409);
    assert.equal((await f.post(`/api/v1/access/approvals/${approval.id}/approve`, { artifactHash: 'f'.repeat(64) })).statusCode, 409);
    assert.equal((await f.post(`/api/v1/access/approvals/${approval.id}/approve`, { artifactHash: approval.artifactHash })).statusCode, 200);
    const result = await f.post(`/api/v1/apps/${f.app.id}/access/apply`, { approvalId: approval.id }); assert.equal(result.statusCode, 200, result.body); assert.equal(result.json().operation.status, 'succeeded'); assert.deepEqual(f.snapshot().policy.roles[0]!.permissions, ['dms.read', 'dms.write']); assert.equal(await f.store.read(state => Object.keys(state.approvals).length), 0);
    assert.equal((await f.post(`/api/v1/apps/${f.app.id}/access/apply`, { approvalId: approval.id })).statusCode, 409);
  } finally { await f.close(); }
});
test('invitation form is anonymous host/origin bound; successful one-use account setup never persists credentials', async () => {
  const f = await fixture(); try { const { token, invitation } = await f.issue(), sessions = await f.store.read(state => Object.keys(state.sessions).length);
    const inspectPath = '/api/public/v1/invitations/inspect';
    assert.equal((await f.post(inspectPath, { token }, { ...f.publicHeaders, host: 'admin.example.test' })).statusCode, 404);
    assert.equal((await f.post(inspectPath, { token }, { ...f.publicHeaders, origin: 'https://evil.example.test' })).statusCode, 403);
    const inspected = await f.post(inspectPath, { token }, { ...f.publicHeaders, cookie: 'autosoft_session=forged', authorization: 'Bearer forged' }); assert.equal(inspected.statusCode, 200, inspected.body); assert.equal(inspected.cookies.length, 0); assert.equal(await f.store.read(state => Object.keys(state.sessions).length), sessions); assert.equal(inspected.json().emailVerified, false); assert.equal(inspected.json().requireTotp, true); assert.deepEqual(inspected.json().roles, [{ name: 'Readers', permissions: ['dms.read'] }]);
    const password = 'Synthetic-Password-17!'; const results = await Promise.all([f.post('/api/public/v1/invitations/accept', { token, password }, f.publicHeaders), f.post('/api/public/v1/invitations/accept', { token, password: 'Another-Synthetic-Password!' }, f.publicHeaders)]); assert.equal(f.calls(), 1); assert.ok(results.some(result => result.statusCode === 200 && result.json().status === 'accepted')); assert.ok(results.every(result => [200, 202, 409, 410].includes(result.statusCode))); const record = await f.store.read(state => state.invitations[invitation.id]!); assert.equal(record.status, 'accepted'); assert.ok(record.userId);
    const persisted = await readFile(f.file, 'utf8'); assert.ok(!persisted.includes(password)); assert.ok(!persisted.includes(token)); assert.equal((await f.post('/api/public/v1/invitations/accept', { token, password }, f.publicHeaders)).statusCode, 410);
  } finally { await f.close(); }
});
test('uncertain invitation writes survive restart and reconcile without retrying a password or account creation', async () => {
  const f = await fixture(); try { f.setPending(); const { token, invitation } = await f.issue(), password = 'Synthetic-Uncertain-Password!';
    const response = await f.post('/api/public/v1/invitations/accept', { token, password }, f.publicHeaders); assert.equal(response.statusCode, 202, response.body); assert.equal(f.calls(), 1);
    const restarted = new JsonStore(f.file); await restarted.initialize(); const original = await restarted.read(state => Object.values(state.accessOperations)[0]!); assert.equal('password' in original.request, false); assert.equal((await restarted.read(state => state.invitations[invitation.id]!)).status, 'accepting');
    await reconcileAccessOperations(restarted, f.dependencies); assert.equal(f.calls(), 1); assert.equal((await restarted.read(state => state.accessOperations[original.id]!)).status, 'running');
    assert.equal((await f.post('/api/public/v1/invitations/accept', { token, password: 'Different-Password-Never-Replayed!' }, f.publicHeaders)).statusCode, 202); assert.equal(f.calls(), 1); await restarted.close();
  } finally { await f.close(); }
});
test('stale policy approvals, changed invitation policy, expired and revoked tokens fail closed', async () => {
  const f = await fixture(); try { const first = await f.issue(); const revoked = await f.post(`/api/v1/apps/${f.app.id}/access/invitations/${first.invitation.id}/revoke`, {}); assert.equal(revoked.statusCode, 200); assert.equal((await f.post('/api/public/v1/invitations/inspect', { token: first.token }, f.publicHeaders)).statusCode, 410);
    const expired = await f.issue(); await f.store.transaction(state => { state.invitations[expired.invitation.id]!.expiresAt = new Date(Date.now() - 1000).toISOString(); }); assert.equal((await f.post('/api/public/v1/invitations/inspect', { token: expired.token }, f.publicHeaders)).statusCode, 410);
    const second = await f.issue(); const changed = { ...f.snapshot().policy, invitationsEnabled: false }; f.changeSnapshot({ ...f.snapshot(), policy: changed, policyHash: accessPolicyHash(changed) }); assert.equal((await f.post('/api/public/v1/invitations/accept', { token: second.token, password: 'Never-Used-Password!' }, f.publicHeaders)).statusCode, 410); assert.equal(f.calls(), 0);
    const current = { ...f.policy, roles: [{ id: f.roleId, name: 'Writers', permissions: ['dms.write'] }] }; f.changeSnapshot({ ...f.snapshot(), policy: current, policyHash: accessPolicyHash(current) });
    const prepared = await f.post(`/api/v1/apps/${f.app.id}/access/policy-approval`, { basePolicyHash: f.snapshot().policyHash, invitationsEnabled: true, roles: current.roles }); const approval = prepared.json().approval; f.changeSnapshot({ ...f.snapshot(), policy: f.policy, policyHash: accessPolicyHash(f.policy) }); assert.equal((await f.post(`/api/v1/access/approvals/${approval.id}/approve`, { artifactHash: approval.artifactHash })).statusCode, 409);
  } finally { await f.close(); }
});
test('malformed/cross-app identity evidence and live-role changes never become access success', async () => {
  const f = await fixture(); try { f.changeSnapshot({ ...f.snapshot(), appId: randomUUID() }); assert.equal((await f.server.inject({ url: `/api/v1/apps/${f.app.id}/access`, headers: f.headers })).statusCode, 503); assert.equal((await f.post(`/api/v1/apps/${f.app.id}/access/invitation-approval`, { email: 'owner@example.test', roleIds: [f.roleId] })).statusCode, 503); assert.equal(f.calls(), 0); assert.equal(await f.store.read(state => Object.keys(state.accessApprovals).length), 0); }
  finally { await f.close(); }
});
