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

export async function accountFixture() {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-accounts-')), file = join(root, 'state.json'), store = new JsonStore(file); await store.initialize();
  const appId = randomUUID(), releaseId = randomUUID(), invitationId = randomUUID(), userId = randomUUID(), creationOperationId = randomUUID(), originalApprovalId = randomUUID(), now = new Date().toISOString();
  const app: AppRecord = { id: appId, slug: 'documents', name: 'Documents', kind: 'web', description: '', activeReleaseId: releaseId, status: 'published', url: null, previewUrl: null, createdAt: now, updatedAt: now };
  const invitation: AppInvitation = { id: invitationId, appId, email: 'reader@example.test', roleIds: [randomUUID()], policyHash: 'c'.repeat(64), expiresAt: now, createdAt: now, createdBy: 'owner', approvalId: originalApprovalId };
  const original = { operationId: creationOperationId, invitation, approval: { id: originalApprovalId } } as Omit<AcceptInvitationRequest, 'password'>;
  await store.transaction(state => { state.apps[appId] = app; state.releases[releaseId] = { id: releaseId, appId } as ReleaseRecord; state.invitations[invitationId] = { ...invitation, tokenHash: 'd'.repeat(64), status: 'accepted', userId, operationId: creationOperationId, acceptedAt: now }; state.accessOperations[creationOperationId] = { id: creationOperationId, appId, action: 'invitation', approvalId: originalApprovalId, artifactHash: 'e'.repeat(64), status: 'succeeded', createdAt: now, completedAt: now, request: original }; });
  let evidence: AppAccountSnapshot = { schemaVersion: 1, appId, invitationId, userId, creationOperationId, releaseId, realm: `app-${createHash('sha256').update(appId).digest('hex').slice(0, 24)}`, clientId: randomUUID(), identityHash: 'a'.repeat(64), policyHash: 'c'.repeat(64), username: invitation.email, email: invitation.email, enabled: true, userEvidenceHash: 'b'.repeat(64), tokenPolicyHash: 'f'.repeat(64), accessTokenLifespanSeconds: 1200, checkedAt: now }, calls = 0, uncertain = false, status: AppAccountStatus['status'] = 'disabled', received: DisableAppAccountRequest | undefined;
  const dependencies: EngineDependencies = { appAccountSnapshot: async () => ({ ...evidence, checkedAt: new Date().toISOString() }), disableAppAccount: async input => { calls++; received = structuredClone(input); if (uncertain) throw new Error('synthetic-secret-do-not-persist'); return result(input); }, appAccountOperation: async input => ({ ...input, status, checkedAt: new Date().toISOString(), detail: 'Protected fixture readback.' }) };
  function result(input: DisableAppAccountRequest): AppAccountStatus { return { operationId: input.operationId, approvalId: input.approval.id, appId, invitationId, userId, artifactHash: input.approval.artifactHash, status, checkedAt: new Date().toISOString(), detail: 'Protected fixture readback.' }; }
  const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', appsOrigin: 'https://apps.example.test', dataDir: root, workspaceDir: join(root, 'workspaces'), adminDist: join(root, 'absent'), oidcClientId: 'test', secretKey: Buffer.alloc(32, 5), requestLimitUsd: 1, monthlyLimitUsd: 5 };
  const server = await createServer(config, store, dependencies), session = await server.inject({ url: '/api/v1/session' }), cookie = session.cookies[0]!, sessionId = cookie.value;
  const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string };
  const post = (url: string, payload: Record<string, unknown> = {}) => server.inject({ method: 'POST', url, payload, headers });
  async function review() { const reply = await post(`/api/v1/apps/${appId}/accounts/${invitationId}/disable-review`); assert.equal(reply.statusCode, 200, reply.body); return reply.json().approval; }
  return { store, file, config, server, dependencies, headers, appId, releaseId, invitationId, userId, creationOperationId, sessionId, post, review, evidence: () => evidence, change: (delta: Partial<AppAccountSnapshot>) => { evidence = { ...evidence, ...delta }; }, calls: () => calls, received: () => received, uncertain: () => { uncertain = true; status = 'unknown'; }, setStatus: (value: AppAccountStatus['status']) => { status = value; }, close: async () => { await server.close(); await store.close(); await rm(root, { recursive: true, force: true }); } };
}
