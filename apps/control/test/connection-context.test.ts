import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHash, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import type { AppRecord, ConnectionRecord, JobRecord } from '../../../packages/core/src/types.ts';
import type { ConnectorStatus } from '../../../packages/core/src/connectors.ts';
import { generationConnectionInventory } from '../src/connection-context.ts';
import { connectorArtifactHash, type ConnectorScope } from '../src/connectors.ts';
import { JsonStore } from '../src/store.ts';
import { WorkflowEngine } from '../src/engine.ts';
import { BudgetManager } from '../src/budget.ts';

async function fixture() {
  const store = new JsonStore(), at = Date.now(), createdAt = new Date(at).toISOString(), key = Buffer.alloc(32, 3);
  const app: AppRecord = { id: randomUUID(), slug: 'documents', name: 'Documents', description: '', kind: 'web', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt, updatedAt: createdAt };
  const username = 'DOMAIN\\Dedicated-Reader', password = 'Protected-Samba-Password-Only', secretRef = `connection:${randomUUID()}`;
  const nonce = Buffer.alloc(12, 1), cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(Buffer.from(secretRef));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify({ username, password })), cipher.final()]);
  const envelope = [nonce, cipher.getAuthTag(), encrypted].map(value => value.toString('base64')).join('.');
  const connection: ConnectionRecord = { id: randomUUID(), name: `Archive ${username} ${password}`, type: 'samba', endpoints: ['smb://10.23.23.20/Documents'], roots: ['documents', '/host/private'], capabilities: ['files.list','files.read'], appIds: [app.id, randomUUID()], secretRef, expiresAt: new Date(at + 31 * 86400000).toISOString(), status: 'configured', dossier: { documentation: ['https://private-acl.example.test'], provenance: 'Protected private review', license: 'private', reviewStatus: 'pending' }, createdAt };
  const scope: ConnectorScope = { appId: app.id, connectionId: connection.id, type: 'samba', serverIp: '10.23.23.20', share: 'Documents', root: 'documents', readonlyAclEvidenceSha256: 'c'.repeat(64), aclEvidenceCheckedAt: createdAt, aclEvidenceDescription: 'Private remote ACL description must not enter any model', accessExpiresAt: new Date(at + 30 * 86400000).toISOString(), credentialRef: secretRef, credentialCiphertextSha256: createHash('sha256').update(envelope).digest('hex'), registryHash: hashArtifact(connection) };
  const approvalId = randomUUID(), operationId = randomUUID(), artifactHash = connectorArtifactHash(scope);
  await store.transaction(state => { state.apps[app.id] = app; state.connections[connection.id] = connection; state.secrets[secretRef] = envelope; state.connectorChanges[approvalId] = scope;
    state.connectorApprovals[approvalId] = { id: approvalId, appId: app.id, connectionId: connection.id, action: 'approve_readonly_samba', artifactHash, impact: ['Private ACL and ciphertext evidence'], createdAt, expiresAt: new Date(at + 300000).toISOString(), approvedBy: 'owner-id', approvedAt: createdAt, consumedAt: createdAt };
    state.connectorOperations[operationId] = { id: operationId, appId: app.id, connectionId: connection.id, approvalId, artifactHash, status: 'configured', scopeHash: 'b'.repeat(64), liveShareVerified: false, createdAt, completedAt: createdAt, detail: 'Retained encrypted runtime state' };
  });
  let status: ConnectorStatus = { status: 'configured', appId: app.id, connectionId: connection.id, approvalId, scopeHash: 'b'.repeat(64), liveShareVerified: false }, probes = 0;
  const options = { secretKey: key, ownerSubject: 'owner-id', now: at, connectorStatus: async () => { probes++; return status; } };
  return { store, app, connection, scope, approvalId, operationId, key, username, password, envelope, secretRef, options, status: (value: ConnectorStatus) => { status = value; }, probes: () => probes };
}

test('model inventory contains only app-authorized redacted metadata and exact configured logical read scope', async () => {
  const f = await fixture();
  await f.store.transaction(state => { state.connections['another-app'] = { ...f.connection, id: 'another-app', name: 'Other customer connection', appIds: [randomUUID()] }; });
  const inventory = await generationConnectionInventory(f.store, f.app.id, f.options), item = inventory.connections[0]!;
  assert.equal(inventory.connections.length, 1); assert.equal(item.status, 'usable'); assert.equal(item.reason, null); assert.deepEqual(item.appIds, [f.app.id]); assert.deepEqual(item.roots, ['documents']); assert.deepEqual(item.capabilities, ['files.list','files.read']); assert.equal(item.expiresAt, f.scope.accessExpiresAt); assert.equal(f.probes(), 1);
  const serialized = JSON.stringify(inventory);
  for (const value of [f.username, f.password, f.envelope, f.secretRef, f.scope.credentialCiphertextSha256, f.scope.readonlyAclEvidenceSha256, f.scope.aclEvidenceDescription, f.scope.serverIp, '/host/private', 'Other customer connection', f.connection.appIds[1]!]) assert.ok(!serialized.includes(value), `Unexpected private model context: ${value}`);
  assert.ok(!/credential|ciphertext|endpoint|provenance|license|scopeHash|approvalId/.test(serialized)); assert.match(item.name, /REDACTED/);
});

test('registered, pending, unsupported and expired scopes are metadata only and never usable', async () => {
  for (const mutation of ['pending','absent','scope_expired','credential_expired','disabled','unsupported','corrupt_credentials'] as const) {
    const f = await fixture(); await f.store.transaction(state => {
      if (mutation === 'pending') state.connectorOperations[f.operationId]!.status = 'pending';
      if (mutation === 'absent') delete state.connectorOperations[f.operationId];
      if (mutation === 'scope_expired') state.connectorChanges[f.approvalId]!.accessExpiresAt = new Date(f.options.now - 1).toISOString();
      if (mutation === 'credential_expired') state.connections[f.connection.id]!.expiresAt = new Date(f.options.now - 1).toISOString();
      if (mutation === 'disabled') state.connections[f.connection.id]!.status = 'disabled';
      if (mutation === 'unsupported') state.connections[f.connection.id]!.type = 'rest';
      if (mutation === 'corrupt_credentials') state.secrets[f.secretRef] = 'not-a-valid-envelope';
    });
    const item = (await generationConnectionInventory(f.store, f.app.id, f.options)).connections[0]!;
    assert.equal(item.status, 'unavailable', mutation); assert.notEqual(item.reason, null); assert.equal(f.probes(), 0, mutation);
    if (mutation === 'corrupt_credentials') { assert.equal(item.name, 'Protected connection'); assert.deepEqual(item.roots, []); }
  }
});

test('registry, ciphertext, approval and runtime proof changes cannot authorize model integrations', async () => {
  for (const mutation of ['registry','ciphertext','approval','owner','scope_hash','cross_app','cross_approval','unknown','outage'] as const) {
    const f = await fixture(); await f.store.transaction(state => {
      if (mutation === 'registry') state.connections[f.connection.id]!.capabilities.push('files.write');
      if (mutation === 'ciphertext') state.secrets[f.secretRef] = state.secrets[f.secretRef]!.slice(0, -1) + 'A';
      if (mutation === 'approval') state.connectorApprovals[f.approvalId]!.artifactHash = 'f'.repeat(64);
      if (mutation === 'owner') state.connectorApprovals[f.approvalId]!.approvedBy = 'sso-admin';
    });
    const base: ConnectorStatus = { status: 'configured', appId: f.app.id, connectionId: f.connection.id, approvalId: f.approvalId, scopeHash: 'b'.repeat(64), liveShareVerified: false };
    if (mutation === 'scope_hash') f.status({ ...base, scopeHash: 'f'.repeat(64) });
    if (mutation === 'cross_app') f.status({ ...base, appId: randomUUID() });
    if (mutation === 'cross_approval') f.status({ ...base, approvalId: randomUUID() });
    if (mutation === 'unknown') f.status({ ...base, status: 'unknown' });
    const options = mutation === 'outage' ? { ...f.options, connectorStatus: async () => { throw new Error(`Unexpected provider failure ${f.password}`); } } : f.options;
    const inventory = await generationConnectionInventory(f.store, f.app.id, options); assert.equal(inventory.connections[0]!.status, 'unavailable', mutation); assert.ok(!JSON.stringify(inventory).includes(f.password));
  }
});

test('workflow passes current app-scoped connection inventory into generation without persisting private source evidence', async () => {
  const f = await fixture(), root = await mkdtemp(join(tmpdir(), 'autosoft-connection-context-')), createdAt = new Date().toISOString();
  const job: JobRecord = { id: randomUUID(), appId: f.app.id, request: 'Use the approved Archive connection', stage: 'queued', baseReleaseId: null, costUsd: 0, budgetUsd: 1, attempts: 0, createdAt, updatedAt: createdAt };
  await f.store.transaction(state => { state.jobs[job.id] = job; }); let received: unknown;
  const engine = new WorkflowEngine(f.store, { generationConnections: appId => generationConnectionInventory(f.store, appId, f.options), planAndGenerate: async input => { received = input.context.connectionInventory; return { specification: { questions: ['Which document categories should be imported?'] }, files: [], pipeline: null, summary: 'Business clarification' }; } }, new BudgetManager(f.store, 1, 5), root);
  try { await engine.run(job.id); assert.equal((received as { connections: { status: string }[] }).connections[0]!.status, 'usable'); assert.equal(await f.store.read(state => state.jobs[job.id]!.stage), 'clarification'); assert.ok(!JSON.stringify(await f.store.read(state => state.jobs[job.id])).includes(f.scope.readonlyAclEvidenceSha256)); }
  finally { await rm(root, { recursive: true, force: true }); }
});

test('revocation or credential changes while the runtime proof is in flight invalidate the model-visible scope', async () => {
  for (const mutation of ['app_acl', 'ciphertext', 'archived'] as const) {
    const f = await fixture();
    const pending = generationConnectionInventory(f.store, f.app.id, { ...f.options, connectorStatus: async input => {
      await f.store.transaction(state => {
        if (mutation === 'app_acl') state.connections[f.connection.id]!.appIds = [];
        if (mutation === 'ciphertext') state.secrets[f.secretRef] = 'changed-encrypted-credential';
        if (mutation === 'archived') state.apps[f.app.id]!.status = 'archived';
      });
      return { status: 'configured', ...input, scopeHash: 'b'.repeat(64), liveShareVerified: false };
    } });
    if (mutation === 'archived') await assert.rejects(pending, /application changed/);
    else { const inventory = await pending; if (mutation === 'app_acl') assert.equal(inventory.connections.length, 0); else assert.equal(inventory.connections[0]!.status, 'unavailable', mutation); }
  }
});
