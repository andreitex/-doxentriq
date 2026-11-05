import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash, createCipheriv, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { AppRecord, Principal } from '../../../packages/core/src/types.ts';
import type { SambaProvisionRequest, ConnectorStatus } from '../../../packages/core/src/connectors.ts';
import { ConnectorBrokerClient } from '../../../packages/core/src/connectors.ts';
import { createServer } from '../src/server.ts';
import { JsonStore } from '../src/store.ts';
import { reconcileConnectorOperations } from '../src/connectors.ts';
import type { Config } from '../src/config.ts';
import type { EngineDependencies } from '../src/engine.ts';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-connectors-')), file = join(root, 'state.json'), store = new JsonStore(file); await store.initialize(); const id = randomUUID(), createdAt = new Date().toISOString();
  const app: AppRecord = { id, slug: 'documents', name: 'Documents', description: '', kind: 'web', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt, updatedAt: createdAt };
  const key = Buffer.alloc(32, 7), owner: Principal = { id: 'owner-id', name: 'Owner', localOwner: true, mfa: true, roles: ['platform-owner'] }, sessionId = 's'.repeat(43), csrf = 'csrf-synthetic';
  await store.transaction(state => { state.apps[id] = app; state.sessions[sessionId] = { id: sessionId, principal: owner, csrfToken: csrf, expiresAt: new Date(Date.now() + 3600000).toISOString(), accessExpiresAt: new Date(Date.now() + 3600000).toISOString() }; });
  const config: Config = { authMode: 'oidc', host: '127.0.0.1', port: 3000, publicOrigin: 'https://admin.example.test', appsOrigin: 'https://apps.example.test', ownerSubject: owner.id, secretKey: key, dataDir: root, workspaceDir: join(root, 'workspaces'), adminDist: join(root, 'no-build'), oidcClientId: 'test', requestLimitUsd: 1, monthlyLimitUsd: 5 };
  let calls = 0, received: SambaProvisionRequest | undefined, uncertain = false, malformed: unknown | undefined, remoteStatus: 'unknown' | 'configured' = 'unknown';
  const dependencies: EngineDependencies = { provisionSamba: async input => { calls++; received = structuredClone(input); if (uncertain) throw new Error('Synthetic lost response after dispatch'); if (malformed) return malformed as ConnectorStatus; return { status: 'configured', appId: input.appId, connectionId: input.connectionId, approvalId: input.approvalId, scopeHash: 'a'.repeat(64), liveShareVerified: false }; }, connectorStatus: async input => ({ status: remoteStatus, appId: input.appId, connectionId: input.connectionId, approvalId: input.approvalId, ...(remoteStatus === 'configured' ? { scopeHash: 'a'.repeat(64) } : {}), liveShareVerified: false }) };
  const server = await createServer(config, store, dependencies), headers = { cookie: `__Host-autosoft-session=${sessionId}`, origin: config.publicOrigin, 'x-csrf-token': csrf };
  const post = (url: string, payload: Record<string, unknown>) => server.inject({ method: 'POST', url, headers, payload });
  const password = 'Synthetic-Samba-Password-17!', username = 'DOMAIN\\dedicated-reader';
  const registered = await post('/api/v1/connections', { name: 'Read-only archive', type: 'samba', endpoints: ['smb://10.23.23.20/Documents'], roots: ['documents'], capabilities: ['files.list', 'files.read'], appIds: [id], credentials: { username, password } }); assert.equal(registered.statusCode, 200, registered.body); const connection = registered.json().connection as { id: string; secretRef: string };
  const body = { appId: id, serverIp: '10.23.23.20', share: 'Documents', root: 'documents', readonlyAclEvidenceSha256: 'b'.repeat(64), aclEvidenceCheckedAt: new Date().toISOString(), aclEvidenceDescription: 'Company reviewed exported ACL: dedicated account reads only this share.', accessExpiresAt: new Date(Date.now() + 30 * 86400000).toISOString() };
  async function prepare() { const response = await post(`/api/v1/connections/${connection.id}/samba/approval`, body); assert.equal(response.statusCode, 200, response.body); return response.json().approval as { id: string; artifactHash: string }; }
  async function approve(approval: { id: string; artifactHash: string }) { const response = await post(`/api/v1/connectors/approvals/${approval.id}/approve`, { artifactHash: approval.artifactHash }); assert.equal(response.statusCode, 200, response.body); }
  return { root, file, store, config, app, connection, password, username, body, server, headers, post, prepare, approve, dependencies, calls: () => calls, received: () => received, uncertain: () => { uncertain = true; }, malformed: (value: unknown) => { malformed = value; }, status: (value: 'unknown' | 'configured') => { remoteStatus = value; }, principal: (principal: Principal) => store.transaction(state => { state.sessions[sessionId]!.principal = principal; }), close: async () => { await server.close(); await store.close(); await rm(root, { recursive: true, force: true }); } };
}
test('permanent owner exact Samba review binds scope and encrypted credential version, without persisting plaintext', async () => {
  const f = await fixture(); try { const approval = await f.prepare(); const draft = await f.store.read(state => state.connectorChanges[approval.id]!); const cipher = await f.store.read(state => state.secrets[f.connection.secretRef]!);
    assert.equal(draft.credentialCiphertextSha256, createHash('sha256').update(cipher).digest('hex')); assert.notEqual(draft.credentialCiphertextSha256, createHash('sha256').update(f.password).digest('hex'));
    assert.equal((await f.post(`/api/v1/connections/${f.connection.id}/samba/provision`, { approvalId: approval.id })).statusCode, 409);
    assert.equal((await f.post(`/api/v1/connectors/approvals/${approval.id}/approve`, { artifactHash: 'f'.repeat(64) })).statusCode, 409); await f.approve(approval);
    const response = await f.post(`/api/v1/connections/${f.connection.id}/samba/provision`, { approvalId: approval.id }); assert.equal(response.statusCode, 200, response.body); assert.equal(response.json().operation.status, 'configured'); assert.equal(response.json().operation.liveShareVerified, false); assert.equal(f.calls(), 1); assert.equal(f.received()!.credentials.password, f.password); assert.equal(f.received()!.principal.localOwner, true);
    for (const privateValue of [f.password, f.username]) assert.ok(!(await readFile(f.file, 'utf8')).includes(privateValue)); assert.ok(!response.body.includes(f.password)); assert.equal((await f.post(`/api/v1/connections/${f.connection.id}/samba/provision`, { approvalId: approval.id })).statusCode, 409); assert.equal(f.calls(), 1);
  } finally { await f.close(); }
});
test('SSO administrators and non-MFA identities cannot prepare or approve protected connector scopes', async () => {
  const f = await fixture(); try { const approval = await f.prepare(); await f.principal({ id: 'sso-admin', name: 'SSO admin', roles: ['platform-admin'], mfa: true, localOwner: false }); assert.equal((await f.post(`/api/v1/connections/${f.connection.id}/samba/approval`, f.body)).statusCode, 403); assert.equal((await f.post(`/api/v1/connectors/approvals/${approval.id}/approve`, { artifactHash: approval.artifactHash })).statusCode, 403); assert.equal((await f.post(`/api/v1/connections/${f.connection.id}/samba/provision`, { approvalId: approval.id })).statusCode, 403); await f.principal({ id: 'owner-id', name: 'Owner', roles: ['platform-owner'], localOwner: true, mfa: false }); assert.equal((await f.post(`/api/v1/connections/${f.connection.id}/samba/approval`, f.body)).statusCode, 403); assert.equal(f.calls(), 0); } finally { await f.close(); }
});
test('scope, credential ciphertext, expiry and app ACL changes invalidate the exact connector approval', async () => {
  for (const mutation of ['ciphertext', 'app_acl', 'write', 'scope', 'expiry', 'artifact'] as const) {
    const f = await fixture(); try { const approval = await f.prepare(); await f.approve(approval); await f.store.transaction(state => {
      const connection = state.connections[f.connection.id]!;
      if (mutation === 'ciphertext') { const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', f.config.secretKey, nonce); cipher.setAAD(Buffer.from(f.connection.secretRef)); const encrypted = Buffer.concat([cipher.update(JSON.stringify({ username: f.username, password: f.password })), cipher.final()]); state.secrets[f.connection.secretRef] = [nonce, cipher.getAuthTag(), encrypted].map(value => value.toString('base64')).join('.'); }
      if (mutation === 'app_acl') connection.appIds = [];
      if (mutation === 'write') connection.capabilities.push('files.write');
      if (mutation === 'scope') connection.roots = ['another-share'];
      if (mutation === 'expiry') state.connectorApprovals[approval.id]!.expiresAt = new Date(Date.now() - 1000).toISOString();
      if (mutation === 'artifact') state.connectorChanges[approval.id]!.share = 'AnotherShare';
    }); const response = await f.post(`/api/v1/connections/${f.connection.id}/samba/provision`, { approvalId: approval.id }); assert.equal(response.statusCode, 409, `${mutation}: ${response.body}`); assert.equal(f.calls(), 0); } finally { await f.close(); }
  }
});
test('unsafe servers/shares/paths, unregistered destinations, stale ACL evidence and credential descriptions are rejected', async () => {
  const f = await fixture(); try { for (const change of [{ serverIp: '127.0.0.1' }, { serverIp: '169.254.2.1' }, { serverIp: '224.0.0.1' }, { serverIp: 'files.example.test' }, { share: 'C$' }, { share: '../Documents' }, { root: '/mnt/documents' }, { serverIp: '10.23.23.21' }, { aclEvidenceCheckedAt: new Date(Date.now() - 25 * 3600000).toISOString() }, { accessExpiresAt: new Date(Date.now() + 91 * 86400000).toISOString() }, { aclEvidenceDescription: `Reviewed evidence including ${f.password}` }]) { const response = await f.post(`/api/v1/connections/${f.connection.id}/samba/approval`, { ...f.body, ...change }); assert.ok([400, 409].includes(response.statusCode), response.body); } assert.equal(f.calls(), 0); } finally { await f.close(); }
});
test('uncertain connector dispatch remains durable and reconciles read-only without replaying protected credentials', async () => {
  const f = await fixture(); try { f.uncertain(); const approval = await f.prepare(); await f.approve(approval); const response = await f.post(`/api/v1/connections/${f.connection.id}/samba/provision`, { approvalId: approval.id }); assert.equal(response.statusCode, 200, response.body); assert.equal(response.json().operation.status, 'pending'); assert.equal(f.calls(), 1); assert.equal((await f.post(`/api/v1/connections/${f.connection.id}/samba/provision`, { approvalId: approval.id })).statusCode, 409);
    const restarted = new JsonStore(f.file); await restarted.initialize(); await reconcileConnectorOperations(restarted, f.dependencies); assert.equal((await restarted.read(state => state.connectorOperations[response.json().operation.id]!)).status, 'pending'); f.status('configured'); await reconcileConnectorOperations(restarted, f.dependencies); assert.equal((await restarted.read(state => state.connectorOperations[response.json().operation.id]!)).status, 'configured'); assert.equal(f.calls(), 1); assert.ok(!(await readFile(f.file, 'utf8')).includes(f.password)); await restarted.close();
  } finally { await f.close(); }
});
test('malformed or cross-scope runtime evidence cannot claim a configured or live verified connector', async () => {
  for (const alteration of [{ liveShareVerified: true }, { appId: randomUUID() }, { approvalId: randomUUID() }, { scopeHash: 'bad' }]) { const f = await fixture(); try { const approval = await f.prepare(); await f.approve(approval); f.malformed({ status: 'configured', appId: f.app.id, connectionId: f.connection.id, approvalId: approval.id, scopeHash: 'a'.repeat(64), liveShareVerified: false, ...alteration }); const response = await f.post(`/api/v1/connections/${f.connection.id}/samba/provision`, { approvalId: approval.id }); assert.equal(response.statusCode, 200, response.body); assert.equal(response.json().operation.status, 'pending'); assert.equal(response.json().operation.liveShareVerified, false); } finally { await f.close(); } }
});
test('connector client refuses non-local plaintext broker destinations before credentials can be transmitted', () => { assert.throws(() => new ConnectorBrokerClient({ url: 'http://broker.example.test', token: 'synthetic', approvalKey: Buffer.alloc(32) })); assert.throws(() => new ConnectorBrokerClient({ url: 'https://user:secret@broker.example.test', token: 'synthetic', approvalKey: Buffer.alloc(32) })); });
