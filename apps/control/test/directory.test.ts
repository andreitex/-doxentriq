import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes, randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { installDirectoryRoutes } from '../src/directory.ts';
import { JsonStore } from '../src/store.ts';
import type { Config } from '../src/config.ts';
import type { AppAccessPolicy, AppAccessSnapshot } from '../../../packages/core/src/access.ts';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import type { AppRecord, ReleaseRecord } from '../../../packages/core/src/types.ts';

async function fixture() {
  const store = new JsonStore(), appId = randomUUID(), releaseId = randomUUID(), connectionId = randomUUID(), roleId = randomUUID(), tenantId = randomUUID(), groupId = randomUUID(), userId = randomUUID(), upstreamId = randomUUID();
  const issuer = 'https://auth.example.test/realms/app-' + (await import('node:crypto')).createHash('sha256').update(appId).digest('hex').slice(0, 24);
  const config = { authMode: 'development', oidcIssuer: 'https://auth.example.test/realms/platform', secretKey: Buffer.alloc(32, 6) } as Config;
  const credentials = { tenantId, clientId: randomUUID(), clientSecret: 'synthetic-protected-directory-secret', consentedScopes: ['Organization.Read.All', 'User.Read.All'] };
  function encrypted() { const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', config.secretKey, nonce); cipher.setAAD(Buffer.from(connectionId)); const data = Buffer.concat([cipher.update(JSON.stringify(credentials)), cipher.final()]); return [nonce, cipher.getAuthTag(), data].map(value => value.toString('base64')).join('.'); }
  const policy: AppAccessPolicy = { schemaVersion: 1, appId, invitationsEnabled: true, requireTotp: true, roles: [{ id: roleId, name: 'Document readers', permissions: ['dms.read'] }], groupMappings: [{ provider: 'microsoft', tenantId, groupId, connectionId, roleIds: [roleId], status: 'pending_validation' }] };
  let snapshot: AppAccessSnapshot = { appId, releaseId, identityHash: 'a'.repeat(64), policyHash: hashArtifact(policy), policy, permissions: ['dms.read', 'dms.write'], checkedAt: new Date().toISOString() };
  await store.transaction(state => { state.apps[appId] = { id: appId, name: 'Documents', status: 'published', activeReleaseId: releaseId } as AppRecord; state.releases[releaseId] = { id: releaseId, appId } as ReleaseRecord; state.connections[connectionId] = { id: connectionId, name: 'Consented directory', type: 'microsoft', roots: [tenantId], endpoints: ['https://graph.microsoft.com/v1.0'], capabilities: ['directory.groups.read'], appIds: [appId], secretRef: connectionId, status: 'configured', expiresAt: null, createdAt: new Date().toISOString(), dossier: { documentation: [], provenance: 'synthetic protocol fixture', license: 'n/a', reviewStatus: 'approved' } }; state.secrets[connectionId] = encrypted(); });
  const { privateKey, publicKey } = await generateKeyPair('ES256'); const exported = await exportJWK(publicKey), jwk: Record<string, string> = { kty: 'EC', crv: 'P-256', x: exported.x!, y: exported.y!, kid: 'fixture', use: 'sig', alg: 'ES256' };
  const server = Fastify({ logger: false }); server.decorateRequest('principal', null);
  server.addHook('onRequest', async request => { request.principal = { id: 'owner', name: 'Synthetic owner', roles: ['platform-owner'], localOwner: request.headers['x-test-owner'] !== 'false', mfa: request.headers['x-test-mfa'] !== 'false' }; });
  let groups: string[] = [groupId], membershipCalls = 0, unavailable = false, memberRead: (() => Promise<void>) | undefined;
  await installDirectoryRoutes(server, store, config, {
    accessSnapshot: async () => ({ ...snapshot, checkedAt: new Date().toISOString() }),
    directoryIdentityConfiguration: async input => { assert.deepEqual(Object.keys(input).sort(), ['appId', 'provider', 'tenantId', 'workspaceDomain']); return { ...input, bindingHash: 'b'.repeat(64), checkedAt: new Date().toISOString() }; },
    directoryIdentityKeys: async () => ({ appId, releaseId, policyHash: snapshot.policyHash, issuer, audience: `app-${appId}`, jwks: { keys: [jwk] }, checkedAt: new Date().toISOString() }),
    directoryIdentitySubject: async input => ({ ...input, upstreamUserId: upstreamId, policyHash: snapshot.policyHash, releaseId, bindingHash: 'c'.repeat(64), checkedAt: new Date().toISOString() }),
  }, { http: async input => { if (unavailable) throw new Error('Synthetic directory outage'); if (input.method === 'POST') return { access_token: 'synthetic-token', token_type: 'Bearer', expires_in: 3600 }; const path = new URL(input.url).pathname; if (path.endsWith('/organization')) return { value: [{ id: tenantId }] }; if (path.endsWith('/transitiveMemberOf')) { membershipCalls++; if (memberRead) await memberRead(); return { value: groups.map(id => ({ id, '@odata.type': '#microsoft.graph.group' })) }; } return { id: upstreamId, accountEnabled: true }; } });
  const request = (url: string, payload: Record<string, unknown>, headers: Record<string, string> = {}) => server.inject({ method: 'POST', url, payload, headers });
  const proposal = { connectionId, provider: 'microsoft', tenantId, workspaceDomain: null, groupIds: [groupId], evidenceTtlSeconds: 60, accessExpiresAt: new Date(Date.now() + 3600000).toISOString() };
  async function approve() { const draft = await request(`/api/v1/apps/${appId}/access/directory/approval`, proposal); assert.equal(draft.statusCode, 200, draft.body); const approval = draft.json().approval; const accepted = await request(`/api/v1/directory/approvals/${approval.id}/approve`, { artifactHash: approval.artifactHash }); assert.equal(accepted.statusCode, 200, accepted.body); return approval; }
  async function activate() { const approval = await approve(); const response = await request(`/api/v1/apps/${appId}/access/directory/activate`, { approvalId: approval.id }); assert.equal(response.statusCode, 200, response.body); return response.json().activation; }
  async function jwt(options: { aud?: string; app?: string; subject?: string } = {}) { return new SignJWT({ app_id: options.app ?? appId }).setSubject(options.subject ?? userId).setAudience(options.aud ?? `app-${appId}`).setIssuer(issuer).setIssuedAt().setExpirationTime('5m').setProtectedHeader({ alg: 'ES256', kid: 'fixture' }).sign(privateKey); }
  async function authorize() { return request(`/api/public/v1/apps/${appId}/directory/authorize`, { target: 'api' }, { authorization: `Bearer ${await jwt()}` }); }
  return { store, server, appId, connectionId, policy, groupId, roleId, userId, upstreamId, credentials, encrypted, request, proposal, approve, activate, jwt, authorize, membershipCalls: () => membershipCalls, groups: (value: string[]) => { groups = value; }, outage: () => { unavailable = true; }, memberRead: (value: () => Promise<void>) => { memberRead = value; }, changePolicy: (value: AppAccessPolicy) => { snapshot = { ...snapshot, policy: value, policyHash: hashArtifact(value) }; }, close: () => server.close() };
}
test('directory activation needs exact unused owner MFA review and verifies consent before enabling a draft', async () => {
  const f = await fixture(); try {
    assert.equal((await f.request(`/api/v1/apps/${f.appId}/access/directory/approval`, f.proposal, { 'x-test-mfa': 'false' })).statusCode, 403);
    assert.equal((await f.request(`/api/v1/apps/${f.appId}/access/directory/approval`, f.proposal, { 'x-test-owner': 'false' })).statusCode, 403);
    const approval = await f.approve(); assert.ok(!JSON.stringify(approval).includes(f.credentials.clientSecret));
    const activatePath = `/api/v1/apps/${f.appId}/access/directory/activate`, activated = await f.request(activatePath, { approvalId: approval.id }); assert.equal(activated.statusCode, 200, activated.body); assert.equal((await f.request(activatePath, { approvalId: approval.id })).statusCode, 409);
    const draft = await f.approve(); await f.store.transaction(state => { state.directoryApprovals[draft.id]!.expiresAt = new Date(Date.now() - 1).toISOString(); }); assert.equal((await f.request(activatePath, { approvalId: draft.id })).statusCode, 409);
    const outage = await f.approve(); f.outage(); assert.equal((await f.request(activatePath, { approvalId: outage.id })).statusCode, 503); assert.equal(await f.store.read(state => state.directoryApprovals[outage.id]!.consumedAt), null);
  } finally { await f.close(); }
});
test('app JWT authorization ignores platform owner cookies and cannot grant foreign audiences, identities or permissions', async () => {
  const f = await fixture(); try { await f.activate(); const path = `/api/public/v1/apps/${f.appId}/directory/authorize`;
    assert.equal((await f.request(path, {}, { cookie: 'autosoft_session=platform-owner' })).statusCode, 401);
    for (const jwt of [await f.jwt({ app: randomUUID() }), await f.jwt({ aud: 'autosoft-admin' }), await f.jwt({ aud: `${f.appId}:mcp` })]) assert.equal((await f.request(path, { target: 'api' }, { authorization: `Bearer ${jwt}` })).statusCode, 401);
    const response = await f.authorize(); assert.equal(response.statusCode, 200, response.body); assert.deepEqual(response.json().permissions, ['dms.read']); assert.equal(response.json().subject, f.userId); assert.ok(Date.parse(response.json().validUntil) - Date.parse(response.json().checkedAt) <= 60000); assert.ok(!response.body.includes(f.upstreamId)); assert.ok(!response.body.includes(f.credentials.clientSecret));
    const evidence = await f.store.read(state => Object.values(state.directoryEvidence)[0]!); assert.ok(!evidence.encrypted.includes(f.userId)); assert.ok(!evidence.encrypted.includes(f.groupId));
  } finally { await f.close(); }
});
test('cached membership expires, group revocation loses permissions and changed registry/cipher disables authorization', async () => {
  const f = await fixture(); try { await f.activate(); assert.equal((await f.authorize()).statusCode, 200); assert.equal((await f.authorize()).statusCode, 200); assert.equal(f.membershipCalls(), 1);
    await f.store.transaction(state => { for (const proof of Object.values(state.directoryEvidence)) proof.expiresAt = new Date(Date.now() - 1).toISOString(); }); f.groups([]); const revoked = await f.authorize(); assert.equal(revoked.statusCode, 200, revoked.body); assert.deepEqual(revoked.json().permissions, []); assert.equal(f.membershipCalls(), 2);
    await f.store.transaction(state => { state.secrets[f.connectionId] = f.encrypted(); }); assert.equal((await f.authorize()).statusCode, 409);
  } finally { await f.close(); }
});
test('an async revocation or policy change cannot return or persist a previously positive membership grant', async () => {
  for (const change of ['activation', 'registry', 'policy']) {
    const f = await fixture(); try { const activation = await f.activate(); f.memberRead(async () => {
      if (change === 'policy') f.changePolicy({ ...f.policy, roles: [{ id: f.roleId, name: 'Writers', permissions: ['dms.write'] }] });
      else await f.store.transaction(state => { if (change === 'activation') state.directoryActivations[activation.id]!.disabledAt = new Date().toISOString(); else state.connections[f.connectionId]!.appIds = []; });
    }); const response = await f.authorize(); assert.equal(response.statusCode, 409, response.body); assert.ok(!response.json().permissions); if (change !== 'policy') assert.equal(await f.store.read(state => Object.keys(state.directoryEvidence).length), 0);
    } finally { await f.close(); }
  }
});
