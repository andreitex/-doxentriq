import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createDirectoryHttp, directoryUrl } from '../src/directory-http.ts';
import { resolveDirectoryMembership, verifyDirectoryConnection, microsoftNextLink, googleDirectoryScopes } from '../src/directory-provider.ts';
import type { DirectoryScope, DirectorySubject } from '../../../packages/core/src/directory.ts';
import { DirectoryBrokerClient } from '../../../packages/core/src/directory.ts';

const appId = '11111111-1111-4111-8111-111111111111', tenantId = '22222222-2222-4222-8222-222222222222', upstreamUserId = '33333333-3333-4333-8333-333333333333', groupId = '44444444-4444-4444-8444-444444444444';
const scope: DirectoryScope = { schemaVersion: 1, appId, connectionId: '55555555-5555-4555-8555-555555555555', provider: 'microsoft', tenantId, workspaceDomain: null, identityBindingHash: 'a'.repeat(64), policyHash: 'b'.repeat(64), registryHash: 'c'.repeat(64), credentialRef: 'fixture', credentialCiphertextSha256: 'd'.repeat(64), groupIds: [groupId], evidenceTtlSeconds: 60, accessExpiresAt: new Date(Date.now() + 3600000).toISOString() };
const subject: DirectorySubject = { appId, appSubject: '66666666-6666-4666-8666-666666666666', provider: 'microsoft', tenantId, workspaceDomain: null, upstreamUserId, policyHash: scope.policyHash, releaseId: '77777777-7777-4777-8777-777777777777', bindingHash: 'e'.repeat(64), checkedAt: new Date().toISOString() };
const credentials = { tenantId, clientId: '88888888-8888-4888-8888-888888888888', clientSecret: 'synthetic-directory-secret', consentedScopes: ['Organization.Read.All', 'User.Read.All'] };
const token = { access_token: 'synthetic-transient-token', token_type: 'Bearer', expires_in: 3600 };
test('Microsoft overage resolves full fixed-endpoint pagination and ignores token group shortcuts', async () => {
  const calls: string[] = [];
  const result = await resolveDirectoryMembership(async input => {
    calls.push(input.url); const url = new URL(input.url);
    if (input.method === 'POST') { assert.equal(input.form!.get('scope'), 'https://graph.microsoft.com/.default'); assert.equal(input.form!.get('client_secret'), credentials.clientSecret); return token; }
    assert.equal(input.bearer, token.access_token);
    if (url.pathname.endsWith('/organization')) return { value: [{ id: tenantId }] };
    if (!url.pathname.endsWith('/transitiveMemberOf')) return { id: upstreamUserId, accountEnabled: true };
    return url.searchParams.has('$skiptoken') ? { value: [{ id: groupId, '@odata.type': '#microsoft.graph.group' }] } : { value: [{ id: '99999999-9999-4999-8999-999999999999', '@odata.type': '#microsoft.graph.directoryRole' }], '@odata.nextLink': `https://graph.microsoft.com/v1.0/users/${upstreamUserId}/transitiveMemberOf?$select=id&$skiptoken=opaque%2Bvalue` };
  }, scope, subject, credentials);
  assert.deepEqual(result, [groupId]); assert.equal(calls.length, 5); assert.ok(calls.every(url => !url.includes(credentials.clientSecret)));
});
test('Microsoft partial positive evidence never grants membership after an escaped, cyclic or unavailable next page', async () => {
  for (const next of [`https://evil.example/users/${upstreamUserId}`, `https://graph.microsoft.com/v1.0/users/${tenantId}/transitiveMemberOf`, `https://graph.microsoft.com/v1.0/users/${upstreamUserId}/transitiveMemberOf?$expand=members`, `https://graph.microsoft.com/v1.0/users/${upstreamUserId}/transitiveMemberOf?$select=id&$top=999`]) {
    let reads = 0;
    await assert.rejects(resolveDirectoryMembership(async input => { if (input.method === 'POST') return token; const url = new URL(input.url); if (url.pathname.endsWith('/organization')) return { value: [{ id: tenantId }] }; if (!url.pathname.endsWith('/transitiveMemberOf')) return { id: upstreamUserId, accountEnabled: true }; reads++; return { value: [{ id: groupId, '@odata.type': '#microsoft.graph.group' }], '@odata.nextLink': next }; }, scope, subject, credentials)); assert.equal(reads, 1);
  }
  assert.throws(() => microsoftNextLink(`https://graph.microsoft.com:444/v1.0/users/${upstreamUserId}/transitiveMemberOf`, upstreamUserId));
});
test('disabled users, foreign tenants and missing explicit directory consent fail closed', async () => {
  await assert.rejects(resolveDirectoryMembership(async input => input.method === 'POST' ? token : new URL(input.url).pathname.endsWith('/organization') ? { value: [{ id: tenantId }] } : { id: upstreamUserId, accountEnabled: false }, scope, subject, credentials));
  await assert.rejects(verifyDirectoryConnection(async input => input.method === 'POST' ? token : { value: [{ id: upstreamUserId }] }, scope, credentials));
  await assert.rejects(verifyDirectoryConnection(async () => { throw new Error('must not dispatch'); }, scope, { ...credentials, consentedScopes: ['User.Read.All'] }));
  await assert.rejects(resolveDirectoryMembership(async () => { throw new Error('must not dispatch'); }, scope, { ...subject, appId: tenantId }, credentials));
});
test('Workspace consent uses signed delegated service-account assertion and immutable customer/user/group checks', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const c = { clientEmail: 'directory@fixture.iam.gserviceaccount.com', delegatedSubject: 'directory-reader@example.com', privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }), consentedScopes: [...googleDirectoryScopes] };
  const g: DirectoryScope = { ...scope, provider: 'google', tenantId: 'C0123fixture', workspaceDomain: 'example.com', groupIds: ['01immutablegroup'] }, s = { ...subject, provider: 'google' as const, tenantId: g.tenantId, workspaceDomain: g.workspaceDomain, upstreamUserId: '123456789012345678901' };
  const calls: string[] = [];
  assert.deepEqual(await resolveDirectoryMembership(async input => {
    calls.push(input.url); const path = new URL(input.url).pathname;
    if (input.method === 'POST') { assert.equal(input.url, 'https://oauth2.googleapis.com/token'); const assertion = input.form!.get('assertion')!; const payload = JSON.parse(Buffer.from(assertion.split('.')[1]!, 'base64url').toString()); assert.equal(payload.sub, c.delegatedSubject); assert.equal(payload.aud, 'https://oauth2.googleapis.com/token'); assert.equal(payload.scope, googleDirectoryScopes.join(' ')); assert.ok(!assertion.includes('PRIVATE KEY')); return token; }
    if (path.includes('/customers/')) return { id: g.tenantId };
    if (path.includes('/users/')) return { id: s.upstreamUserId, customerId: g.tenantId, suspended: false, primaryEmail: 'reader@example.com' };
    if (path.includes('/hasMember/')) return { isMember: true };
    return { groups: [{ id: '01immutablegroup', email: 'documents@example.com' }] };
  }, g, s, c), g.groupIds);
  assert.ok(calls.some(url => url.endsWith(`/groups/01immutablegroup/hasMember/${s.upstreamUserId}`))); assert.ok(calls.every(url => !url.includes('@')));
  await assert.rejects(resolveDirectoryMembership(async input => input.method === 'POST' ? token : new URL(input.url).pathname.includes('/users/') ? { id: s.upstreamUserId, customerId: g.tenantId, suspended: false, primaryEmail: 'reader@example.com' } : new URL(input.url).pathname.includes('/customers/') ? { id: g.tenantId } : { groups: [{ id: '01immutablegroup', email: 'documents@foreign.example' }] }, g, s, c));
});
test('credentialed directory transport rejects unsafe DNS, mutation URLs and untrusted broker origins before dispatch', async () => {
  let calls = 0; const http = createDirectoryHttp({ resolve: async () => [{ address: '127.0.0.1', family: 4 }], transport: async () => { calls++; return {}; } });
  await assert.rejects(http({ method: 'GET', url: 'https://graph.microsoft.com/v1.0/organization?$select=id', bearer: 'secret' })); assert.equal(calls, 0);
  for (const url of ['https://graph.microsoft.com/v1.0/groups/group/members', 'http://graph.microsoft.com/v1.0/organization', 'https://graph.microsoft.com@evil.example/v1.0/organization', 'https://graph.microsoft.com/v1.0/organization#leak', 'https://admin.googleapis.com/admin/directory/v1/users/reader@example.com']) assert.throws(() => directoryUrl(url, 'GET'));
  assert.throws(() => new DirectoryBrokerClient({ url: 'http://broker.example/', token: 'secret', approvalKey: Buffer.alloc(32) }));
  assert.throws(() => new DirectoryBrokerClient({ url: 'https://broker.example/foreign/', token: 'secret', approvalKey: Buffer.alloc(32) }));
});
