import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createDirectoryVerifier } from '../src/auth.mjs';
import { authorize, HttpError } from '../src/domain.mjs';
import { handleMcp } from '../src/mcp.mjs';
import { createApplication } from '../src/http.mjs';
const appId = randomUUID(), subject = randomUUID(), audience = `app-${appId}`, url = `https://control:3000/api/public/v1/apps/${appId}/directory/authorize`;
const base = { id: subject, appId, roles: [], scopes: [] };
const result = () => ({ appId, subject, audience, permissions: ['dms.read'], policyHash: 'a'.repeat(64), checkedAt: new Date().toISOString(), validUntil: new Date(Date.now() + 60000).toISOString() });
test('DMS consults exact company directory authorization per request and does not retain group grants', async () => {
  let calls = 0, permissions = ['dms.read'];
  const verify = createDirectoryVerifier({ appId, audience, url, verify: async () => base, fetchImpl: async (endpoint, options) => { calls++; assert.equal(endpoint, url); assert.equal(options.headers.authorization, 'Bearer synthetic-app-token'); assert.equal(options.redirect, 'error'); assert.deepEqual(JSON.parse(options.body), { target: 'api' }); return new Response(JSON.stringify({ ...result(), permissions }), { headers: { 'content-type': 'application/json' } }); } });
  const first = await verify('Bearer synthetic-app-token'); authorize(first, appId, 'dms.read'); assert.throws(() => authorize(first, appId, 'dms.write'), error => error.status === 403);
  permissions = []; const second = await verify('Bearer synthetic-app-token'); assert.throws(() => authorize(second, appId, 'dms.read'), error => error.status === 403); assert.deepEqual(base.roles, []); assert.equal(calls, 2);
});
test('configured directory outage, wrong app/subject/audience, foreign privileges and expired evidence deny all app grants', async () => {
  const changes = [{ appId: randomUUID() }, { subject: randomUUID() }, { audience: 'autosoft-admin' }, { permissions: ['platform-owner'] }, { permissions: ['dms.read', 'dms.read'] }, { policyHash: 'missing' }, { validUntil: new Date(Date.now() - 1).toISOString() }, { validUntil: new Date(Date.now() + 3600000).toISOString() }, { checkedAt: new Date(Date.now() - 120000).toISOString() }];
  for (const change of changes) {
    const verify = createDirectoryVerifier({ appId, audience, url, verify: async () => ({ ...base, roles: ['dms.admin'] }), fetchImpl: async () => new Response(JSON.stringify({ ...result(), ...change })) });
    await assert.rejects(verify('Bearer synthetic'), error => error.status === 503);
  }
  const unavailable = createDirectoryVerifier({ appId, audience, url, verify: async () => ({ ...base, roles: ['dms.admin'] }), fetchImpl: async () => new Response('unavailable', { status: 503 }) }); await assert.rejects(unavailable('Bearer synthetic'), error => error.status === 503);
  for (const endpoint of ['https://evil.example/authorize', `http://control:3000/api/public/v1/apps/${appId}/directory/authorize`, `https://control:3000/api/public/v1/apps/${randomUUID()}/directory/authorize`, url + '?secret=leak']) assert.throws(() => createDirectoryVerifier({ appId, audience, url: endpoint, verify: async () => base }));
});
test('directory MCP grants remain constrained by the independently signed MCP audience and read/search scopes', async () => {
  let scopes = [], targetSeen;
  const verify = createDirectoryVerifier({ appId, audience, url, verify: async (_authorization, target) => { targetSeen = target; return { ...base, scopes }; }, fetchImpl: async () => new Response(JSON.stringify({ ...result(), audience: `${appId}:mcp`, permissions: ['dms.read', 'dms.search'] })) });
  const message = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'search_documents', arguments: { query: '' } } }; let reads = 0;
  const service = { appId, search: async () => { reads++; return []; } };
  const denied = await verify('Bearer synthetic-mcp', 'mcp'); await assert.rejects(handleMcp({ message, principal: denied, service, protocolHeader: '2025-11-25' }), error => error.status === 403); assert.equal(reads, 0); assert.equal(targetSeen, 'mcp');
  scopes = ['dms.read', 'dms.search']; const allowed = await handleMcp({ message, principal: await verify('Bearer synthetic-mcp', 'mcp'), service, protocolHeader: '2025-11-25' }); assert.ok(!allowed.error && !allowed.result?.isError); assert.equal(reads, 1);
});
test('browser session permissions come from the verified backend and disappear after revocation or unavailable authorization', async () => {
  let roles = ['dms.read', 'dms.write'], unavailable = false;
  const application = createApplication({ service: {}, origin: 'http://127.0.0.1', publicConfig: { issuer: 'https://identity.example/realms/app' }, allowInsecureHttp: true, verify: async authorization => { if (authorization !== 'Bearer synthetic') throw new HttpError(401, 'Signed app token required'); if (unavailable) throw new HttpError(503, 'Directory authorization unavailable'); return { ...base, roles, directoryAuthorization: { validUntil: new Date(Date.now() + 30000).toISOString() } }; } });
  await new Promise(resolve => application.listen(0, '127.0.0.1', resolve)); const endpoint = `http://127.0.0.1:${application.address().port}/api/session`;
  try {
    assert.equal((await fetch(endpoint)).status, 401);
    const first = await (await fetch(endpoint, { headers: { authorization: 'Bearer synthetic' } })).json(); assert.deepEqual(first.principal.roles, ['dms.read', 'dms.write']); assert.equal(first.principal.appId, appId); assert.ok(Date.parse(first.principal.permissionsValidUntil) - Date.now() <= 30000);
    roles = []; const revoked = await (await fetch(endpoint, { headers: { authorization: 'Bearer synthetic' } })).json(); assert.deepEqual(revoked.principal.roles, []);
    unavailable = true; assert.equal((await fetch(endpoint, { headers: { authorization: 'Bearer synthetic' } })).status, 503);
  } finally { await new Promise(resolve => application.close(resolve)); }
});
