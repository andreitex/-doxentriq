import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createVerifier, loadAuth } from '../src/auth.mjs';
import { SambaConnector, safeRelativePath } from '../src/connector.mjs';
import { DmsService } from '../src/domain.mjs';
import { handleMcp } from '../src/mcp.mjs';
import { FileStorage } from '../src/storage.mjs';
import { createApplication } from '../src/http.mjs';
import { loadTls } from '../src/tls.mjs';
import { MemoryRepository, MemoryStorage } from './support.mjs';

const issuer = 'https://identity.example/realms/app-dms-a', audience = 'dms-a', appId = 'dms-a';
const key = await generateKeyPair('ES256'), jwk = await exportJWK(key.publicKey); jwk.kid = 'fixture';
const verify = createVerifier({ issuer, audience, appId, jwks: { keys: [jwk] } });
async function token(claims = {}, aud = audience, iss = issuer, expiry = '5m') { return new SignJWT({ app_id: appId, resource_access: { [audience]: { roles: ['dms.read', 'dms.search'] } }, ...claims }).setProtectedHeader({ alg: 'ES256', kid: 'fixture' }).setSubject('reader').setIssuer(iss).setAudience(aud).setIssuedAt().setExpirationTime(expiry).sign(key.privateKey); }
test('signed access tokens require exact issuer, audience, app identity and unexpired lifetime', async () => {
  assert.equal((await verify('Bearer ' + await token())).appId, appId);
  for (const bad of [await token({}, 'other-app'), await token({}, audience, 'https://wrong.example'), await token({ app_id: 'other-app' }), await token({ app_id: undefined }), await token({}, audience, issuer, '-1h')]) await assert.rejects(verify('Bearer ' + bad));
  await assert.rejects(verify('Bearer ' + await token({}, audience), 'mcp'));
  const realmOwner = await verify('Bearer ' + await token({ realm_access: { roles: ['dms.admin'] }, resource_access: {} })); assert.deepEqual(realmOwner.roles, []);
});

test('local signing-key refresh takes effect without restart and stale or foreign key evidence fails closed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-dms-jwks-')), file = join(root, 'jwks.json');
  const makeBundle = (publicKey, kid) => {
    const keys = [{ ...publicKey, kid, alg: 'ES256', use: 'sig' }].map(key => Object.fromEntries(Object.keys(key).sort().map(name => [name, key[name]])));
    const now = Date.now(); return { keys, autosoft: { schemaVersion: 1, appId, resourceId: appId, issuer, checkedAt: new Date(now).toISOString(), validUntil: new Date(now + 3600000).toISOString(), keysHash: createHash('sha256').update(JSON.stringify(keys)).digest('hex') } };
  };
  try {
    await writeFile(file, JSON.stringify(makeBundle(jwk, 'fixture')));
    const auth = await loadAuth({ APP_ID: appId, OIDC_ISSUER: issuer, OIDC_AUDIENCE: audience, OIDC_JWKS_FILE: file, OIDC_JWKS_RESOURCE_ID: appId });
    assert.equal((await auth.verify('Bearer ' + await token())).id, 'reader');
    const rotated = await generateKeyPair('ES256'), publicKey = await exportJWK(rotated.publicKey), next = makeBundle(publicKey, 'next');
    const nextToken = await new SignJWT({ app_id: appId, resource_access: { [audience]: { roles: ['dms.read'] } } }).setProtectedHeader({ alg: 'ES256', kid: 'next' }).setSubject('reader-next').setIssuer(issuer).setAudience(audience).setIssuedAt().setExpirationTime('5m').sign(rotated.privateKey);
    await writeFile(file, JSON.stringify(next));
    assert.equal((await auth.verify('Bearer ' + nextToken)).id, 'reader-next');
    await assert.rejects(auth.verify('Bearer ' + await token()), error => error.status === 401);
    for (const mutate of [value => { value.autosoft.issuer = 'https://foreign.example'; }, value => { value.autosoft.resourceId = `${appId}_preview`; }, value => { value.autosoft.appId = 'other-app'; }, value => { value.autosoft.keysHash = '0'.repeat(64); }, value => { value.autosoft.checkedAt = new Date(Date.now() - 7200000).toISOString(); value.autosoft.validUntil = new Date(Date.now() - 3600000).toISOString(); }, value => { value.autosoft.validUntil = new Date(Date.now() + 7200000).toISOString(); }, value => { value.keys[0].d = 'private-material'; }, value => { delete value.autosoft; }]) {
      const invalid = structuredClone(next); mutate(invalid); await writeFile(file, JSON.stringify(invalid)); await assert.rejects(auth.verify('Bearer ' + nextToken), error => error.status === 503);
    }
    await writeFile(file, JSON.stringify(next)); assert.equal((await auth.verify('Bearer ' + nextToken)).id, 'reader-next');
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('MCP requires separate audience, matching app client permission, and matching tool scope', async () => {
  const service = new DmsService({ appId, repository: new MemoryRepository(), storage: new MemoryStorage() });
  const message = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'search_documents', arguments: { query: '' } } };
  const principal = await verify('Bearer ' + await token({ scope: 'dms.search' }, `${appId}:mcp`), 'mcp');
  assert.equal((await handleMcp({ message, principal, service })).result.isError, false);
  await assert.rejects(handleMcp({ message, principal: { ...principal, scopes: [] }, service }), error => error.status === 403);
  await assert.rejects(handleMcp({ message, principal: { ...principal, roles: [] }, service }), error => error.status === 403);
  await assert.rejects(handleMcp({ message, principal: { ...principal, appId: 'other' }, service }), error => error.status === 403);
  await assert.rejects(handleMcp({ message, principal, service, protocolHeader: 'unsupported' }), error => error.status === 400);
});
test('Samba adapter rejects traversal, unauthorized app/operations and redirects', async () => {
  for (const path of ['../secret', '/etc/passwd', 'folder/../secret', 'C:\\secret', 'folder\\secret', 'folder//file', '%2e%2e/secret', 'folder/%252e%252e/secret']) assert.throws(() => safeRelativePath(path));
  const registry = { connections: [{ id: 'finance', type: 'samba', reviewStatus: 'approved', appIds: [appId], roots: ['finance-root'], capabilities: ['files.list', 'files.read'], adapterUrl: 'https://connector.example' }] };
  let calls = 0;
  const connector = new SambaConnector(registry, 'test-only-adapter-token', async (url, input) => { calls++; assert.equal(input.redirect, 'error'); assert.deepEqual(JSON.parse(input.body), { appId, root: 'finance-root', path: 'reports' }); return new Response(JSON.stringify({ entries: [{ name: 'report.pdf', kind: 'file' }] })); });
  assert.equal((await connector.perform({ appId, connectionId: 'finance', operation: 'list', relativePath: 'reports' })).entries.length, 1);
  await assert.rejects(connector.perform({ appId: 'other', connectionId: 'finance', operation: 'list', relativePath: '' }), error => error.status === 403);
  await assert.rejects(connector.perform({ appId, connectionId: 'finance', operation: 'write', relativePath: '' }), error => error.status === 403);
  await assert.rejects(connector.perform({ appId, connectionId: 'finance', operation: 'read', relativePath: '../secret' }), error => error.status === 400);
  assert.equal(calls, 1);
});
test('filesystem adapter uses only its sealed app and read-only scope, never a requested host path', async () => {
  let calls = 0;
  const record = { id: 'source', type: 'filesystem', reviewStatus: 'approved', appIds: [appId], roots: ['imports'], capabilities: ['files.list', 'files.read'], adapterUrl: 'https://as-filesystem-fixture:8443' };
  const connector = new SambaConnector({ schemaVersion: 1, connections: [record] }, 'fixture-scoped-token', async (url, input) => {
    calls++; assert.equal(url.origin, record.adapterUrl); assert.equal(input.redirect, 'error'); assert.deepEqual(JSON.parse(input.body), { appId, root: 'imports', path: 'invoices/report.pdf' });
    return new Response(JSON.stringify({ contentBase64: Buffer.from('synthetic-content').toString('base64'), mime: 'application/pdf' }));
  });
  assert.equal(Buffer.from((await connector.perform({ appId, connectionId: 'source', operation: 'read', relativePath: 'invoices/report.pdf' })).contentBase64, 'base64').toString(), 'synthetic-content');
  for (const input of [{ appId: 'foreign', operation: 'read', relativePath: '' }, { appId, operation: 'write', relativePath: '' }, { appId, operation: 'read', relativePath: 'C:/host/secret' }, { appId, operation: 'read', relativePath: '/etc/passwd' }, { appId, operation: 'read', relativePath: 'bad\u007fname' }]) await assert.rejects(connector.perform({ connectionId: 'source', ...input }));
  record.type = 'email'; await assert.rejects(connector.perform({ appId, connectionId: 'source', operation: 'list', relativePath: '' }), error => error.status === 403);
  assert.equal(calls, 1);
});

test('immutable filesystem storage enforces quota and integrity without erasing versions', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-dms-')); try {
    const storage = new FileStorage(root, 8, 8); await storage.initialize();
    const first = await storage.put(Buffer.from('first')); assert.equal((await storage.read(first.blobId, first.checksum)).toString(), 'first');
    await assert.rejects(storage.put(Buffer.from('more')), error => error.status === 507);
    await assert.rejects(storage.read(first.blobId, '0'.repeat(64)), /integrity/);
    await assert.rejects(storage.read('../outside', first.checksum));
    await storage.initialize(); assert.equal((await storage.read(first.blobId, first.checksum)).toString(), 'first');
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('HTTP endpoint rejects browser Origin injection and unauthenticated access; readiness is side-effect free', async () => {
  const repository = new MemoryRepository(), service = new DmsService({ appId, repository, storage: new MemoryStorage() });
  const server = createApplication({ service, verify, publicConfig: { appId, issuer, clientId: audience }, origin: 'https://dms.example', allowInsecureHttp: true });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(base + '/healthz')).status, 200); assert.equal(repository.records.length, 0);
    assert.equal((await fetch(base + '/api/documents')).status, 401);
    assert.equal((await fetch(base + '/api/documents', { headers: { authorization: 'Bearer ' + await token(), origin: 'https://evil.example' } })).status, 403);
    assert.equal((await fetch(base + '/api/documents', { headers: { authorization: 'Bearer ' + await token(), origin: 'https://dms.example' } })).status, 200);
    assert.equal((await fetch(base + '/mcp', { headers: { authorization: 'Bearer ' + await token({ scope: 'dms.search' }, `${appId}:mcp`) } })).status, 405);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('production app TLS requires a certificate/key pair and only explicit local tests can use HTTP', async () => {
  await assert.rejects(loadTls({ NODE_ENV: 'production' }), /requires app-scoped TLS/);
  await assert.rejects(loadTls({ APP_TLS_CERT_FILE: 'certificate-only' }), /supplied together/);
  await assert.rejects(loadTls({ APP_TLS_KEY_FILE: 'key-only', NODE_ENV: 'test' }), /supplied together/);
  assert.equal(await loadTls({ NODE_ENV: 'test' }), undefined);
  assert.equal(await loadTls({ NODE_ENV: 'local' }), undefined);
  assert.throws(() => createApplication({ publicConfig: { issuer }, origin: 'https://dms.example' }), /TLS is required/);
  assert.throws(() => createApplication({ publicConfig: { issuer }, origin: 'https://dms.example', tls: { cert: 'without-key' } }), /supplied together/);
});
