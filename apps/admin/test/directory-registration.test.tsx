import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { AppRecord, ConnectionRecord } from '../src/types';
import DirectoryRegistration, { directoryRegistration, emptyDirectoryRegistration, googleDirectoryConsent, isDirectoryConnection, microsoftDirectoryConsent, readDirectoryKeyFile } from '../src/components/DirectoryRegistration';
import Connections from '../src/views/Connections';

const at = Date.parse('2026-10-10T17:00:00Z'), iso = (delta: number) => new Date(at + delta).toISOString(), appId = '11111111-1111-4111-8111-111111111111', tenantId = '44444444-4444-4444-8444-444444444444', clientId = '99999999-9999-4999-8999-999999999999';
const app: AppRecord = { id: appId, slug: 'documents', name: 'Documents', description: '', kind: 'web', status: 'published', activeReleaseId: 'release-one', url: null, previewUrl: null, createdAt: iso(0), updatedAt: iso(0) };
const key = '-----BEGIN PRIVATE KEY-----\n' + 'A'.repeat(120) + '\n-----END PRIVATE KEY-----\n';
const fields = { ...emptyDirectoryRegistration(), tenantCustomerId: tenantId, clientId, clientSecret: 'dedicated-protected-secret', expiresAt: iso(30 * 86400000), consentAcknowledged: true };
const googleFields = { ...fields, tenantCustomerId: 'Ccustomer123', clientEmail: 'directory@project.iam.gserviceaccount.com', privateKey: key, delegatedSubject: 'directory-admin@customer.example' };

test('Microsoft protected registration fixes official endpoint, exact directory scopes and immutable tenant credential', () => {
  assert.deepEqual(directoryRegistration({ name: ' Dedicated directory ', provider: 'microsoft', appIds: [appId], fields }, at), { name: 'Dedicated directory', type: 'microsoft', endpoints: ['https://graph.microsoft.com/v1.0'], roots: [tenantId], capabilities: ['directory.groups.read'], appIds: [appId], expiresAt: fields.expiresAt, credentials: { tenantId, clientId, clientSecret: fields.clientSecret, consentedScopes: [...microsoftDirectoryConsent] } });
});

test('Google protected registration fixes customer identity and ignores unrelated Microsoft input fields', () => {
  const body = directoryRegistration({ name: 'Google groups', provider: 'google', appIds: [appId], fields: googleFields }, at);
  assert.deepEqual(body, { name: 'Google groups', type: 'google', endpoints: ['https://admin.googleapis.com/admin/directory/v1'], roots: ['Ccustomer123'], capabilities: ['directory.groups.read'], appIds: [appId], expiresAt: fields.expiresAt, credentials: { clientEmail: googleFields.clientEmail, privateKey: key, delegatedSubject: googleFields.delegatedSubject, consentedScopes: [...googleDirectoryConsent] } });
  assert.doesNotMatch(JSON.stringify(body), /clientSecret|Organization.Read.All|workspaceDomain|roleIds|groupIds|auth_uri|token_uri/);
});

test('directory registration requires explicit consent, exact app IDs and real bounded credential expiry', () => {
  for (const change of [{ consentAcknowledged: false }, { expiresAt: '' }, { expiresAt: iso(-1) }, { expiresAt: iso(366 * 86400000) }, { tenantCustomerId: 'customer.example' }, { clientId: 'arbitrary-name' }, { clientSecret: '' }, { clientSecret: 'A'.repeat(4097) }]) assert.throws(() => directoryRegistration({ name: 'Directory', provider: 'microsoft', appIds: [appId], fields: { ...fields, ...change } }, at));
  for (const appIds of [[], ['all'], [appId,appId]]) assert.throws(() => directoryRegistration({ name: 'Directory', provider: 'microsoft', appIds, fields }, at));
  for (const change of [{ tenantCustomerId: 'customer.example' }, { clientEmail: 'user@customer.example' }, { privateKey: '' }, { privateKey: 'secret' }, { delegatedSubject: 'not-an-email' }]) assert.throws(() => directoryRegistration({ name: 'Directory', provider: 'google', appIds: [appId], fields: { ...googleFields, ...change } }, at));
});

test('native Google service-account file extracts only exact credential identity/key and discards supplied URLs', () => {
  const native = { type: 'service_account', client_email: googleFields.clientEmail, private_key: key, token_uri: 'http://127.0.0.1/steal', auth_uri: 'https://attacker.example', project_id: 'not-used', private_key_id: 'not-used' };
  assert.deepEqual(readDirectoryKeyFile(JSON.stringify(native)), { clientEmail: googleFields.clientEmail, privateKey: key });
  assert.deepEqual(readDirectoryKeyFile(JSON.stringify(native), googleFields.clientEmail), { clientEmail: googleFields.clientEmail, privateKey: key });
  assert.deepEqual(readDirectoryKeyFile(key, googleFields.clientEmail), { clientEmail: googleFields.clientEmail, privateKey: key });
  assert.doesNotMatch(JSON.stringify(readDirectoryKeyFile(JSON.stringify(native))), /127.0.0.1|attacker|private_key_id|project_id/);
  for (const change of [{ type: 'authorized_user' }, { client_email: 'wrong@example.com' }, { private_key: 'malformed' }, { private_key: 'A'.repeat(16001) }]) assert.throws(() => readDirectoryKeyFile(JSON.stringify({ ...native, ...change })));
  assert.throws(() => readDirectoryKeyFile(JSON.stringify(native), 'other@project.iam.gserviceaccount.com'));
  assert.throws(() => readDirectoryKeyFile('A'.repeat(32769))); assert.throws(() => readDirectoryKeyFile('{bad-json}'));
});

test('Google key is never rendered and protected forms disclose per-app activation and unverified consent', () => {
  const props = { provider: 'google' as const, fields: googleFields, apps: [app], appIds: [appId], busy: false, canManage: true, onChange() {}, onApps() {}, onError() {} };
  const html = renderToStaticMarkup(createElement(DirectoryRegistration, props)); assert.match(html, /type="file"/); assert.match(html, /Google&#x27;s native downloaded service-account JSON/); assert.match(html, /only directory.groups.read/); assert.match(html, /Stored credentials do not validate consent/); assert.match(html, /Each app still needs its own approved group policy/); assert.match(html, /value is hidden/); assert.doesNotMatch(html, /BEGIN PRIVATE KEY|AAAAAAAAAAAAAAAA|dedicated-protected-secret|textarea|auth_uri|token_uri/);
  const denied = renderToStaticMarkup(createElement(DirectoryRegistration, { ...props, canManage: false })); assert.match(denied, /permanent local owner with MFA/); assert.match(denied, /type="file"[^>]*disabled=""/); assert.match(denied, /type="checkbox"[^>]*disabled=""/);
  const cleared = emptyDirectoryRegistration(); assert.equal(cleared.privateKey, ''); assert.equal(cleared.clientSecret, ''); assert.equal(cleared.clientEmail, ''); assert.equal(cleared.consentAcknowledged, false);
});

test('directory cards distinguish supported authorization from broader provider metadata without claiming health', () => {
  const connection: ConnectionRecord = { id: '33333333-3333-4333-8333-333333333333', name: 'Directory reads', type: 'microsoft', endpoints: ['https://graph.microsoft.com/v1.0'], roots: [tenantId], capabilities: ['directory.groups.read'], appIds: [appId], expiresAt: fields.expiresAt, status: 'configured', secretRef: 'protected-hidden-ref', dossier: { documentation: [], provenance: 'Metadata only', license: 'unreviewed', reviewStatus: 'pending' }, createdAt: iso(0) };
  assert.equal(isDirectoryConnection(connection), true); assert.equal(isDirectoryConnection({ ...connection, capabilities: ['email.read'] }), false); assert.equal(isDirectoryConnection({ ...connection, endpoints: ['https://attacker.example'] }), false);
  const html = renderToStaticMarkup(createElement(Connections, { apps: [app], connections: [connection], loading: false, onRetry() {}, canProvision: true })); assert.match(html, /Activate immutable groups separately in application Access/); assert.match(html, /registration verifies neither consent nor live tenant health/); assert.doesNotMatch(html, /no runtime adapter in this release|protected-hidden-ref|>Healthy<|>Configured</);
  assert.match(renderToStaticMarkup(createElement(Connections, { apps: [app], connections: [{ ...connection, capabilities: ['email.read'] }], loading: false, onRetry() {} })), /this connector type has no runtime adapter in this release/);
});
