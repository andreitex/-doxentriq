import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { filesystemArtifactHash } from '../../../packages/core/src/connector-adapters.ts';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import type { AppRecord, ConnectionRecord } from '../src/types';
import { FilesystemDispatchUncertain, FilesystemReviewContent, configureFilesystemReview, filesystemRegistration, validateFilesystemApproval, validateFilesystemOperation, validateFilesystemSources, type FilesystemApproval, type FilesystemReviewScope, type FilesystemSource } from '../src/components/FilesystemProvision';
import FilesystemRegistration from '../src/components/FilesystemRegistration';
import Connections from '../src/views/Connections';

const at = Date.parse('2026-10-10T15:00:00Z'), iso = (delta: number) => new Date(at + delta).toISOString();
const app: AppRecord = { id: 'app-one', slug: 'files-app', name: 'Files App', description: '', kind: 'web', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt: iso(0), updatedAt: iso(0) };
const source: FilesystemSource = { sourceRootId: 'company-import', sourceEvidenceHash: 'a'.repeat(64), sourceExpiresAt: iso(30 * 86400000), templateSourceHash: 'b'.repeat(64), templateImage: `registry:5000/connectors/filesystem@sha256:${'c'.repeat(64)}`, qualificationReportHash: 'd'.repeat(64) };
const connection: ConnectionRecord = { id: 'connection-one', name: 'Reviewed documents', type: 'filesystem', endpoints: ['filesystem://company-import'], roots: ['documents'], capabilities: ['files.list','files.read'], appIds: [app.id], expiresAt: source.sourceExpiresAt, status: 'needs_credentials', secretRef: null, dossier: { documentation: [], provenance: 'Registration metadata only.', license: 'unreviewed', reviewStatus: 'pending' }, createdAt: iso(0) };
const scope: FilesystemReviewScope = { connection, appId: app.id, source, root: 'documents', accessExpiresAt: iso(86400000) };
const artifact = filesystemArtifactHash({ ...source, appId: app.id, connectionId: connection.id, type: 'filesystem', root: scope.root, accessExpiresAt: scope.accessExpiresAt, registryHash: hashArtifact(connection) });
const approval: FilesystemApproval = { id: 'approval-one', appId: app.id, connectionId: connection.id, action: 'approve_readonly_filesystem', artifactHash: artifact, impact: ['Allow Files App to list and read only company-import.', 'No write permissions; retain all source data.'], createdAt: iso(0), expiresAt: iso(300000), approvedAt: null, approvedBy: null, consumedAt: null };
const configured = { operationId: 'operation-one', approvalId: approval.id, appId: app.id, connectionId: connection.id, artifactHash: artifact, type: 'filesystem', status: 'configured', scopeHash: artifact, liveRootVerified: false, detail: 'Exact scope configured. Live check still required.' };

test('filesystem registration binds one selected company source and emits no host paths or credentials', () => {
  const body = filesystemRegistration({ name: ' Reviewed documents ', appId: app.id, source, root: 'documents', expiresAt: iso(86400000) }, at);
  assert.deepEqual(body, { name: 'Reviewed documents', type: 'filesystem', endpoints: ['filesystem://company-import'], roots: ['documents'], capabilities: ['files.list','files.read'], appIds: [app.id], expiresAt: iso(86400000) });
  assert.doesNotMatch(JSON.stringify(body), /credentials|secretRef|sourcePath|\/data\/|sourceEvidenceHash/);
  for (const root of ['/etc', '../documents', 'C:\\data', 'docs/nested', 'documents with spaces']) assert.throws(() => filesystemRegistration({ name: 'Files', appId: app.id, source, root, expiresAt: iso(86400000) }, at));
  for (const expiresAt of [iso(-1), iso(91 * 86400000), 'malformed']) assert.throws(() => filesystemRegistration({ name: 'Files', appId: app.id, source, root: 'documents', expiresAt }, at));
});

test('source selection rejects foreign, duplicate, expired and unqualified catalog responses', () => {
  assert.deepEqual(validateFilesystemSources({ schemaVersion: 1, appId: app.id, sources: [source] }, app.id, at), [source]);
  for (const value of [{ schemaVersion: 1, appId: 'other-app', sources: [source] }, { schemaVersion: 1, appId: app.id, sources: [source, source] }, ...[{ sourceExpiresAt: iso(-1) }, { sourceRootId: '/etc' }, { templateImage: 'python:latest' }, { qualificationReportHash: '' }, { sourcePath: '/data/imports/company-import' }].map(change => ({ schemaVersion: 1, appId: app.id, sources: [{ ...source, ...change }] }))]) assert.throws(() => validateFilesystemSources(value, app.id, at));
});

test('browser review recomputes the exact backend artifact and rejects altered source, registry, app and expiry', async () => {
  assert.equal((await validateFilesystemApproval(approval, scope, at)).artifactHash, artifact);
  for (const changed of [{ ...scope, source: { ...source, sourceEvidenceHash: 'f'.repeat(64) } }, { ...scope, connection: { ...connection, capabilities: ['files.list','files.read','files.write'] } }, { ...scope, connection: { ...connection, secretRef: 'protected-ref' } }, { ...scope, appId: 'other-app' }, { ...scope, accessExpiresAt: iso(2 * 86400000) }]) await assert.rejects(validateFilesystemApproval(approval, changed, at));
  for (const change of [{ artifactHash: 'f'.repeat(64) }, { action: 'approve_readonly_samba' }, { appId: 'other-app' }, { consumedAt: iso(0) }, { expiresAt: iso(-1) }]) await assert.rejects(validateFilesystemApproval({ ...approval, ...change }, scope, at));
});

test('filesystem configuration submits the exact approval before its one bound provision request', async () => {
  const calls: { path: string; body: unknown }[] = [];
  const result = await configureFilesystemReview(scope, approval, async (path, options) => { calls.push({ path, body: options.body }); return calls.length === 1 ? { approval: { ...approval, approvedAt: iso(0), approvedBy: 'owner-one' } } : { operation: configured }; }, () => at);
  assert.deepEqual(calls, [{ path: '/adapters/approvals/approval-one/approve', body: { artifactHash: artifact } }, { path: '/connections/connection-one/filesystem/provision', body: { approvalId: approval.id } }]);
  assert.equal(result.status, 'configured'); assert.equal(result.liveRootVerified, false);
});

test('malformed approval confirmation or expired review prevents provision dispatch', async () => {
  for (const change of [{ id: 'other-review' }, { createdAt: iso(-1) }, { expiresAt: iso(299999) }, { artifactHash: 'f'.repeat(64) }, { approvedBy: null }, { approvedAt: iso(1) }]) { let calls = 0; await assert.rejects(configureFilesystemReview(scope, approval, async () => { calls++; return { approval: { ...approval, approvedAt: iso(0), approvedBy: 'owner-one', ...change } }; }, () => at)); assert.equal(calls, 1); }
  let calls = 0, clock = at; await assert.rejects(configureFilesystemReview(scope, approval, async () => { calls++; clock = at + 300001; return { approval: { ...approval, approvedAt: iso(0), approvedBy: 'owner-one' } }; }, () => clock)); assert.equal(calls, 1);
});

test('uncertain or cross-scope provision remains an inspection outcome without automatic retry', async () => {
  for (const outcome of ['lost', 'foreign', 'fake-live']) { let calls = 0; await assert.rejects(configureFilesystemReview(scope, approval, async () => { calls++; if (calls === 1) return { approval: { ...approval, approvedAt: iso(0), approvedBy: 'owner-one' } }; if (outcome === 'lost') throw new Error('Synthetic transport loss'); return { operation: { ...configured, ...(outcome === 'foreign' ? { appId: 'other-app' } : { liveRootVerified: true }) } }; }, () => at), FilesystemDispatchUncertain); assert.equal(calls, 2); }
  assert.throws(() => validateFilesystemOperation({ ...configured, scopeHash: 'f'.repeat(64) }));
});

test('filesystem protected form displays only logical source selection and truthful qualification state', () => {
  const noop = () => {}; const props = { apps: [app], appId: app.id, sourceId: source.sourceRootId, root: 'documents', expiresAt: '2026-10-11T18:00', sources: [source], loading: false, busy: false, canProvision: true, onApp: noop, onSource: noop, onRoot: noop, onExpiry: noop, onRefresh: noop };
  const html = renderToStaticMarkup(createElement(FilesystemRegistration, props)); assert.match(html, /company-import/); assert.match(html, /files.list and files.read/); assert.match(html, /Host paths and credentials are never entered here/); assert.doesNotMatch(html, /type="password"|sourcePath|\/mnt\/|\/data\/|https:\/\/api/);
  const unavailable = renderToStaticMarkup(createElement(FilesystemRegistration, { ...props, sources: [] })); assert.match(unavailable, /No qualified source is available/); assert.match(unavailable, /cannot activate an unqualified adapter/);
  const denied = renderToStaticMarkup(createElement(FilesystemRegistration, { ...props, canProvision: false })); assert.match(denied, /permanent local owner with MFA/); assert.match(denied, /select required="" disabled=""/);
  const evidence = renderToStaticMarkup(createElement(FilesystemReviewContent, { approval, scope })); assert.match(evidence, new RegExp(artifact)); assert.match(evidence, /No write permissions/); assert.match(evidence, /Configuration is not live access evidence/); assert.doesNotMatch(evidence, /sourcePath|\/data\/imports|protected-ref/);
});

test('filesystem cards distinguish registry metadata, owner-only configuration and live verification', () => {
  const props = { apps: [app], connections: [connection], loading: false, onRetry() {} };
  const owner = renderToStaticMarkup(createElement(Connections, { ...props, canProvision: true })); assert.match(owner, /Not required · logical company source only/); assert.match(owner, /Registration only until company source\/image qualification/); assert.match(owner, /actual read-only mount and contained listing during app preview/); assert.match(owner, /Review &amp; configure filesystem scope/); assert.doesNotMatch(owner, />Configured<|Root verified|no runtime adapter in this release/);
  const sso = renderToStaticMarkup(createElement(Connections, props)); assert.match(sso, /Sign in as the permanent local owner with MFA/); assert.match(sso, /disabled=""[^>]*><svg[^]*?Review &amp; configure filesystem scope/);
});
