import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import Connections from '../src/views/Connections';
import type { AppRecord, ConnectionRecord } from '../src/types';

const now = new Date().toISOString(), app: AppRecord = { id: 'app-id', slug: 'documents', name: 'Documents', description: '', kind: 'web', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt: now, updatedAt: now };
const connection: ConnectionRecord = { id: 'connection-id', name: 'Read-only archive', type: 'samba', endpoints: ['smb://10.23.23.20/Documents'], roots: ['documents'], capabilities: ['files.list', 'files.read'], appIds: [app.id], secretRef: 'connection:credential-ref', expiresAt: null, status: 'configured', dossier: { documentation: [], provenance: 'Awaiting scope review.', license: 'unreviewed', reviewStatus: 'pending' }, createdAt: now };
test('Samba setup explicitly distinguishes registered credentials from runtime scope and live share qualification', () => {
  const html = renderToStaticMarkup(createElement(Connections, { apps: [app], selectedApp: app, connections: [connection], loading: false, onRetry() {}, canProvision: true }));
  assert.match(html, /Read-only archive: protected runtime scope/); assert.match(html, /real encrypted share probe during app preview/); assert.match(html, /Review &amp; configure Samba scope/); assert.match(html, /Stored · value hidden/); assert.doesNotMatch(html, /liveShareVerified.*true|Share verified|password-value|credential-ref/);
});
test('ordinary platform administrators see owner-only protected Samba provisioning guidance', () => {
  const html = renderToStaticMarkup(createElement(Connections, { apps: [app], selectedApp: app, connections: [connection], loading: false, onRetry() {}, canProvision: false }));
  assert.match(html, /Sign in as the permanent local owner with MFA/); assert.match(html, /disabled=""[^>]*><svg[^]*?Review &amp; configure Samba scope/);
});

test('integration registrations and stored credentials never claim unsupported runtime access or automatic provider research', () => {
  const unsupported = ['microsoft', 'google', 'email', 'stripe', 'efactura', 'rest', 'mcp'] as const;
  const records = unsupported.map(type => ({ ...connection, id: `registered-${type}`, name: `Requested ${type}`, type }));
  const html = renderToStaticMarkup(createElement(Connections, { apps: [app], connections: records, loading: false, onRetry() {} }));
  assert.equal((html.match(/Registration only: this connector type has no runtime adapter in this release/g) ?? []).length, unsupported.length);
  assert.equal((html.match(/Credentials stored/g) ?? []).length, unsupported.length);
  assert.match(html, /Registered application scope/); assert.match(html, /Requested capabilities/); assert.match(html, /company implementation and review/);
  assert.doesNotMatch(html, />Configured<|AutoSoft can research|Review &amp; configure Samba scope/);
  const empty = renderToStaticMarkup(createElement(Connections, { apps: [app], connections: [], loading: false, onRetry() {} }));
  assert.match(empty, /Ask your company operator/); assert.doesNotMatch(empty, /AutoSoft can research/);
  const noCredentials = renderToStaticMarkup(createElement(Connections, { apps: [app], connections: [{ ...records[0]!, secretRef: null, status: 'needs_credentials' }], loading: false, onRetry() {} }));
  assert.match(noCredentials, />Registered</); assert.doesNotMatch(noCredentials, /Credentials stored/);
});
