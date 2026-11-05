import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { PortalView } from '../src/portal/Portal';
import { loadPortalCatalog, parsePortalCatalog } from '../src/portal/catalog';

const origin = 'https://apps.example.com';
function fixture() { return { schemaVersion: 1, portalOrigin: origin, listingPolicy: 'public_only', apps: [{ id: 'app-public', name: 'Public documents', description: 'Public organization resources', kind: 'web', access: 'public', url: 'https://documents.apps.example.com/' }] }; }

test('explicitly listed protected applications show sign-in guidance without platform session handoff', () => {
  const input = fixture(); input.apps[0]!.access = 'signin_required';
  assert.throws(() => parsePortalCatalog(input, origin), 'Legacy public-only schema cannot claim protected listing');
  const catalog = parsePortalCatalog({ ...input, schemaVersion: 2, listingPolicy: 'explicit_listing' }, origin);
  const html = renderToStaticMarkup(createElement(PortalView, { catalog, loading: false, onRetry() {} }));
  assert.match(html, /Sign in required/); assert.doesNotMatch(html, /Public access|\/auth\/login/);
  assert.equal(catalog.apps[0]!.access, 'signin_required');
});

test('public portal renders only the minimal supplied catalog with no administrative navigation or sign-in flow', () => {
  const catalog = parsePortalCatalog(fixture(), origin);
  const html = renderToStaticMarkup(createElement(PortalView, { catalog, loading: false, onRetry() {} }));
  assert.match(html, /Public documents/);
  assert.match(html, /href="https:\/\/documents.apps.example.com\/"/);
  assert.match(html, /Some applications are hidden from this directory/);
  assert.match(html, /configured company SSO or local account/);
  assert.doesNotMatch(html, /\/auth\/login|\/api\/v1|Conversation|Connections|Model budget|Create application|Published releases/);
});

test('empty and unavailable portal states do not invent apps or imply signed-in access', () => {
  const catalog = parsePortalCatalog({ ...fixture(), apps: [] }, origin);
  const empty = renderToStaticMarkup(createElement(PortalView, { catalog, loading: false, onRetry() {} }));
  assert.match(empty, /No applications are listed yet/);
  assert.doesNotMatch(empty, /portal-card"/);
  const unavailable = renderToStaticMarkup(createElement(PortalView, { loading: false, error: 'Application directory unavailable', onRetry() {} }));
  assert.match(unavailable, /role="alert"/);
  assert.doesNotMatch(unavailable, /public app<|href="https:/);
});

test('catalog validation refuses private access, foreign origins, previews, unsafe URL destinations and duplicate cards', () => {
  for (const access of ['sso', 'local', 'authorized', undefined]) {
    const catalog = fixture(); catalog.apps[0]!.access = access as string;
    assert.throws(() => parsePortalCatalog(catalog, origin));
  }
  for (const url of ['javascript:alert(1)', 'http://documents.apps.example.com/', 'https://documents.evil.example/', 'https://preview-documents.apps.example.com/', 'https://nested.documents.apps.example.com/', 'https://documents.apps.example.com:444/', 'https://user:password@documents.apps.example.com/', 'https://documents.apps.example.com/?token=secret', 'https://documents.apps.example.com/auth/login', 'https://admin.apps.example.com/']) {
    const catalog = fixture(); catalog.apps[0]!.url = url;
    assert.throws(() => parsePortalCatalog(catalog, origin));
  }
  assert.throws(() => parsePortalCatalog(fixture(), 'https://admin.example.com'));
  assert.throws(() => parsePortalCatalog({ ...fixture(), listingPolicy: 'all_apps' }, origin));
  const duplicate = fixture(); duplicate.apps.push({ ...duplicate.apps[0]! });
  assert.throws(() => parsePortalCatalog(duplicate, origin));
});

test('portal request omits cookies and authorization and refuses redirect-based session handoff', async () => {
  let calls = 0;
  const transport: typeof fetch = async (url, options) => {
    calls++;
    assert.equal(url, '/api/public/v1/apps');
    assert.equal(options?.credentials, 'omit');
    assert.equal(options?.cache, 'no-store');
    assert.equal(options?.redirect, 'error');
    const headers = new Headers(options?.headers);
    assert.equal(headers.get('authorization'), null);
    assert.equal(headers.get('cookie'), null);
    return new Response(JSON.stringify(fixture()), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const catalog = await loadPortalCatalog(origin, undefined, transport);
  assert.equal(calls, 1); assert.equal(catalog.apps.length, 1);
  await assert.rejects(loadPortalCatalog(origin, undefined, async () => new Response('private database credential failure', { status: 503 })), error => error instanceof Error && !error.message.includes('credential failure'));
  await assert.rejects(loadPortalCatalog(origin, undefined, async () => new Response('<html>Admin login</html>', { status: 200, headers: { 'content-type': 'text/html' } })));
});

test('portal strips unexpected fields and renders catalog descriptions as escaped text', () => {
  const input = fixture(); input.apps[0]!.description = '<script>stealSecrets()</script>';
  const catalog = parsePortalCatalog({ ...input, apps: [{ ...input.apps[0], secretRef: 'must-not-appear', roles: ['platform-owner'], releaseId: 'private-release' }] }, origin);
  assert.deepEqual(Object.keys(catalog.apps[0]!).sort(), ['access', 'description', 'id', 'kind', 'name', 'url']);
  const html = renderToStaticMarkup(createElement(PortalView, { catalog, loading: false, onRetry() {} }));
  assert.match(html, /&lt;script&gt;stealSecrets\(\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>|must-not-appear|platform-owner|private-release/);
});
