import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { releaseArtifactHash } from '../../../packages/core/src/index.ts';
import { slugSchema } from '../../../packages/core/src/schemas.ts';
import type { AppRecord, ReleaseRecord } from '../../../packages/core/src/types.ts';
import type { Config } from '../src/config.ts';
import { createServer } from '../src/server.ts';
import { JsonStore } from '../src/store.ts';

async function setup() {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-portal-')), dist = join(root, 'dist'); await mkdir(join(dist, 'assets'), { recursive: true }); await mkdir(join(dist, '.vite'));
  const files = { 'index.html': '<html>PRIVATE_ADMIN_ENTRY</html>', 'portal.html': '<html>PUBLIC_PORTAL_ENTRY<script src="/portal-assets/portal.js"></script></html>', 'assets/portal.js': 'export const portal = true;', 'assets/shared.js': 'export const sharedRuntime = true;', 'assets/portal.css': 'body { color: green }', 'assets/admin.js': 'export const PRIVATE_ADMIN_BUNDLE = true;' };
  for (const [path, content] of Object.entries(files)) await writeFile(join(dist, path), content);
  await writeFile(join(dist, '.vite', 'manifest.json'), JSON.stringify({ 'portal.html': { file: 'assets/portal.js', imports: ['_shared.js'], css: ['assets/portal.css'] }, '_shared.js': { file: 'assets/shared.js' }, 'index.html': { file: 'assets/admin.js' } }));
  const store = new JsonStore(); await store.initialize(); const now = new Date().toISOString();
  const app: AppRecord = { id: randomUUID(), slug: 'document-library', name: 'Document library', description: 'Public read-only catalog', kind: 'web', status: 'published', activeReleaseId: null, url: 'https://untrusted-stored-address.invalid/', previewUrl: null, createdAt: now, updatedAt: now };
  const release: ReleaseRecord = { id: randomUUID(), appId: app.id, version: '0.1.0', summary: 'Public documents', artifactHash: '', commit: 'a'.repeat(40), images: [`registry.test/app@sha256:${'b'.repeat(64)}`], schemaVersion: 1, compatibleSchemaMin: 1, compatibleSchemaMax: 1, baseReleaseId: null, status: 'published', evidence: { status: 'passed', checkedAt: now, feedUpdatedAt: now, findings: [], checks: ['dependencies', 'build', 'application_tests', 'security', 'image_packaging', 'preview', 'migration_rehearsal', 'acceptance'].map(name => ({ name, passed: true, detail: 'Fixture verified' })) }, migrations: [], createdAt: now, publishedAt: now };
  release.artifactHash = releaseArtifactHash(release); app.activeReleaseId = release.id;
  const privateApp = { ...app, id: randomUUID(), slug: 'private-app', name: 'Hidden private app' }, privateRelease = { ...release, id: randomUUID(), appId: privateApp.id }; privateRelease.artifactHash = releaseArtifactHash(privateRelease); privateApp.activeReleaseId = privateRelease.id;
  await store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; state.apps[privateApp.id] = privateApp; state.releases[privateRelease.id] = privateRelease; state.secrets['not-public'] = 'not-exposed-ciphertext'; });
  const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: root, workspaceDir: join(root, 'workspaces'), oidcClientId: 'test', secretKey: Buffer.alloc(32, 42), requestLimitUsd: 1, monthlyLimitUsd: 5, adminDist: dist, appsOrigin: 'https://apps.example.test:8443' };
  let catalog: unknown = { apps: [{ appId: app.id, releaseId: release.id, artifactHash: release.artifactHash, images: release.images, auth: 'public' }] };
  const server = await createServer(config, store, { publicCatalog: async () => catalog as { apps: { appId: string; releaseId: string; artifactHash: string; images: string[]; auth: 'public' }[] } });
  const close = async () => { await server.close(); await store.close(); await rm(root, { recursive: true, force: true }); }; return { root, store, server, app, release, privateApp, config, setCatalog: (value: unknown) => { catalog = value; }, close };
}

test('anonymous apps catalog contains only exact broker-verified public active releases and creates no session', async () => {
  const context = await setup(); const host = 'apps.example.test:8443';
  try {
    const response = await context.server.inject({ method: 'GET', url: '/api/public/v1/apps', remoteAddress: '198.51.100.5', headers: { host, cookie: 'autosoft_session=forged-admin', authorization: 'Bearer ignored-platform-secret' } }); assert.equal(response.statusCode, 200, response.body); assert.equal(response.headers['cache-control'], 'no-store'); assert.equal(response.cookies.length, 0); assert.equal(await context.store.read(state => Object.keys(state.sessions).length), 0);
    assert.deepEqual(response.json(), { schemaVersion: 2, portalOrigin: 'https://apps.example.test:8443', listingPolicy: 'explicit_listing', apps: [{ id: context.app.id, name: context.app.name, description: context.app.description, kind: 'web', access: 'public', url: 'https://document-library.apps.example.test:8443/' }] });
    for (const secret of ['not-exposed-ciphertext', 'Hidden private app', 'artifactHash', 'registry.test', 'untrusted-stored-address']) assert.ok(!response.body.includes(secret));
    await context.store.transaction(state => { state.apps[context.app.id]!.status = 'building'; }); const improving = await context.server.inject({ method: 'GET', url: '/api/public/v1/apps', headers: { host } }); assert.equal(improving.json().apps.length, 1, 'A currently published public app stays visible during a new build.');
    context.setCatalog({ apps: [{ appId: context.app.id, releaseId: randomUUID(), artifactHash: context.release.artifactHash, images: context.release.images, auth: 'public' }] }); const stale = await context.server.inject({ method: 'GET', url: '/api/public/v1/apps', headers: { host } }); assert.deepEqual(stale.json().apps, []);
    context.setCatalog({ apps: [{ appId: context.app.id, releaseId: context.release.id, artifactHash: context.release.artifactHash, images: context.release.images, auth: 'unknown' }] }); const malformed = await context.server.inject({ method: 'GET', url: '/api/public/v1/apps', headers: { host } }); assert.equal(malformed.statusCode, 503); assert.ok(!malformed.body.includes('Hidden private app'));
    const wrongHost = await context.server.inject({ method: 'GET', url: '/api/public/v1/apps', headers: { host: 'admin.example.test' } }); assert.equal(wrongHost.statusCode, 404); assert.equal(wrongHost.cookies.length, 0);
  } finally { await context.close(); }
});

test('apps host serves only the public portal and manifest-scoped assets, independent of admin cookies', async () => {
  const context = await setup(); const session = await context.server.inject({ method: 'GET', url: '/api/v1/session' }); const cookie = session.cookies[0]!; const headers = { host: 'apps.example.test:8443', cookie: `${cookie.name}=${cookie.value}`, authorization: 'Bearer forged-platform-bearer' };
  try {
    const portal = await context.server.inject({ method: 'GET', url: '/?from=admin', headers }); assert.equal(portal.statusCode, 200, portal.body); assert.match(portal.body, /PUBLIC_PORTAL_ENTRY/); assert.ok(!portal.body.includes('PRIVATE_ADMIN_ENTRY')); assert.equal(portal.cookies.length, 0);
    for (const name of ['portal.js', 'shared.js', 'portal.css']) { const asset = await context.server.inject({ method: 'GET', url: `/portal-assets/${name}`, headers }); assert.equal(asset.statusCode, 200, asset.body); assert.equal(asset.cookies.length, 0); }
    for (const path of ['/index.html', '/portal.html', '/assets/admin.js', '/assets/portal.js', '/.vite/manifest.json', '/api/v1/session', '/api/v1/apps?token=ignored', '/api/auth/check', '/auth/login', '/healthz', '/readyz', '/internal/v1/security-reports', '/metrics', '/portal-assets/admin.js', '/portal-assets/not-found.js', '/portal-assets/%70ortal.js', '/portal-assets/%2e%2e/index.html', '/portal-assets/nested/portal.js', '/%61pi/v1/session', '//api/v1/apps']) {
      const denied = await context.server.inject({ method: 'GET', url: path, headers }); assert.equal(denied.statusCode, 404, `${path}: ${denied.body}`); assert.ok(!denied.body.includes('PRIVATE_ADMIN_ENTRY')); assert.ok(!denied.body.includes('PRIVATE_ADMIN_BUNDLE')); assert.equal(denied.cookies.length, 0);
    }
    assert.equal((await context.server.inject({ method: 'POST', url: '/api/public/v1/apps', headers, payload: {} })).statusCode, 404); assert.equal((await context.server.inject({ method: 'POST', url: '/', headers, payload: {} })).statusCode, 404);
    const wrongHostAsset = await context.server.inject({ method: 'GET', url: '/portal-assets/portal.js', headers: { host: 'admin.example.test' } }); assert.equal(wrongHostAsset.statusCode, 404);
  } finally { await context.close(); }
});

test('default app slugs respect the template length, alphabet and reserved preview namespace', async () => {
  const context = await setup(); const session = await context.server.inject({ method: 'GET', url: '/api/v1/session' }); const cookie = session.cookies[0]!; const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: context.config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string };
  try {
    for (const name of ['A'.repeat(120), '123 documents', 'Preview', 'Preview - Documents', 'preview__stuff', '処理', 'Report---']) {
      const response = await context.server.inject({ method: 'POST', url: '/api/v1/apps', headers, payload: { name } }); assert.equal(response.statusCode, 200, response.body); const { slug, id } = response.json().app; assert.ok(slug.length <= 48); assert.ok(slugSchema.safeParse(slug).success, slug); assert.ok(!slug.startsWith('preview-')); assert.match(slug, /^[a-z]/); assert.ok(slug.endsWith(id.slice(0, 8)));
    }
  } finally { await context.close(); }
});

test('directory authorization is private, never creates a platform session and rejects browser or portal access', async () => {
  const context = await setup(); const path = `/api/public/v1/apps/${context.app.id}/directory/authorize`;
  try {
    for (const headers of [{ host: 'apps.example.test:8443' }, { host: 'admin.example.test' }, { host: 'evil.example' }, { host: 'control:3000', origin: 'https://apps.example.test:8443' }]) {
      const denied = await context.server.inject({ method: 'POST', url: path, headers, payload: {} });
      assert.equal(denied.statusCode, 404, denied.body); assert.equal(denied.cookies.length, 0);
    }
    const query = await context.server.inject({ method: 'POST', url: path + '?token=ignored', headers: { host: 'control:3000' }, payload: {} }); assert.equal(query.statusCode, 404);
    const privateRequest = await context.server.inject({ method: 'POST', url: path, headers: { host: 'control:3000', authorization: 'Bearer forged' }, payload: {} });
    assert.ok([401, 403, 503].includes(privateRequest.statusCode), privateRequest.body); assert.equal(privateRequest.cookies.length, 0);
    assert.equal(await context.store.read(state => Object.keys(state.sessions).length), 0);
  } finally { await context.close(); }
});

test('protected listing needs explicit disclosure, rejects stale changes and preserves app authorization', async () => {
  const c = await setup();
  try {
    const host = 'apps.example.test:8443';
    c.setCatalog({ apps: [{ appId: c.app.id, releaseId: c.release.id, artifactHash: c.release.artifactHash, images: c.release.images, auth: 'local' }] });
    const catalog = async () => (await c.server.inject({ method: 'GET', url: '/api/public/v1/apps', headers: { host } })).json();
    assert.deepEqual((await catalog()).apps, []);
    const session = await c.server.inject({ method: 'GET', url: '/api/v1/session' }); const cookie = session.cookies[0]!;
    const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: c.config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string };
    const url = `/api/v1/apps/${c.app.id}/portal-listing`;
    const payload = { revision: 0, visibility: 'listed', releaseId: c.release.id, artifactHash: c.release.artifactHash, acknowledgePublicListing: true, name: c.app.name, description: c.app.description, slug: c.app.slug, url: 'https://document-library.apps.example.test:8443/' };
    assert.equal((await c.server.inject({ method: 'PUT', url, headers, payload: { ...payload, acknowledgePublicListing: false } })).statusCode, 400);
    assert.equal((await c.server.inject({ method: 'PUT', url, headers: { ...headers, 'x-csrf-token': 'wrong' }, payload })).statusCode, 403);
    assert.equal((await c.server.inject({ method: 'PUT', url, headers, payload: { ...payload, name: 'Different reviewed name' } })).statusCode, 409);
    assert.equal((await c.server.inject({ method: 'PUT', url, headers, payload: { ...payload, slug: 'another-app' } })).statusCode, 409);
    assert.equal((await c.server.inject({ method: 'PUT', url, headers, payload: { ...payload, url: 'https://wrong.apps.example.test:8443/' } })).statusCode, 409);
    assert.equal((await c.server.inject({ method: 'PUT', url, headers, payload: { ...payload, releaseId: randomUUID() } })).statusCode, 409);
    const accepted = await c.server.inject({ method: 'PUT', url, headers, payload }); assert.equal(accepted.statusCode, 200, accepted.body);
    const visible = await catalog(); assert.equal(visible.apps.length, 1); assert.equal(visible.apps[0].access, 'signin_required');
    const unchanged = await c.store.read(state => ({ app: state.apps[c.app.id], release: state.releases[c.release.id], policies: state.accessSnapshots, history: Object.values(state.portalListingHistory) }));
    assert.deepEqual(unchanged.app, c.app); assert.deepEqual(unchanged.release, c.release); assert.deepEqual(unchanged.policies, {}); assert.equal(unchanged.history.length, 1); assert.ok(unchanged.history[0]!.changedBy);
    assert.equal(unchanged.history[0]!.url, payload.url); assert.equal(unchanged.history[0]!.releaseId, c.release.id); assert.equal(unchanged.history[0]!.artifactHash, c.release.artifactHash);
    assert.equal((await c.server.inject({ method: 'PUT', url, headers, payload })).statusCode, 409);
    await c.store.transaction(state => { state.apps[c.app.id]!.description = 'Unreviewed new description'; });
    assert.equal((await catalog()).apps[0].description, c.app.description, 'Only reviewed metadata is disclosed');
    const hidden = await c.server.inject({ method: 'PUT', url, headers, payload: { ...payload, revision: 1, visibility: 'unlisted', description: 'Unreviewed new description' } }); assert.equal(hidden.statusCode, 200, hidden.body);
    assert.deepEqual((await catalog()).apps, []);
    assert.equal((await c.store.read(state => Object.values(state.portalListingHistory))).length, 2);
    assert.equal((await c.server.inject({ method: 'PUT', url, headers: { ...headers, host }, payload })).statusCode, 404);
  } finally { await c.close(); }
});

test('SSO administrators cannot change public directory visibility without the owner', async () => {
  const c = await setup();
  try {
    const session = await c.server.inject({ method: 'GET', url: '/api/v1/session' }); const cookie = session.cookies[0]!;
    await c.store.transaction(state => { const saved = state.sessions[cookie.value]!; saved.principal = { id: 'admin', name: 'SSO administrator', localOwner: false, mfa: true, roles: ['platform-admin'] }; saved.accessExpiresAt = new Date(Date.now() + 3600000).toISOString(); });
    c.config.authMode = 'oidc';
    const response = await c.server.inject({ method: 'PUT', url: `/api/v1/apps/${c.app.id}/portal-listing`, headers: { cookie: `${cookie.name}=${cookie.value}`, origin: c.config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string }, payload: { revision: 0, visibility: 'listed', releaseId: c.release.id, artifactHash: c.release.artifactHash, acknowledgePublicListing: true, name: c.app.name, description: c.app.description, slug: c.app.slug, url: 'https://document-library.apps.example.test:8443/' } });
    assert.equal(response.statusCode, 403, response.body); assert.deepEqual(await c.store.read(state => state.portalListings), {});
  } finally { await c.close(); }
});

test('directory approval binds the reviewed origin and serializes simultaneous decisions', async () => {
  const c = await setup();
  try {
    const session = await c.server.inject({ method: 'GET', url: '/api/v1/session' }), cookie = session.cookies[0]!;
    const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: c.config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string };
    const url = `/api/v1/apps/${c.app.id}/portal-listing`;
    const settings = (await c.server.inject({ method: 'GET', url, headers })).json();
    assert.equal(settings.url, 'https://document-library.apps.example.test:8443/');
    assert.equal(settings.slug, c.app.slug); assert.equal(settings.canList, true);
    const { revision, name, description, slug, releaseId, artifactHash } = settings;
    const payload = { revision, name, description, slug, releaseId, artifactHash, url: settings.url, visibility: 'listed', acknowledgePublicListing: true };
    c.config.appsOrigin = 'https://moved.example.test';
    assert.equal((await c.server.inject({ method: 'PUT', url, headers, payload })).statusCode, 409);
    assert.deepEqual(await c.store.read(state => state.portalListingHistory), {});
    c.config.appsOrigin = 'https://apps.example.test:8443';
    const decisions = await Promise.all([
      c.server.inject({ method: 'PUT', url, headers, payload }),
      c.server.inject({ method: 'PUT', url, headers, payload: { ...payload, visibility: 'unlisted', acknowledgePublicListing: false } }),
    ]);
    assert.deepEqual(decisions.map(response => response.statusCode).sort(), [200, 409]);
    assert.equal((await c.store.read(state => Object.keys(state.portalListingHistory))).length, 1);
    c.config.appsOrigin = 'http://apps.example.test';
    const unavailable = (await c.server.inject({ method: 'GET', url, headers })).json();
    assert.equal(unavailable.canList, false); assert.equal(unavailable.url, null);
  } finally { await c.close(); }
});

test('published updates and compatible rollback preserve the independent directory decision', async () => {
  const c = await setup();
  try {
    const session = await c.server.inject({ method: 'GET', url: '/api/v1/session' }), cookie = session.cookies[0]!;
    const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: c.config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string };
    const payload = { revision: 0, visibility: 'listed', releaseId: c.release.id, artifactHash: c.release.artifactHash, acknowledgePublicListing: true, name: c.app.name, description: c.app.description, slug: c.app.slug, url: 'https://document-library.apps.example.test:8443/' };
    const accepted = await c.server.inject({ method: 'PUT', url: `/api/v1/apps/${c.app.id}/portal-listing`, headers, payload });
    assert.equal(accepted.statusCode, 200, accepted.body);
    const next: ReleaseRecord = { ...c.release, id: randomUUID(), version: '0.2.0', commit: 'c'.repeat(40) };
    next.artifactHash = releaseArtifactHash(next);
    for (const release of [next, c.release]) {
      await c.store.transaction(state => {
        state.releases[state.apps[c.app.id]!.activeReleaseId!]!.status = 'superseded';
        state.releases[release.id] = { ...release, status: 'published' };
        state.apps[c.app.id]!.activeReleaseId = release.id;
        state.apps[c.app.id]!.name = 'Unreviewed renamed application';
      });
      c.setCatalog({ apps: [{ appId: c.app.id, releaseId: release.id, artifactHash: release.artifactHash, images: release.images, auth: 'local' }] });
      const catalog = await c.server.inject({ method: 'GET', url: '/api/public/v1/apps', headers: { host: 'apps.example.test:8443' } });
      assert.equal(catalog.statusCode, 200, catalog.body);
      assert.equal(catalog.json().apps[0].name, c.app.name);
      assert.equal(catalog.json().apps[0].access, 'signin_required');
    }
    const history = await c.store.read(state => Object.values(state.portalListingHistory));
    assert.equal(history.length, 1); assert.equal(history[0]!.releaseId, c.release.id);
    assert.equal(history[0]!.name, c.app.name);
  } finally { await c.close(); }
});
