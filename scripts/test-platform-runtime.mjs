// Exercise the API's actual production dependency tree without external services.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { access, lstat, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = await realpath(process.cwd());
const load = path => import(pathToFileURL(join(root, path)).href);
for (const name of ['typescript', 'vite', '@vitejs/plugin-react', '@typescript/typescript-linux-x64']) {
  await assert.rejects(access(join(root, 'node_modules', name)), { code: 'ENOENT' });
}
assert.equal(await realpath(join(root, 'node_modules/@autosoft/core')), join(root, 'packages/core'));
const esbuild = await import(pathToFileURL(join(root, 'node_modules/esbuild/lib/main.js')).href);
assert.match(esbuild.transformSync('const value: number = 1;', { loader: 'ts' }).code, /const value = 1/);
await load('packages/core/src/index.ts');
const { createRuntime } = await load('apps/control/src/runtime.ts');
assert.equal(typeof createRuntime, 'function');
const { JsonStore } = await load('apps/control/src/store.ts');
const { configureDependencies } = await load('apps/control/src/dependencies.ts');
const { createServer } = await load('apps/control/src/server.ts');
await load('apps/control/src/messaging.ts');
assert.ok(JSON.parse(await readFile(join(root, 'models/integrations.json'), 'utf8')));
assert.ok((await readFile(join(root, 'templates/generation-guide.md'), 'utf8')).length > 100);
const manifest = JSON.parse(await readFile(join(root, 'apps/admin/dist/.vite/manifest.json'), 'utf8'));
const portalEntry = Object.entries(manifest).find(([key, value]) => key === 'portal.html' && value.isEntry);
assert.ok(portalEntry, 'Compiled portal entry must survive packaging.');

const temporaryRoot = await realpath(tmpdir());
const work = await mkdtemp(join(temporaryRoot, 'autosoft-platform-runtime-'));
let server;
const store = new JsonStore(join(work, 'state.json'));
try {
  await store.initialize();
  const config = {
    authMode: 'development', host: '127.0.0.1', port: 0,
    publicOrigin: 'https://admin.fixture.invalid', appsOrigin: 'https://apps.fixture.invalid',
    dataDir: work, workspaceDir: join(work, 'workspace'), secretKey: randomBytes(32),
    oidcClientId: 'autosoft-admin', requestLimitUsd: 1, monthlyLimitUsd: 1,
    adminDist: join(root, 'apps/admin/dist'),
  };
  const dependencies = await configureDependencies(config, store);
  assert.equal(dependencies.planAndGenerate, undefined, 'Fixture must make no model calls.');
  server = await createServer(config, store, dependencies);
  await server.listen({ host: '127.0.0.1', port: 0 });
  const address = server.server.address();
  assert.equal(typeof address, 'object');
  const response = await fetch(`http://127.0.0.1:${address.port}/healthz`, { signal: AbortSignal.timeout(5000) });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok' });
  const ready = await server.inject({ url: '/readyz', headers: { host: 'admin.fixture.invalid' } });
  assert.equal(ready.statusCode, 200);
  assert.equal(ready.json().storage, 'development');
  const admin = await server.inject({ url: '/', headers: { host: 'admin.fixture.invalid' } });
  assert.equal(admin.statusCode, 200);
  assert.match(admin.headers['content-type'], /text\/html/);
  const portal = await server.inject({ url: '/', headers: { host: 'apps.fixture.invalid' } });
  assert.equal(portal.statusCode, 200);
  assert.match(portal.headers['content-type'], /text\/html/);
  assert.notEqual(portal.body, admin.body);
  const asset = await server.inject({ url: '/portal-assets/' + portalEntry[1].file.slice('assets/'.length), headers: { host: 'apps.fixture.invalid' } });
  assert.equal(asset.statusCode, 200);
  const denied = await server.inject({ url: '/api/v1/apps', headers: { host: 'apps.fixture.invalid' } });
  assert.equal(denied.statusCode, 404);
  const catalog = await server.inject({ url: '/api/public/v1/apps', headers: { host: 'apps.fixture.invalid' } });
  assert.equal(catalog.statusCode, 503, 'Missing real publication evidence must keep the catalog unavailable.');
  console.log('Production dependency tree, native esbuild, API health/readiness and compiled admin/portal boundaries passed; external services and image security remain separate.');
} finally {
  await server?.close();
  await store.close();
  // Remove only this newly created, ordinary directory directly beneath tmpdir.
  assert.equal(dirname(await realpath(work)), temporaryRoot);
  assert.equal((await lstat(work)).isSymbolicLink(), false);
  await rm(work, { recursive: true });
}
