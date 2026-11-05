import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hashArtifact, releaseArtifactHash } from '../../../packages/core/src/index.ts';
import type { AppRecord, ReleaseRecord, ReleaseObservation } from '../../../packages/core/src/types.ts';
import { createServer } from '../src/server.ts';
import { JsonStore } from '../src/store.ts';
import { observePublishedReleases } from '../src/observation.ts';
import type { EngineDependencies } from '../src/engine.ts';
import type { Config } from '../src/config.ts';

async function setup(dependencies: EngineDependencies = {}) {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-observation-')), file = join(root, 'state.json'), store = new JsonStore(file); await store.initialize(); const now = new Date().toISOString();
  const app: AppRecord = { id: randomUUID(), slug: 'document-library', name: 'Document library', description: '', kind: 'web', status: 'published', activeReleaseId: null, url: 'https://document-library.apps.example.test/', previewUrl: 'https://preview-document-library.apps.example.test/', createdAt: now, updatedAt: now };
  const target: ReleaseRecord = { id: randomUUID(), appId: app.id, version: '0.1.0', summary: 'Preserved document library', artifactHash: '', commit: 'a'.repeat(40), images: [`registry.test/app@sha256:${'b'.repeat(64)}`], schemaVersion: 1, compatibleSchemaMin: 1, compatibleSchemaMax: 2, baseReleaseId: null, status: 'published', evidence: { status: 'passed', checkedAt: now, feedUpdatedAt: now, findings: [], checks: ['dependencies', 'build', 'application_tests', 'security', 'image_packaging', 'preview', 'migration_rehearsal', 'acceptance'].map(name => ({ name, passed: true, detail: 'Fixture verified' })) }, migrations: [], createdAt: now, publishedAt: now };
  target.artifactHash = releaseArtifactHash(target); app.activeReleaseId = target.id;
  const release: ReleaseRecord = { ...structuredClone(target), id: randomUUID(), version: '0.2.0', summary: 'Improved document search', commit: 'c'.repeat(40), images: [`registry.test/app@sha256:${'d'.repeat(64)}`], schemaVersion: 2, baseReleaseId: target.id, status: 'ready', publishedAt: null }; release.artifactHash = releaseArtifactHash(release); app.previewReleaseId = release.id;
  await store.transaction(state => { state.apps[app.id] = app; state.releases[target.id] = target; state.releases[release.id] = release; state.secrets['existing-secret-reference'] = 'encrypted-documents-service-reference'; });
  const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: root, workspaceDir: join(root, 'workspaces'), oidcClientId: 'test', secretKey: Buffer.alloc(32, 42), requestLimitUsd: 1, monthlyLimitUsd: 5, adminDist: join(root, 'missing'), appsOrigin: 'https://apps.example.test' };
  const server = await createServer(config, store, { deploy: async () => ({ url: app.url!, healthy: true }), ...dependencies }); const session = await server.inject({ method: 'GET', url: '/api/v1/session' }); const cookie = session.cookies[0]!; const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string };
  const approveAndPublish = async (automaticRecovery = true) => {
    const review = await server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers, payload: { action: 'publish', automaticRecovery } }); assert.equal(review.statusCode, 200, review.body); const { approval, recoveryGrant } = review.json();
    const approved = await server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers, payload: { artifactHash: approval.artifactHash, ...(recoveryGrant ? { authorizationHash: recoveryGrant.authorizationHash } : {}) } }); assert.equal(approved.statusCode, 200, approved.body);
    const published = await server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/publish`, headers, payload: { approvalId: approval.id } }); assert.equal(published.statusCode, 200, published.body); return { approval, recoveryGrant, operationId: published.json().operationId as string };
  };
  const close = async () => { await server.close(); await store.close(); await rm(root, { recursive: true, force: true }); }; return { root, file, store, app, target, release, server, headers, approveAndPublish, close };
}
function runtime(clock: () => number, status: () => ReleaseObservation['status']): EngineDependencies {
  return { observe: async input => { const result = { ...input, checkedAt: new Date(clock()).toISOString(), status: status(), detail: 'Actual independently observed fixture health' }; return { ...result, evidenceHash: hashArtifact(result) }; } };
}

test('automatic recovery needs exact additional user consent and its artifacts are disclosed in publication', async () => {
  let sentGrant: unknown; const context = await setup({ deploy: async input => { sentGrant = input.recoveryGrant; return { url: input.app.url!, healthy: true }; } });
  try {
    const review = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${context.release.id}/approval`, headers: context.headers, payload: { automaticRecovery: true } }); const { approval, recoveryGrant } = review.json(); assert.equal(review.statusCode, 200, review.body); assert.equal(recoveryGrant.targetReleaseId, context.target.id); assert.equal(recoveryGrant.approvedAt, null); assert.ok(approval.impact.some((value: string) => value.includes('AUTOMATIC RECOVERY') && value.includes(context.target.artifactHash)));
    for (const authorizationHash of [undefined, 'f'.repeat(64)]) { const denied = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: context.headers, payload: { artifactHash: approval.artifactHash, ...(authorizationHash ? { authorizationHash } : {}) } }); assert.equal(denied.statusCode, 409); }
    const approve = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: context.headers, payload: { artifactHash: approval.artifactHash, authorizationHash: recoveryGrant.authorizationHash } }); assert.equal(approve.statusCode, 200, approve.body);
    const publish = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${context.release.id}/publish`, headers: context.headers, payload: { approvalId: approval.id } }); assert.equal(publish.statusCode, 200, publish.body);
    const activated = await context.store.read(state => state.recoveryGrants[recoveryGrant.id]!); assert.equal(activated.publicationOperationId, publish.json().operationId); assert.equal(activated.approvedBy, 'development-owner'); assert.deepEqual(sentGrant, activated); assert.ok((await context.store.read(state => state.approvals[approval.id]))?.consumedAt);
  } finally { await context.close(); }
});

test('three independent failures dispatch one exact durable eligible recovery and preserve current data references', async () => {
  let clock = Date.now(), recoveries = 0; const deps = runtime(() => clock, () => 'unhealthy'); const context = await setup(); await context.approveAndPublish();
  deps.recoverRelease = async input => {
    recoveries++; assert.equal(input.release.id, context.target.id); assert.equal(input.app.activeReleaseId, context.release.id); assert.equal(input.observationIds.length, 3); assert.equal(new Set(input.observationIds).size, 3); assert.equal(input.evidenceHashes.length, 3);
    const saved = await context.store.read(state => Object.values(state.recoveryIntents)[0]!); assert.deepEqual(saved.request, input); assert.equal(saved.status, 'running'); assert.equal(await context.store.read(state => state.operations[input.operationId]?.status), 'running'); return { url: context.app.url!, healthy: true };
  };
  try {
    for (let index = 0; index < 3; index++) { clock += 60000; await observePublishedReleases(context.store, deps, { now: clock }); assert.equal(recoveries, index === 2 ? 1 : 0); }
    const state = await context.store.read(state => state); assert.equal(state.apps[context.app.id]?.activeReleaseId, context.target.id); assert.equal(state.apps[context.app.id]?.databaseSchemaVersion, 2); assert.equal(state.releases[context.target.id]?.schemaVersion, 1); assert.equal(state.releases[context.release.id]?.status, 'superseded'); assert.equal(Object.values(state.recoveryIntents)[0]?.status, 'succeeded'); assert.equal(state.observationAttempts[Object.values(state.recoveryIntents)[0]!.request.observationIds[0]!]!.result!.status, 'unhealthy'); assert.equal(state.secrets['existing-secret-reference'], 'encrypted-documents-service-reference');
    const reopened = new JsonStore(context.file); await reopened.initialize(); assert.equal(await reopened.read(state => Object.values(state.recoveryIntents)[0]?.status), 'succeeded'); assert.equal((await readFile(context.file, 'utf8')).includes('authorizationHash'), true);
    clock += 60000; await observePublishedReleases(context.store, { ...deps, ...runtime(() => clock, () => 'healthy') }, { now: clock }); assert.equal(recoveries, 1);
  } finally { await context.close(); }
});

test('unavailable and healthy observations reset failure streaks and no grant requires input', async () => {
  let clock = Date.now(), status: ReleaseObservation['status'] = 'unhealthy', recoveries = 0; const context = await setup(); await context.approveAndPublish(false); const deps = { ...runtime(() => clock, () => status), recoverRelease: async () => { recoveries++; return { url: context.app.url!, healthy: true }; } };
  try {
    for (const next of ['unhealthy', 'unavailable', 'unhealthy', 'healthy', 'unhealthy', 'unhealthy', 'unhealthy', 'unhealthy'] as const) { status = next; clock += 60000; await observePublishedReleases(context.store, deps, { now: clock }); }
    const state = await context.store.read(state => state); assert.equal(recoveries, 0); assert.equal(state.apps[context.app.id]?.activeReleaseId, context.release.id); assert.equal(state.observations[context.app.id]?.consecutiveFailures.length, 3); assert.match(state.observations[context.app.id]?.recoveryReason ?? '', /No explicit exact-release/); assert.equal(Object.values(state.notifications).filter(item => item.title === 'Published application needs recovery attention' && item.message.includes('No explicit exact-release')).length, 1);
  } finally { await context.close(); }
});

test('fresh security findings, incomplete scans and expired grants block automatic recovery', async () => {
  for (const scenario of ['vulnerable', 'unclassified', 'incomplete', 'stale', 'expired']) {
    let clock = Date.now(), recoveries = 0; const context = await setup(); const { recoveryGrant } = await context.approveAndPublish(); const deps = { ...runtime(() => clock, () => 'unhealthy'), recoverRelease: async () => { recoveries++; return { url: context.app.url!, healthy: true }; } };
    try {
      await context.store.transaction(state => {
        if (scenario === 'expired') state.recoveryGrants[recoveryGrant.id]!.expiresAt = new Date(clock - 1).toISOString();
        else { const id = randomUUID(); state.securityReports[id] = { id, subject: 'app', appId: context.app.id, releaseId: context.target.id, status: scenario === 'incomplete' ? 'unavailable' : scenario === 'stale' ? 'passed' : 'failed', checkedAt: new Date(scenario === 'stale' ? clock - 2 * 86400000 : clock).toISOString(), feedUpdatedAt: new Date(clock).toISOString(), findings: ['vulnerable', 'unclassified'].includes(scenario) ? [{ id: 'ADVISORY-TEST', severity: scenario === 'unclassified' ? 'UNKNOWN' : 'MEDIUM', package: 'dependency', installedVersion: '1', source: 'vendor', description: 'Blocking scan finding' }] : [], coverage: [{ name: 'image', status: scenario === 'incomplete' ? 'unavailable' : 'passed', detail: 'Actual scan fixture' }], receivedAt: new Date(clock).toISOString() }; }
      });
      for (let index = 0; index < 3; index++) { clock += 60000; await observePublishedReleases(context.store, deps, { now: clock }); }
      assert.equal(recoveries, 0, scenario); assert.equal(await context.store.read(state => Object.keys(state.recoveryIntents).length), 0, scenario); assert.equal(await context.store.read(state => state.observations[context.app.id]?.recoveryStatus), 'needs_attention', scenario);
    } finally { await context.close(); }
  }
});

test('an ambiguous recovery remains pending and is reconciled without replay after restart', async () => {
  let clock = Date.now(), recoveries = 0, receipt: 'unknown' | 'succeeded' = 'unknown'; const context = await setup(); await context.approveAndPublish();
  const deps: EngineDependencies = { ...runtime(() => clock, () => 'unhealthy'), recoverRelease: async () => { recoveries++; throw new Error('Connection interrupted after sending recovery'); }, operation: async input => {
    const operation = await context.store.read(state => state.operations[input.operationId]!); return receipt === 'unknown' ? { status: 'unknown' } : { status: 'succeeded', appId: operation.appId, releaseId: operation.releaseId, healthy: true, url: context.app.url! };
  } };
  try {
    for (let index = 0; index < 3; index++) { clock += 60000; await observePublishedReleases(context.store, deps, { now: clock }); }
    assert.equal(recoveries, 1); assert.equal(await context.store.read(state => state.apps[context.app.id]?.activeReleaseId), context.release.id); assert.equal(await context.store.read(state => Object.values(state.recoveryIntents)[0]?.status), 'running');
    clock += 60000; await observePublishedReleases(context.store, deps, { now: clock }); assert.equal(recoveries, 1);
    receipt = 'succeeded'; clock += 60000; await observePublishedReleases(context.store, { ...deps, ...runtime(() => clock, () => 'healthy') }, { now: clock }); assert.equal(recoveries, 1); assert.equal(await context.store.read(state => state.apps[context.app.id]?.activeReleaseId), context.target.id); assert.equal(await context.store.read(state => Object.values(state.recoveryIntents)[0]?.status), 'succeeded');
  } finally { await context.close(); }
});

test('mismatched observation evidence cannot authorize recovery and schema-incompatible consent is refused', async () => {
  let clock = Date.now(), recoveries = 0; const context = await setup();
  try {
    await context.store.transaction(state => { state.releases[context.target.id]!.compatibleSchemaMax = 1; state.releases[context.target.id]!.artifactHash = releaseArtifactHash(state.releases[context.target.id]!); });
    const refused = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${context.release.id}/approval`, headers: context.headers, payload: { automaticRecovery: true } }); assert.equal(refused.statusCode, 409); assert.match(refused.body, /current database schema/);
    await context.store.transaction(state => { state.releases[context.target.id] = context.target; }); await context.approveAndPublish();
    const deps: EngineDependencies = { observe: async input => ({ ...input, releaseId: randomUUID(), checkedAt: new Date(clock).toISOString(), status: 'unhealthy', detail: 'Wrong app release', evidenceHash: 'f'.repeat(64) }), recoverRelease: async () => { recoveries++; return { url: context.app.url!, healthy: true }; } };
    for (let index = 0; index < 3; index++) { clock += 60000; await observePublishedReleases(context.store, deps, { now: clock }); }
    assert.equal(recoveries, 0); assert.equal(await context.store.read(state => state.observations[context.app.id]?.status), 'unavailable'); assert.equal(await context.store.read(state => state.observations[context.app.id]?.consecutiveFailures.length), 0);
  } finally { await context.close(); }
});

test('runtime schema downgrades cannot record recovery success or authorize a later incompatible release', async () => {
  let clock = Date.now(); const context = await setup(); await context.approveAndPublish();
  const deps = { ...runtime(() => clock, () => 'unhealthy'), recoverRelease: async () => ({ url: context.app.url!, healthy: true, schemaVersion: 1 }) };
  try {
    for (let index = 0; index < 3; index++) { clock += 60000; await observePublishedReleases(context.store, deps, { now: clock }); }
    const state = await context.store.read(state => state); assert.equal(state.apps[context.app.id]?.activeReleaseId, context.release.id); assert.equal(state.apps[context.app.id]?.databaseSchemaVersion, 2); assert.equal(Object.values(state.recoveryIntents)[0]?.status, 'running'); assert.match(Object.values(state.recoveryIntents)[0]?.error ?? '', /expected preserved database schema/);
    await context.store.transaction(state => { state.apps[context.app.id]!.activeReleaseId = context.target.id; state.releases[context.target.id]!.status = 'published'; state.releases[context.release.id]!.status = 'superseded'; const incompatible = { ...structuredClone(context.target), id: randomUUID(), status: 'ready' as const, baseReleaseId: context.target.id, compatibleSchemaMax: 1, publishedAt: null }; incompatible.artifactHash = releaseArtifactHash(incompatible); state.releases[incompatible.id] = incompatible; state.apps[context.app.id]!.previewReleaseId = incompatible.id; });
    const candidate = await context.store.read(state => Object.values(state.releases).find(release => release.status === 'ready')!);
    const review = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${candidate.id}/approval`, headers: context.headers, payload: {} }); const approval = review.json().approval;
    const denied = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: context.headers, payload: { artifactHash: approval.artifactHash } }); assert.equal(denied.statusCode, 409); assert.match(denied.body, /current database schema/);
  } finally { await context.close(); }
});
