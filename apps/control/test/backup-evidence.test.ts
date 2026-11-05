import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative } from 'node:path';
import { createServer } from '../src/server.ts';
import { emptyState, JsonStore } from '../src/store.ts';
import { verifiedCheckpoint, type BackupReport } from '../src/reports.ts';
import type { Config } from '../src/config.ts';
import type { AppRecord, ReleaseRecord } from '../../../packages/core/src/types.ts';
import { releaseArtifactHash } from '../../../packages/core/src/index.ts';

const token = 'backup-evidence-test-token-at-least-32-characters';
const started = Date.now() - 600000;
const time = (step = 0) => new Date(started + step * 1000).toISOString();
const expiry = () => new Date(Date.now() + 3600000).toISOString();
function backup(appIds: string[], step = 0, changes: Partial<BackupReport> = {}): BackupReport {
  return { id: randomUUID(), kind: 'restore_verification', status: 'passed', completedAt: time(step), receivedAt: time(step), checkpointId: 'cp-evidence', manifestHash: 'c'.repeat(64), expiresAt: expiry(), appIds, detail: 'Synthetic isolated restore verification', ...changes };
}
function fixtures() {
  const app: AppRecord = { id: randomUUID(), name: 'Recovery app', slug: 'recovery-app', description: '', kind: 'web', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt: time(), updatedAt: time() };
  const other = { ...app, id: randomUUID(), name: 'Other app', slug: 'other-app' };
  const release: ReleaseRecord = { id: randomUUID(), appId: app.id, version: '0.1.0', summary: 'Remove exact obsolete test column', artifactHash: '', commit: 'a'.repeat(40), images: [`registry.test/app@sha256:${'b'.repeat(64)}`], schemaVersion: 1, compatibleSchemaMin: 1, compatibleSchemaMax: 1, baseReleaseId: null, status: 'ready', evidence: { status: 'passed', checkedAt: new Date().toISOString(), feedUpdatedAt: new Date().toISOString(), findings: [], checks: ['dependencies', 'build', 'application_tests', 'security', 'image_packaging', 'preview', 'migration_rehearsal', 'acceptance'].map(name => ({ name, passed: true, detail: 'Synthetic accepted gate' })) }, migrations: [{ id: 'obsolete-column', destructive: true, checksum: 'f'.repeat(64), impact: 'Remove obsolete column from 10 synthetic records; original values are in cp-evidence.' }], createdAt: time(), publishedAt: null };
  release.artifactHash = releaseArtifactHash(release); app.previewReleaseId = release.id;
  return { app, other, release };
}
async function setup(persistent = false) {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-backup-evidence-'));
  const file = persistent ? join(root, 'state.json') : undefined;
  const store = new JsonStore(file); await store.initialize(); const f = fixtures();
  await store.transaction(state => { state.apps[f.app.id] = f.app; state.apps[f.other.id] = f.other; state.releases[f.release.id] = f.release; });
  const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: root, workspaceDir: join(root, 'workspaces'), oidcClientId: 'test', secretKey: Buffer.alloc(32, 42), requestLimitUsd: 1, monthlyLimitUsd: 5, adminDist: join(root, 'absent-dist'), reportToken: token };
  let deployments = 0;
  const server = await createServer(config, store, { deploy: async () => { deployments++; return { healthy: true, url: 'https://recovery-app.example.test' }; } });
  const session = await server.inject({ method: 'GET', url: '/api/v1/session' }); const cookie = session.cookies[0]!;
  const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string };
  const ingest = async (value: BackupReport, status = 200) => {
    const { receivedAt: _receivedAt, ...payload } = value;
    const result = await server.inject({ method: 'POST', url: '/internal/v1/backup-reports', headers: { authorization: `Bearer ${token}` }, payload });
    assert.equal(result.statusCode, status, result.body); return result;
  };
  const eligible = async (appId = f.app.id) => store.read(state => verifiedCheckpoint(state, 'cp-evidence', appId));
  const draft = async () => {
    const result = await server.inject({ method: 'POST', url: `/api/v1/releases/${f.release.id}/approval`, headers, payload: { checkpointId: 'cp-evidence' } });
    assert.equal(result.statusCode, 200, result.body); return result.json().approval as { id: string; artifactHash: string; impact: string[] };
  };
  const approve = async (approval: { id: string; artifactHash: string }) => server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers, payload: { artifactHash: approval.artifactHash } });
  const publish = async (approval: { id: string }) => server.inject({ method: 'POST', url: `/api/v1/releases/${f.release.id}/publish`, headers, payload: { approvalId: approval.id } });
  const close = async () => { await server.close(); await store.close(); const placement = relative(tmpdir(), root); assert.ok(placement && !placement.startsWith('..') && !isAbsolute(placement)); await rm(root, { recursive: true, force: true }); };
  return { ...f, file, store, server, headers, ingest, eligible, draft, approve, publish, close, deployments: () => deployments };
}

test('same backup report is idempotent, including reordered application scope', async () => {
  const c = await setup(); try {
    const value = backup([c.app.id, c.other.id]); await c.ingest(value);
    const before = await c.store.read(state => state); await c.ingest({ ...value, appIds: [c.other.id, c.app.id] });
    assert.deepEqual(await c.store.read(state => state), before); assert.equal(await c.eligible(), true);
  } finally { await c.close(); }
});

test('changed reuse of a backup report ID preserves the original and commits a deduplicated integrity hold', async () => {
  const c = await setup(); try {
    const value = backup([c.app.id]); await c.ingest(value); const before = await c.store.read(state => state);
    for (const changes of [{ status: 'failed' as const }, { appIds: [c.other.id] }, { manifestHash: 'd'.repeat(64) }, { expiresAt: new Date(Date.now() + 7200000).toISOString() }, { completedAt: time(1) }]) {
      await c.ingest({ ...value, ...changes }, 409); assert.deepEqual(await c.store.read(state => state.backupReports[value.id]), before.backupReports[value.id]);
      assert.equal(await c.eligible(), false); assert.equal(await c.store.read(state => Object.values(state.backupReports).filter(item => item.integrityConflict).length), 1);
    }
    await c.ingest(backup([c.app.id], 2)); assert.equal(await c.eligible(), false);
  } finally { await c.close(); }
});

test('checkpoint identifiers cannot be rebound to a different manifest across report kinds', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id], 0, { kind: 'nightly' }));
    const before = await c.store.read(state => state); await c.ingest(backup([c.app.id], 1, { manifestHash: 'd'.repeat(64) }), 409);
    for (const [id, report] of Object.entries(before.backupReports)) assert.deepEqual(await c.store.read(state => state.backupReports[id]), report);
    assert.equal(await c.store.read(state => Object.values(state.backupReports).filter(item => item.integrityConflict).length), 1);
    await c.ingest(backup([c.app.id], 2)); assert.equal(await c.eligible(), false);
  } finally { await c.close(); }
});

test('newer failed and unavailable restore attempts revoke success until a newer pass', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id])); assert.equal(await c.eligible(), true);
    await c.ingest(backup([], 1, { status: 'failed', manifestHash: undefined, expiresAt: undefined })); assert.equal(await c.eligible(), false);
    await c.ingest(backup([c.app.id], 2)); assert.equal(await c.eligible(), true);
    await c.ingest(backup([], 3, { status: 'unavailable' })); assert.equal(await c.eligible(), false);
  } finally { await c.close(); }
});

test('unscoped restore failure revokes all checkpoints but named app scope is respected', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id, c.other.id]));
    await c.ingest(backup([c.other.id], 1, { status: 'failed', checkpointId: undefined, manifestHash: undefined, expiresAt: undefined }));
    assert.equal(await c.eligible(), true); assert.equal(await c.eligible(c.other.id), false);
    await c.ingest(backup([], 2, { status: 'unavailable', checkpointId: undefined, manifestHash: undefined, expiresAt: undefined }));
    assert.equal(await c.eligible(), false); assert.equal(await c.eligible(c.other.id), false);
    await c.ingest(backup([c.app.id, c.other.id], 3)); assert.equal(await c.eligible(), true);
  } finally { await c.close(); }
});

test('failure of another checkpoint cannot revoke a healthy checkpoint', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id])); await c.ingest(backup([], 1, { status: 'failed', checkpointId: 'other-checkpoint', manifestHash: undefined, expiresAt: undefined }));
    assert.equal(await c.eligible(), true);
  } finally { await c.close(); }
});

test('late older reports cannot supersede the latest restore outcome', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id], 2)); await c.ingest(backup([], 1, { status: 'failed' })); assert.equal(await c.eligible(), true);
    await c.ingest(backup([], 3, { status: 'failed' })); await c.ingest(backup([c.app.id], 0)); assert.equal(await c.eligible(), false);
  } finally { await c.close(); }
});

test('conflicting restore outcomes at the same completion time require a newer verification', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id])); await c.ingest(backup([], 0, { status: 'failed' })); assert.equal(await c.eligible(), false);
    await c.ingest(backup([c.app.id], 1)); assert.equal(await c.eligible(), true);
  } finally { await c.close(); }
});

test('latest narrower restore scope does not borrow app coverage from an older pass', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id, c.other.id])); await c.ingest(backup([c.other.id], 1));
    assert.equal(await c.eligible(), false); assert.equal(await c.eligible(c.other.id), true);
  } finally { await c.close(); }
});

test('an expired latest pass cannot fall back to an older unexpired pass', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id])); await c.ingest(backup([c.app.id], 1, { expiresAt: time(2) })); assert.equal(await c.eligible(), false);
  } finally { await c.close(); }
});

test('legacy contradictory manifests and malformed or future verification cannot grant recovery', () => {
  const appId = randomUUID(); const state = emptyState(); const value = backup([appId]); state.backupReports[value.id] = value;
  assert.equal(verifiedCheckpoint(state, value.checkpointId, appId), true);
  const other = backup([appId], 1, { manifestHash: 'd'.repeat(64) }); state.backupReports[other.id] = other; assert.equal(verifiedCheckpoint(state, value.checkpointId, appId), false);
  delete state.backupReports[other.id];
  for (const changes of [{ manifestHash: 'invalid' }, { expiresAt: 'invalid' }, { completedAt: 'invalid' }, { completedAt: new Date(Date.now() + 120000).toISOString() }]) {
    state.backupReports[value.id] = { ...value, ...changes }; assert.equal(verifiedCheckpoint(state, value.checkpointId, appId), false);
  }
});

test('duplicate app scope and expiry before completion are rejected', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id, c.app.id]), 400); await c.ingest(backup([c.app.id], 1, { expiresAt: time(0) }), 400);
    assert.equal(await c.eligible(), false); assert.equal(await c.store.read(state => Object.keys(state.backupReports).length), 0);
  } finally { await c.close(); }
});

test('destructive review displays the exact manifest and a refreshed verification invalidates approval', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id])); const approval = await c.draft();
    assert.ok(approval.impact.some(item => item.includes('cp-evidence') && item.includes('c'.repeat(64)) && item.includes('evidence expires')));
    await c.ingest(backup([c.app.id], 1)); assert.equal(await c.eligible(), true);
    const result = await c.approve(approval); assert.equal(result.statusCode, 409, result.body); assert.match(result.body, /recovery evidence changed/i);
    assert.equal(await c.store.read(state => state.approvals[approval.id]?.approvedAt), null);
  } finally { await c.close(); }
});

test('failed restore after approval prevents publication without consuming or dispatching it', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id])); const approval = await c.draft(); const accepted = await c.approve(approval); assert.equal(accepted.statusCode, 200, accepted.body);
    await c.ingest(backup([], 1, { status: 'failed' })); const result = await c.publish(approval); assert.equal(result.statusCode, 409, result.body);
    assert.equal(c.deployments(), 0); assert.equal(await c.store.read(state => state.approvals[approval.id]?.consumedAt), null);
  } finally { await c.close(); }
});

test('changed passing recovery evidence after approval requires review before publication', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id])); const approval = await c.draft(); assert.equal((await c.approve(approval)).statusCode, 200);
    await c.ingest(backup([c.app.id], 1)); assert.equal(await c.eligible(), true);
    const result = await c.publish(approval); assert.equal(result.statusCode, 409, result.body); assert.match(result.body, /recovery evidence changed/i);
    assert.equal(c.deployments(), 0); assert.equal(await c.store.read(state => state.approvals[approval.id]?.consumedAt), null);
  } finally { await c.close(); }
});

test('unchanged verified checkpoint permits the synthetic approval and deployment path', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id])); const approval = await c.draft(); const accepted = await c.approve(approval); assert.equal(accepted.statusCode, 200, accepted.body);
    const result = await c.publish(approval); assert.equal(result.statusCode, 200, result.body); assert.equal(c.deployments(), 1);
  } finally { await c.close(); }
});

test('a manifest collision after a valid pass durably revokes eligibility and preserves the expected hash', async () => {
  const c = await setup(); try {
    const original = backup([c.app.id]); await c.ingest(original); assert.equal(await c.eligible(), true);
    await c.ingest(backup([c.app.id], 1, { manifestHash: 'd'.repeat(64) }), 409);
    assert.equal(await c.eligible(), false); assert.equal(await c.store.read(state => state.backupReports[original.id]?.manifestHash), 'c'.repeat(64));
    await c.ingest(backup([c.app.id], 2)); assert.equal(await c.eligible(), false);
    const newPoint = backup([c.app.id], 3, { checkpointId: 'cp-new-identity' }); await c.ingest(newPoint);
    assert.equal(await c.store.read(state => verifiedCheckpoint(state, newPoint.checkpointId, c.app.id)), true);
  } finally { await c.close(); }
});

test('independent checkpoint failures notify even when another checkpoint has a newer report', async () => {
  const c = await setup(); try {
    await c.ingest(backup([c.app.id], 2, { status: 'failed', checkpointId: 'cp-other' }));
    await c.ingest(backup([c.app.id], 1, { status: 'failed' }));
    assert.equal(await c.store.read(state => Object.values(state.notifications).filter(item => item.title === 'Backup or restore verification failed').length), 2);
    await c.ingest(backup([c.app.id], 3, { status: 'failed' }));
    assert.equal(await c.store.read(state => Object.values(state.notifications).filter(item => item.title === 'Backup or restore verification failed').length), 2);
  } finally { await c.close(); }
});

test('an integrity conflict survives persisted state reopening without modifying the original proof', async () => {
  const c = await setup(true); try {
    const original = backup([c.app.id]); await c.ingest(original);
    await c.ingest(backup([c.app.id], 1, { manifestHash: 'd'.repeat(64) }), 409);
    const reopened = new JsonStore(c.file); await reopened.initialize();
    try {
      assert.equal(await reopened.read(state => verifiedCheckpoint(state, original.checkpointId, c.app.id)), false);
      assert.equal(await reopened.read(state => state.backupReports[original.id]?.manifestHash), original.manifestHash);
      assert.equal(await reopened.read(state => Object.values(state.backupReports).filter(item => item.integrityConflict).length), 1);
    } finally { await reopened.close(); }
  } finally { await c.close(); }
});
