import { authorityMonth } from '../src/spending-authority.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createServer } from '../src/server.ts';
import { JsonStore, event, enqueue } from '../src/store.ts';
import { BudgetManager, BudgetLimitError } from '../src/budget.ts';
import { WorkflowEngine, writeScopedFiles } from '../src/engine.ts';
import { reconcileDeployments } from '../src/deployments.ts';
import { releaseArtifactHash,hashArtifact } from '../../../packages/core/src/index.ts';
import { stages } from '../../../packages/core/src/schemas.ts';
import { pipelineDefinitionHash } from '../../../packages/core/src/source-hash.ts';
import { snapshotFixture } from '../../../packages/core/test/migration-snapshot-fixture.ts';
import type { Config } from '../src/config.ts';
import type { AppRecord, JobRecord, ReleaseRecord } from '../../../packages/core/src/types.ts';
const boundPipeline = {schemaVersion:1,template:'node-api',stages:stages.map(name=>({name,commands:[],timeoutSeconds:60}))};
const now = () => new Date().toISOString();
function fixtures() {
  const app: AppRecord = { id: randomUUID(), slug: 'test-app', name: 'Test app', description: '', kind: 'web', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt: now(), updatedAt: now() };
  const job: JobRecord = { id: randomUUID(), appId: app.id, request: 'Create a document library', stage: 'queued', baseReleaseId: null, costUsd: 0, budgetUsd: 1, attempts: 0, createdAt: now(), updatedAt: now() };
  const release: ReleaseRecord = { id: randomUUID(), appId: app.id, version: '0.1.0', summary: 'Document library', artifactHash: '', commit: 'a'.repeat(40), images: [`registry.test/app@sha256:${'b'.repeat(64)}`], schemaVersion: 1, compatibleSchemaMin: 1, compatibleSchemaMax: 1, baseReleaseId: null, status: 'ready', evidence: { status: 'passed', checkedAt: now(), feedUpdatedAt: now(), findings: [], checks: ['dependencies', 'build', 'application_tests', 'security', 'image_packaging', 'preview', 'migration_rehearsal', 'acceptance'].map(name => ({ name, passed: true, detail: 'Verified test fixture' })) }, migrations: [], createdAt: now(), publishedAt: null };
  release.artifactHash = releaseArtifactHash(release); app.previewReleaseId = release.id; return { app, job, release };
}
function config(root: string): Config { return { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: root, workspaceDir: join(root, 'workspaces'), oidcClientId: 'test', secretKey: Buffer.alloc(32, 42), requestLimitUsd: 1, monthlyLimitUsd: 5, adminDist: join(root, 'absent-dist'), reportToken: 'maintenance-test-token-with-32-characters' }; }
async function setup(dependencies: Parameters<typeof createServer>[2] = {}, overrides: Partial<Config> = {}) {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-control-')); const store = new JsonStore(); await store.initialize(); const server = await createServer({ ...config(root), ...overrides }, store, dependencies);
  const response = await server.inject({ method: 'GET', url: '/api/v1/session' }); const cookie = response.cookies[0]!;
  const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: 'http://127.0.0.1:3000', 'x-csrf-token': response.json().csrfToken as string };
  const close = async () => { await server.close(); await store.close(); await rm(root, { force: true, recursive: true }); }; return { root, store, server, headers, close };
}
test('JSON store atomically persists events/outbox and discards failed transactions', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-store-')); const path = join(root, 'state.json'); const store = new JsonStore(path); await store.initialize(); const { app, job } = fixtures();
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; event(state, job, 'queued', 'Recorded'); enqueue(state, job.id); });
  await assert.rejects(store.transaction(state => { delete state.apps[app.id]; throw new Error('rollback'); }));
  const reopened = new JsonStore(path); await reopened.initialize(); assert.equal(await reopened.read(state => state.apps[app.id]?.name), 'Test app'); assert.equal(await reopened.read(state => state.events.length), 1); assert.equal(await reopened.read(state => Object.values(state.outbox)[0]?.jobId), job.id);
  await rm(root, { recursive: true, force: true });
});
test('concurrent reservations cannot exceed a job budget and settlement is idempotent', async () => {
  const store = new JsonStore(); const { app, job } = fixtures(); await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; }); const hooks = new BudgetManager(store, 1, 5).hooks(job.id);
  const results = await Promise.allSettled([hooks.reserve(0.7), hooks.reserve(0.7)]); assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const id = (results.find(result => result.status === 'fulfilled') as PromiseFulfilledResult<string>).value; await hooks.settle(id, 0.3); await hooks.settle(id, 0.3); assert.equal(await store.read(state => state.jobs[job.id]?.costUsd), 0.3);
});
test('workflow provider outage records actionable attention and never creates a release', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-engine-')); const store = new JsonStore(); const { app, job } = fixtures(); await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
  const engine = new WorkflowEngine(store, {}, new BudgetManager(store, 1, 5), root); await engine.run(job.id); const state = await store.read(state => state);
  assert.equal(state.jobs[job.id]?.stage, 'needs_attention'); assert.match(String(state.jobs[job.id]?.result?.error), /model provider/); assert.equal(state.jobs[job.id]?.result?.attentionKind, 'setup'); assert.match(String(state.jobs[job.id]?.result?.recoveryHint), /Never enter passwords/); assert.equal(Object.keys(state.releases).length, 0); assert.equal(Object.keys(state.leases).length, 0); await rm(root, { recursive: true, force: true });
});
test('worker lease recovery increments the durable app fence and an old worker cannot complete the job', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-fence-')); const store = new JsonStore(join(root, 'state.json')); await store.initialize(); const { app, job } = fixtures(); app.runtimeFence = 4;
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
  let started!: () => void, finish!: () => void; const entered = new Promise<void>(resolve => { started = resolve; }); const blocked = new Promise<void>(resolve => { finish = resolve; }); let oldFence = 0, newFence = 0, verifications = 0;
  const old = new WorkflowEngine(store, { planAndGenerate: async (input, hooks) => { oldFence = input.job.runtimeFence!; const incurred = await hooks.reserve(0.1); started(); await blocked; await assert.rejects(hooks.reserve(0.1), /no further model spending/); await hooks.settle(incurred, 0.05); return { specification: { goal: 'Old worker output' }, files: [{ path: 'src/main.ts', content: 'export const stale = true;' }], pipeline: {}, summary: 'Stale output' }; }, verify: async () => { verifications++; throw new Error('Old worker must never verify'); } }, new BudgetManager(store, 1, 5), root);
  const running = old.run(job.id);
  try {
    await entered; assert.equal(oldFence, 5); await store.transaction(state => { state.leases[job.id]!.until = new Date(Date.now() - 1).toISOString(); });
    const replacement = new WorkflowEngine(store, { planAndGenerate: async input => { newFence = input.job.runtimeFence!; return { specification: { questions: ['Which document categories?'] }, files: [], pipeline: null, summary: '' }; } }, new BudgetManager(store, 1, 5), root);
    await replacement.recover(); await replacement.run(job.id); finish(); await running;
    const state = await store.read(state => state); assert.equal(newFence, 6); assert.equal(state.apps[app.id]?.runtimeFence, 6); assert.equal(state.jobs[job.id]?.runtimeFence, 6); assert.equal(state.jobs[job.id]?.stage, 'clarification'); assert.deepEqual(state.jobs[job.id]?.specification?.questions, ['Which document categories?']); assert.equal(verifications, 0); assert.equal(Object.keys(state.releases).length, 0);
    const reopened = new JsonStore(join(root, 'state.json')); await reopened.initialize(); assert.equal(await reopened.read(state => state.apps[app.id]?.runtimeFence), 6); assert.equal(await reopened.read(state => state.jobs[job.id]?.runtimeFence), 6);
  } finally { finish(); await running; await rm(root, { recursive: true, force: true }); }
});
test('mandatory unavailable verification blocks generated release and preserves source', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-engine-')); const store = new JsonStore(); const { app, job } = fixtures(); await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
  const engine = new WorkflowEngine(store, { planAndGenerate: async () => ({ specification: { goal: 'Documents' }, files: [{ path: 'src/main.ts', content: 'export const ready = true;' }], pipeline: { version: 1 }, summary: 'Documents' }) }, new BudgetManager(store, 1, 5), root);
  await engine.run(job.id); assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'needs_attention'); assert.equal(await store.read(state => Object.keys(state.releases).length), 0); assert.equal(await store.read(state => state.jobs[job.id]?.specification?.goal), 'Documents'); await rm(root, { recursive: true, force: true });
});
test('generated paths reject traversal, absolute paths, protected metadata and existing artifacts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-paths-'));
  for (const path of ['../outside', '/outside', 'C:/outside', 'C:relative', 'src/file:stream', 'src/line\nbreak', 'a\\outside', '.git/config', '.env.production', '.npmrc']) await assert.rejects(writeScopedFiles(root, [{ path, content: 'secret' }]));
  await writeScopedFiles(root, [{ path: 'src/main.ts', content: 'safe' }]); await assert.rejects(writeScopedFiles(root, [{ path: 'src/main.ts', content: 'overwrite' }])); assert.equal(await readFile(join(root, 'src/main.ts'), 'utf8'), 'safe'); await rm(root, { recursive: true, force: true });
});
test('mutations require exact origin and CSRF, and development sessions reject remote clients', async () => {
  const context = await setup(); try {
    const unauthorized = await context.server.inject({ method: 'POST', url: '/api/v1/apps', headers: { cookie: context.headers.cookie }, payload: { name: 'Test' } }); assert.equal(unauthorized.statusCode, 403);
    const wrongOrigin = await context.server.inject({ method: 'POST', url: '/api/v1/apps', headers: { ...context.headers, origin: 'https://evil.test' }, payload: { name: 'Test' } }); assert.equal(wrongOrigin.statusCode, 403);
    const remote = await context.server.inject({ method: 'GET', url: '/api/v1/session', remoteAddress: '10.0.0.5' }); assert.equal(remote.statusCode, 403);
    const created = await context.server.inject({ method: 'POST', url: '/api/v1/apps', headers: context.headers, payload: { name: 'Documents', kind: 'web' } }); assert.equal(created.statusCode, 200);
  } finally { await context.close(); }
});
test('jobs and durable outbox are created in one transition; concurrent requests serialize', async () => {
  const context = await setup(); const { app } = fixtures(); try {
    await context.store.transaction(state => { state.apps[app.id] = app; });
    const results = await Promise.all([1, 2].map(() => context.server.inject({ method: 'POST', url: `/api/v1/apps/${app.id}/jobs`, headers: context.headers, payload: { request: 'Create a document system' } })));
    assert.deepEqual(results.map(result => result.statusCode).sort(), [200, 409]); assert.equal(await context.store.read(state => Object.keys(state.jobs).length), 1); assert.equal(await context.store.read(state => Object.keys(state.outbox).length), 1);
  } finally { await context.close(); }
});
test('credentials are encrypted at rest and excluded from connection responses', async () => {
  const context = await setup(); try {
    const response = await context.server.inject({ method: 'POST', url: '/api/v1/connections', headers: context.headers, payload: { name: 'Email', type: 'email', credentials: { password: 'test-sensitive-secret' } } }); assert.equal(response.statusCode, 200); assert.ok(!response.body.includes('test-sensitive-secret'));
    const secrets = await context.store.read(state => JSON.stringify(state.secrets)); assert.ok(!secrets.includes('test-sensitive-secret')); assert.notEqual(secrets, '{}');
  } finally { await context.close(); }
});
test('approval is bound to artifact and cannot approve changed source or publish unavailable security', async () => {
  let deployments = 0; const context = await setup({ deploy: async () => { deployments++; return { healthy: true, url: 'https://app.test' }; } }); const { app, release } = fixtures(); try {
    await context.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const created = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers: context.headers, payload: {} }); assert.equal(created.statusCode, 200); const approvalId = created.json().approval.id as string;
    const wrong = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approvalId}/approve`, headers: context.headers, payload: { artifactHash: 'c'.repeat(64) } }); assert.equal(wrong.statusCode, 409);
    const approved = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approvalId}/approve`, headers: context.headers, payload: { artifactHash: release.artifactHash } }); assert.equal(approved.statusCode, 200);
    await context.store.transaction(state => { state.releases[release.id]!.evidence.status = 'unavailable'; });
    const published = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/publish`, headers: context.headers, payload: { approvalId } }); assert.equal(published.statusCode, 409); assert.equal(deployments, 0);
  } finally { await context.close(); }
});
test('publish consumes exact approval once and verifies deployment health before switching recorded release', async () => {
  let deployments = 0; const context = await setup({ deploy: async () => { deployments++; return { healthy: true, url: 'https://app.test' }; } }); const { app, release } = fixtures(); try {
    await context.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const created = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers: context.headers, payload: {} }); const approvalId = created.json().approval.id as string;
    await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approvalId}/approve`, headers: context.headers, payload: { artifactHash: release.artifactHash } });
    const published = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/publish`, headers: context.headers, payload: { approvalId } }); assert.equal(published.statusCode, 200, published.body); assert.equal(await context.store.read(state => state.apps[app.id]?.activeReleaseId), release.id);
    const again = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/publish`, headers: context.headers, payload: { approvalId } }); assert.equal(again.statusCode, 409); assert.equal(deployments, 1);
  } finally { await context.close(); }
});
test('a confirmed pre-execution rejection returns its deployment job to review atomically', async () => {
  const context = await setup({ deploy: async () => { throw Object.assign(new Error('Security changed before execution'), { confirmedRejected: true }); } });
  const { app, job, release } = fixtures(); try {
    job.stage = 'awaiting_approval'; job.result = { releaseId: release.id };
    await context.store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.releases[release.id] = release; });
    const reviewed = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers: context.headers, payload: {} }); const approval = reviewed.json().approval;
    await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: context.headers, payload: { artifactHash: approval.artifactHash } });
    const publication = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/publish`, headers: context.headers, payload: { approvalId: approval.id } }); assert.equal(publication.statusCode, 503);
    const state = await context.store.read(state => state); const operation = Object.values(state.operations)[0]!;
    assert.equal(operation.status, 'failed'); assert.equal(operation.approvalId, approval.id); assert.equal(operation.artifactHash, release.artifactHash);
    assert.equal(state.jobs[job.id]?.stage, 'awaiting_approval'); assert.equal(state.apps[app.id]?.activeReleaseId, null); assert.ok(state.approvals[approval.id]?.consumedAt);
    assert.match(state.events.at(-1)!.message, /Publication did not occur/);
    const nextReview = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers: context.headers, payload: {} }); assert.equal(nextReview.statusCode, 200);
    const reused = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/publish`, headers: context.headers, payload: { approvalId: approval.id } }); assert.equal(reused.statusCode, 409);
  } finally { await context.close(); }
});
test('an uncertain publication error never claims cancellation or returns its job to review', async () => {
  const context = await setup({ deploy: async () => { throw new Error('Connection interrupted after submission'); }, operation: async () => ({ status: 'unknown' }) }); const { app, job, release } = fixtures(); try {
    job.stage = 'awaiting_approval'; job.result = { releaseId: release.id }; await context.store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.releases[release.id] = release; });
    const reviewed = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers: context.headers, payload: {} }); const approval = reviewed.json().approval;
    await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: context.headers, payload: { artifactHash: approval.artifactHash } });
    const publication = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/publish`, headers: context.headers, payload: { approvalId: approval.id } }); assert.equal(publication.statusCode, 503);
    assert.equal(await context.store.read(state => Object.values(state.operations)[0]?.status), 'running'); assert.equal(await context.store.read(state => state.jobs[job.id]?.stage), 'deployment');
  } finally { await context.close(); }
});
test('chat cancellation cannot claim to stop an already submitted publication', async () => {
  const context = await setup(); const { app, job, release } = fixtures(); try {
    job.result = { releaseId: release.id }; await context.store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.releases[release.id] = release; });
    for (const stage of ['deployment', 'observation'] as const) {
      await context.store.transaction(state => { state.jobs[job.id]!.stage = stage; });
      const cancelled = await context.server.inject({ method: 'POST', url: `/api/v1/jobs/${job.id}/cancel`, headers: context.headers, payload: {} }); assert.equal(cancelled.statusCode, 409); assert.match(cancelled.body, /cannot safely stop publication/); assert.equal(await context.store.read(state => state.jobs[job.id]?.stage), stage);
    }
    assert.equal(await context.store.read(state => state.events.length), 0);
  } finally { await context.close(); }
});
test('daily reports require maintenance authentication, reject false pass claims, and deduplicate findings', async () => {
  const context = await setup(); try {
    const finding = { id: 'CVE-TEST-1', severity: 'HIGH', package: 'example', installedVersion: '1.0', fixedVersion: '1.1', source: 'vendor', description: 'Test finding' };
    const body = { subject: 'vm', status: 'failed', checkedAt: now(), feedUpdatedAt: now(), findings: [finding], coverage: [{ name: 'os', status: 'passed', detail: 'Completed scan' }] };
    const denied = await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', payload: body }); assert.equal(denied.statusCode, 401);
    const headers = { authorization: 'Bearer maintenance-test-token-with-32-characters' };
    const falselyPassed = await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload: { ...body, status: 'passed' } }); assert.equal(falselyPassed.statusCode, 400);
    const first = await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload: body }); assert.equal(first.statusCode, 200);
    const repeat = await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload: { ...body, checkedAt: new Date(Date.now() + 1000).toISOString() } }); assert.equal(repeat.statusCode, 200);
    assert.equal(await context.store.read(state => Object.values(state.notifications).filter(item => item.title.includes('security finding')).length), 1);
    const resolved = await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload: { ...body, checkedAt: new Date(Date.now() + 2000).toISOString(), status: 'passed', findings: [] } }); assert.equal(resolved.statusCode, 200);
    const security = await context.server.inject({ method: 'GET', url: '/api/v1/security', headers: context.headers }); assert.equal(security.json().findings.length, 0); assert.equal(security.json().vm.status, 'passed');
  } finally { await context.close(); }
});
test('a new active app finding schedules a bounded remediation candidate without publishing', async () => {
  const context = await setup(); const { app, release } = fixtures(); try {
    app.activeReleaseId = release.id; app.status = 'published'; release.status = 'published'; await context.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const body = { subject: 'app', appId: app.id, releaseId: release.id, status: 'failed', checkedAt: now(), feedUpdatedAt: now(), findings: [{ id: 'CVE-TEST-2', severity: 'MEDIUM', package: 'example', installedVersion: '1.0', source: 'vendor', description: 'Test finding' }], coverage: [{ name: 'dependencies', status: 'passed', detail: 'Scanned' }] };
    const report = await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers: { authorization: 'Bearer maintenance-test-token-with-32-characters' }, payload: body }); assert.equal(report.statusCode, 200);
    const state = await context.store.read(state => state); assert.equal(Object.values(state.jobs).length, 1); assert.equal(Object.values(state.jobs)[0]?.budgetUsd, 1); assert.equal(state.apps[app.id]?.activeReleaseId, release.id); assert.equal(Object.values(state.outbox).length, 1);
  } finally { await context.close(); }
});
test('destructive approvals require independently reported restore verification for the exact app', async () => {
  const context = await setup(); const { app, release } = fixtures(); try {
    release.migrations = [{ id: 'remove-column', destructive: true, impact: 'Remove legacy_index from 10 records; checkpoint cp-1 preserves original rows.', checksum: 'f'.repeat(64) }]; release.artifactHash = releaseArtifactHash(release);
    await context.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const denied = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers: context.headers, payload: { checkpointId: 'cp-1' } }); assert.equal(denied.statusCode, 409);
    const backup = await context.server.inject({ method: 'POST', url: '/internal/v1/backup-reports', headers: { authorization: 'Bearer maintenance-test-token-with-32-characters' }, payload: { kind: 'restore_verification', status: 'passed', completedAt: now(), checkpointId: 'cp-1', manifestHash: 'c'.repeat(64), expiresAt: new Date(Date.now() + 600000).toISOString(), appIds: [app.id], detail: 'Separate restoration verified all row counts and document hashes.' } }); assert.equal(backup.statusCode, 200);
    const allowed = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers: context.headers, payload: { checkpointId: 'cp-1' } }); assert.equal(allowed.statusCode, 200); assert.ok(allowed.json().approval.impact.some((item: string) => item.includes('DESTRUCTIVE')));
  } finally { await context.close(); }
});
test('deployment recovery reconciles a trusted receipt without replaying publication', async () => {
  const store = new JsonStore(); const { app, release } = fixtures(); const operationId = randomUUID();
  await store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; state.operations[operationId] = { id: operationId, appId: app.id, releaseId: release.id, baseReleaseId: null, action: 'publish', status: 'running', createdAt: now() }; });
  let calls = 0;
  await reconcileDeployments(store, { operation: async () => ({ status: 'unknown' }), deploy: async () => { calls++; throw new Error('Must not replay'); } }); assert.equal(await store.read(state => state.operations[operationId]?.status), 'running');
  await reconcileDeployments(store, { operation: async () => ({ status: 'succeeded', healthy: true, url: 'https://app.test', appId: app.id, releaseId: release.id }), deploy: async () => { calls++; throw new Error('Must not replay'); } });
  assert.equal(await store.read(state => state.operations[operationId]?.status), 'succeeded'); assert.equal(await store.read(state => state.apps[app.id]?.activeReleaseId), release.id); assert.equal(calls, 0);
});
test('deployment recovery rejects a receipt for a different app', async () => {
  const store = new JsonStore(); const { app, release } = fixtures(); const operationId = randomUUID();
  await store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; state.operations[operationId] = { id: operationId, appId: app.id, releaseId: release.id, baseReleaseId: null, action: 'publish', status: 'running', createdAt: now() }; });
  await reconcileDeployments(store, { operation: async () => ({ status: 'succeeded', healthy: true, url: 'https://app.test', appId: randomUUID(), releaseId: release.id }) });
  assert.equal(await store.read(state => state.operations[operationId]?.status), 'running'); assert.equal(await store.read(state => state.apps[app.id]?.activeReleaseId), null);
});
test('an unknown stale publication unlocks only after an exact broker tombstone, without replay', async () => {
  const store = new JsonStore(); const { app, job, release } = fixtures(); const operationId = randomUUID(), approvalId = randomUUID();
  job.stage = 'deployment'; job.result = { releaseId: release.id };
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.releases[release.id] = release; state.operations[operationId] = { id: operationId, appId: app.id, releaseId: release.id, baseReleaseId: null, action: 'publish', status: 'running', approvalId, artifactHash: release.artifactHash, createdAt: new Date(Date.now() - 6 * 60000).toISOString() }; });
  let cancellations = 0, publications = 0; const dependencies = {
    operation: async () => ({ status: 'unknown' as const }), deploy: async () => { publications++; throw new Error('Must never replay publication'); },
    cancelOperation: async (input: { operationId: string; appId: string; releaseId: string; approvalId: string; artifactHash: string }) => { cancellations++; assert.deepEqual(input, { operationId, appId: app.id, releaseId: release.id, approvalId, artifactHash: release.artifactHash }); return { status: 'failed' as const, appId: app.id, releaseId: release.id }; }
  };
  await reconcileDeployments(store, dependencies); await reconcileDeployments(store, dependencies);
  assert.equal(cancellations, 1); assert.equal(publications, 0); assert.equal(await store.read(state => state.operations[operationId]?.status), 'failed'); assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'awaiting_approval'); assert.equal(await store.read(state => state.events.length), 1);
});
test('fresh unknown and started publications are never tombstoned, and mismatched tombstones remain pending', async () => {
  const store = new JsonStore(); const { app, release } = fixtures(); const operationId = randomUUID();
  await store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; state.operations[operationId] = { id: operationId, appId: app.id, releaseId: release.id, baseReleaseId: null, action: 'publish', status: 'running', approvalId: randomUUID(), artifactHash: release.artifactHash, createdAt: now() }; });
  let calls = 0; const cancelOperation = async () => { calls++; return { status: 'failed' as const, appId: randomUUID(), releaseId: release.id }; };
  await reconcileDeployments(store, { operation: async () => ({ status: 'unknown' }), cancelOperation }); assert.equal(calls, 0);
  await store.transaction(state => { state.operations[operationId]!.createdAt = new Date(Date.now() - 6 * 60000).toISOString(); });
  await reconcileDeployments(store, { operation: async () => ({ status: 'running' }), cancelOperation }); assert.equal(calls, 0);
  await reconcileDeployments(store, { operation: async () => ({ status: 'unknown' }), cancelOperation }); assert.equal(calls, 1); assert.equal(await store.read(state => state.operations[operationId]?.status), 'running'); assert.match(await store.read(state => state.operations[operationId]?.error ?? ''), /expected application/);
});
test('a budget increase requires exact approval, is consumed once and resumes only a budget pause', async () => {
  const context = await setup(); const { app, job } = fixtures(); try {
    job.stage = 'needs_attention'; job.result = { budgetBlocked: true }; await context.store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
    const review = await context.server.inject({ method: 'POST', url: `/api/v1/jobs/${job.id}/budget-approval`, headers: context.headers, payload: { newBudgetUsd: 2 } }); assert.equal(review.statusCode, 200); const approval = review.json().approval;
    const before = await context.server.inject({ method: 'POST', url: `/api/v1/jobs/${job.id}/extend-budget`, headers: context.headers, payload: { approvalId: approval.id } }); assert.equal(before.statusCode, 409);
    const approved = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: context.headers, payload: { artifactHash: approval.artifactHash } }); assert.equal(approved.statusCode, 200, approved.body);
    const applied = await context.server.inject({ method: 'POST', url: `/api/v1/jobs/${job.id}/extend-budget`, headers: context.headers, payload: { approvalId: approval.id } }); assert.equal(applied.statusCode, 200); assert.equal(applied.json().job.budgetUsd, 2); assert.equal(applied.json().job.stage, 'queued');
    const again = await context.server.inject({ method: 'POST', url: `/api/v1/jobs/${job.id}/extend-budget`, headers: context.headers, payload: { approvalId: approval.id } }); assert.equal(again.statusCode, 409); assert.equal(await context.store.read(state => Object.keys(state.outbox).length), 1);
  } finally { await context.close(); }
});
test('monthly cap changes persist and live reservations enforce the approved cap', async () => {
  const context = await setup(); const { app, job } = fixtures(); try {
    job.budgetUsd = 12; await context.store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
    const review = await context.server.inject({ method: 'POST', url: '/api/v1/budget/monthly-approval', headers: context.headers, payload: { newMonthlyLimitUsd: 10 } }); assert.equal(review.statusCode, 200); const approval = review.json().approval;
    await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: context.headers, payload: { artifactHash: approval.artifactHash } });
    const applied = await context.server.inject({ method: 'POST', url: '/api/v1/budget/extend-monthly', headers: context.headers, payload: { approvalId: approval.id } }); assert.equal(applied.statusCode, 200); assert.equal(applied.json().monthlyLimitUsd, 10);
    const hooks = new BudgetManager(context.store, 1, 5).hooks(job.id); const id = await hooks.reserve(6); await hooks.settle(id, 6); await assert.rejects(hooks.reserve(5), /spending limit/);
  } finally { await context.close(); }
});
test('new daily security evidence invalidates an otherwise unchanged release approval', async () => {
  const context = await setup(); const { app, release } = fixtures(); try {
    await context.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const review = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers: context.headers, payload: {} }); const approval = review.json().approval;
    const report = await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers: { authorization: 'Bearer maintenance-test-token-with-32-characters' }, payload: { subject: 'app', appId: app.id, releaseId: release.id, status: 'passed', checkedAt: now(), feedUpdatedAt: now(), findings: [], coverage: [{ name: 'dependencies', status: 'passed', detail: 'Current security evidence' }] } }); assert.equal(report.statusCode, 200);
    const approvalResult = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: context.headers, payload: { artifactHash: approval.artifactHash } }); assert.equal(approvalResult.statusCode, 409); assert.match(approvalResult.body, /Security evidence changed/);
  } finally { await context.close(); }
});
test('Prometheus exposes actual process counters and recorded app counts only on development loopback', async () => {
  const context = await setup(); const { app } = fixtures(); try {
    await context.store.transaction(state => { state.apps[app.id] = app; }); const response = await context.server.inject({ method: 'GET', url: '/metrics' }); assert.equal(response.statusCode, 200); assert.match(response.body, /autosoft_process_cpu_user_seconds_total/); assert.match(response.body, /autosoft_applications\{status="draft"\} 1/);
    const remote = await context.server.inject({ method: 'GET', url: '/metrics', remoteAddress: '10.0.0.6' }); assert.equal(remote.statusCode, 403);
  } finally { await context.close(); }
});
test('verified build failures repair at most three times per stage and pass actual diagnostics and source', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-repair-')); const store = new JsonStore(); const { app, job, release } = fixtures(); await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; }); let generations = 0;
  const evidence = { ...release.evidence, status: 'failed' as const, checks: release.evidence.checks.map(check => check.name === 'build' ? { ...check, passed: false, detail: 'Type mismatch at src/main.ts:1' } : check) };
  const engine = new WorkflowEngine(store, { planAndGenerate: async input => { generations++; if (generations > 1) { assert.ok(input.context.previousFiles?.some(file => file.path === 'src/main.ts')); assert.ok(JSON.stringify(input.context.failureEvidence).includes('Type mismatch')); } return { specification: { goal: 'Documents' }, files: [{ path: 'src/main.ts', content: 'export const broken = 1;' }], pipeline: boundPipeline, summary: 'Documents' }; }, verify: async () => ({ evidence, images: [], commit: '', previewUrl: null }) }, new BudgetManager(store, 1, 5), root);
  for (let attempt = 0; attempt < 4; attempt++) await engine.run(job.id);
  assert.equal(generations, 4); assert.equal(await store.read(state => state.repairAttempts[job.id]?.verification), 3); assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'needs_attention'); assert.equal(await store.read(state => Object.keys(state.releases).length), 0); await rm(root, { recursive: true, force: true });
});
test('missing scan freshness never enters automatic verification repair', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-repair-')); const store = new JsonStore(); const { app, job, release } = fixtures(); await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
  const evidence = { ...release.evidence, status: 'failed' as const, feedUpdatedAt: '', checks: [{ name: 'build', passed: false, detail: 'Compilation failed' }] };
  const engine = new WorkflowEngine(store, { planAndGenerate: async () => ({ specification: { goal: 'Documents' }, files: [{ path: 'src/main.ts', content: 'export const broken = 1;' }], pipeline: boundPipeline, summary: 'Documents' }), verify: async () => ({ evidence, images: [], commit: '', previewUrl: null }) }, new BudgetManager(store, 1, 5), root);
  await engine.run(job.id); assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'needs_attention'); assert.equal(await store.read(state => state.repairAttempts[job.id]), undefined); await rm(root, { recursive: true, force: true });
});
test('SSE replays persisted events after Last-Event-ID and streams subsequent durable progress', async () => {
  const context = await setup(); const { app, job } = fixtures(); const cancellation = new AbortController(); try {
    await context.store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; event(state, job, 'queued', 'First recorded event'); event(state, job, 'specification', 'Second recorded event'); });
    const address = await context.server.listen({ port: 0, host: '127.0.0.1' }); const response = await fetch(`${address}/api/v1/jobs/${job.id}/events`, { headers: { cookie: context.headers.cookie, 'last-event-id': '1' }, signal: cancellation.signal });
    assert.equal(response.status, 200); const reader = response.body!.getReader(); const decoder = new TextDecoder(); const first = decoder.decode((await reader.read()).value); assert.match(first, /Second recorded event/); assert.ok(!first.includes('First recorded event'));
    await context.store.transaction(state => { event(state, state.jobs[job.id]!, 'implementation', 'Third durable event'); });
    let next = ''; for (let attempt = 0; attempt < 3 && !next.includes('Third durable event'); attempt++) next += decoder.decode((await reader.read()).value);
    assert.match(next, /Third durable event/); cancellation.abort();
  } finally { cancellation.abort(); await context.close(); }
});
test('preview tickets are single-use, host-scoped and tied to the MFA administration session', async () => {
  const context = await setup({}, { appsOrigin: 'https://apps.example.test' }); const { app, release } = fixtures(); app.previewUrl = `https://preview-${app.slug}.apps.example.test`;
  try {
    await context.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const launch = await context.server.inject({ method: 'GET', url: `/api/v1/apps/${app.id}/preview-launch`, headers: context.headers }); assert.equal(launch.statusCode, 302, launch.body);
    const destination = new URL(launch.headers.location!); const ticket = destination.searchParams.get('ticket')!; assert.equal(destination.pathname, '/__autosoft/preview'); assert.ok(!JSON.stringify(await context.store.read(state => state.previewTickets)).includes(ticket));
    const wrongHost = await context.server.inject({ method: 'GET', url: `/api/auth/preview/exchange?ticket=${ticket}`, headers: { host: 'preview-other.apps.example.test' } }); assert.equal(wrongHost.statusCode, 401);
    const exchanged = await context.server.inject({ method: 'GET', url: `/api/auth/preview/exchange?ticket=${ticket}`, headers: { host: destination.host } }); assert.equal(exchanged.statusCode, 302); assert.equal(exchanged.headers.location, '/');
    const cookie = exchanged.cookies[0]!; assert.equal(cookie.name, '__Host-autosoft-preview'); assert.equal(cookie.secure, true); assert.equal(cookie.httpOnly, true); assert.equal(cookie.path, '/'); assert.equal(cookie.domain, undefined);
    const replay = await context.server.inject({ method: 'GET', url: `/api/auth/preview/exchange?ticket=${ticket}`, headers: { host: destination.host } }); assert.equal(replay.statusCode, 401);
    const previewHeaders = { host: destination.host, 'x-autosoft-preview-host': destination.host, cookie: `${cookie.name}=${cookie.value}` };
    const allowed = await context.server.inject({ method: 'GET', url: '/api/auth/check', headers: previewHeaders }); assert.equal(allowed.statusCode, 200, allowed.body);
    const crossApp = await context.server.inject({ method: 'GET', url: '/api/auth/check', headers: { ...previewHeaders, host: 'preview-other.apps.example.test', 'x-autosoft-preview-host': 'preview-other.apps.example.test' } }); assert.equal(crossApp.statusCode, 401);
    const productionAuthority = await context.store.read(state => Object.values(state.previewSessions)[0]!); await context.store.transaction(state => { delete state.sessions[productionAuthority.sessionId]; });
    const revoked = await context.server.inject({ method: 'GET', url: '/api/auth/check', headers: previewHeaders }); assert.equal(revoked.statusCode, 401);
  } finally { await context.close(); }
});
test('replacement previews invalidate old tickets and block review and publication of older candidates', async () => {
  let publications = 0; const context = await setup({ deploy: async () => { publications++; return { healthy: true, url: 'https://test-app.apps.example.test' }; } }, { appsOrigin: 'https://apps.example.test' });
  const { app, release: first } = fixtures(); app.previewUrl = `https://preview-${app.slug}.apps.example.test`;
  const second: ReleaseRecord = { ...first, id: randomUUID(), version: '0.2.0', commit: 'd'.repeat(40), images: [`registry.test/app@sha256:${'e'.repeat(64)}`] }; second.artifactHash = releaseArtifactHash(second);
  try {
    await context.store.transaction(state => { state.apps[app.id] = app; state.releases[first.id] = first; state.releases[second.id] = second; });
    const review = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${first.id}/approval`, headers: context.headers, payload: {} }); const approved = review.json().approval;
    await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approved.id}/approve`, headers: context.headers, payload: { artifactHash: approved.artifactHash } });
    const pendingReview = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${first.id}/approval`, headers: context.headers, payload: {} }); const pending = pendingReview.json().approval;
    const launch = await context.server.inject({ method: 'GET', url: `/api/v1/apps/${app.id}/preview-launch?releaseId=${first.id}`, headers: context.headers }); const destination = new URL(launch.headers.location!); const ticket = destination.searchParams.get('ticket')!;
    await context.store.transaction(state => { state.apps[app.id]!.previewReleaseId = second.id; });
    const oldTicket = await context.server.inject({ method: 'GET', url: `/api/auth/preview/exchange?ticket=${ticket}`, headers: { host: destination.host } }); assert.equal(oldTicket.statusCode, 401);
    const oldPreview = await context.server.inject({ method: 'GET', url: `/api/v1/apps/${app.id}/preview-launch?releaseId=${first.id}`, headers: context.headers }); assert.equal(oldPreview.statusCode, 409);
    const oldReview = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${first.id}/approval`, headers: context.headers, payload: {} }); assert.equal(oldReview.statusCode, 409);
    const oldApprove = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${pending.id}/approve`, headers: context.headers, payload: { artifactHash: pending.artifactHash } }); assert.equal(oldApprove.statusCode, 409);
    const oldPublish = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${first.id}/publish`, headers: context.headers, payload: { approvalId: approved.id } }); assert.equal(oldPublish.statusCode, 409); assert.equal(publications, 0);
    const newPreview = await context.server.inject({ method: 'GET', url: `/api/v1/apps/${app.id}/preview-launch?releaseId=${second.id}`, headers: context.headers }); assert.equal(newPreview.statusCode, 302);
    const newReview = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${second.id}/approval`, headers: context.headers, payload: {} }); const latest = newReview.json().approval;
    const newApproval = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${latest.id}/approve`, headers: context.headers, payload: { artifactHash: latest.artifactHash } }); assert.equal(newApproval.statusCode, 200);
    const newPublish = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${second.id}/publish`, headers: context.headers, payload: { approvalId: latest.id } }); assert.equal(newPublish.statusCode, 200); assert.equal(publications, 1);
  } finally { await context.close(); }
});
test('verification invalidates the previous preview before the broker runs and binds its new release', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-preview-')); const store = new JsonStore(); const { app, job, release } = fixtures(); app.previewUrl = 'https://preview-test-app.apps.example.test';
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.releases[release.id] = release; });
  const engine = new WorkflowEngine(store, {
    planAndGenerate: async () => ({ specification: { goal: 'Documents' }, files: [{ path: 'src/main.ts', content: 'export const ready = true;' }], pipeline: boundPipeline, summary: 'Verified replacement' }),
    verify: async input => { assert.equal(await store.read(state => state.apps[app.id]?.previewReleaseId), null); assert.equal(await store.read(state => state.apps[app.id]?.previewUrl), null); const snapshot=snapshotFixture();snapshot.binding={...snapshot.binding,appId:input.app.id,jobId:input.job.id,attemptId:input.attemptId,fence:input.job.runtimeFence!};snapshot.requestHash=hashArtifact(snapshot.binding);return { appId:input.app.id,attemptId:input.attemptId,filesHash:input.filesHash,sourceBindingVersion:1,inputSourceHash:input.filesHash,pipelineHash:pipelineDefinitionHash(input.pipeline),sourceHash:snapshot.binding.sourceHash,schemaVersion:1,compatibleSchemaMin:1,compatibleSchemaMax:1,migrations:[],migrationSnapshot:snapshot,evidence: release.evidence, images: release.images, commit: release.commit, previewUrl: 'https://preview-test-app.apps.example.test' }; }
  }, new BudgetManager(store, 1, 5), root);
  try { await engine.run(job.id); const state = await store.read(state => state); assert.equal(state.jobs[job.id]?.stage, 'awaiting_approval'); assert.equal(state.apps[app.id]?.previewReleaseId, state.jobs[job.id]?.result?.releaseId); assert.notEqual(state.apps[app.id]?.previewReleaseId, release.id); }
  finally { await rm(root, { recursive: true, force: true }); }
});
test('improvements load the active verified Git source including dependency locks', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-source-')); const store = new JsonStore(); const { app, job, release } = fixtures(); app.activeReleaseId = release.id; job.baseReleaseId = release.id;
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.releases[release.id] = release; }); let loaded = false;
  const engine = new WorkflowEngine(store, { previousSource: async input => { assert.deepEqual(input, { appId: app.id, commit: release.commit }); return { files: [{ path: 'package-lock.json', content: '{"lockfileVersion":3}' }, { path: 'src/main.ts', content: 'export const original = true;' }] }; }, planAndGenerate: async input => { loaded = !!input.context.previousFiles?.some(file => file.path === 'package-lock.json'); return { specification: { questions: ['Which document types are required?'] }, files: [], pipeline: null, summary: '' }; } }, new BudgetManager(store, 1, 5), root);
  try { await engine.run(job.id); assert.equal(loaded, true); assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'clarification'); } finally { await rm(root, { recursive: true, force: true }); }
});
test('credentials entered in chat are rejected before persistent jobs or provider context exist', async () => {
  const context = await setup(); const { app } = fixtures();
  try {
    await context.store.transaction(state => { state.apps[app.id] = app; });
    for(const credential of ['password=should-never-be-stored','whsec_'+'S'.repeat(24),'sk_live_'+'S'.repeat(24),'rk_test_'+'S'.repeat(24)]){
      const response = await context.server.inject({ method: 'POST', url: `/api/v1/apps/${app.id}/jobs`, headers: context.headers, payload: { request: `Connect using ${credential}` } });
      assert.equal(response.statusCode, 400); assert.match(response.body, /protected connection forms/); assert.ok(!response.body.includes(credential)); assert.equal(await context.store.read(state => Object.keys(state.jobs).length), 0);
    }
  } finally { await context.close(); }
});
test('rollback accepts fresh scanning only for its exact immutable target release', async () => {
  let deployed = false; const context = await setup({ deploy: async input => { assert.deepEqual(input.approvedFindings, []); deployed = true; return { url: 'https://test-app.apps.example.test', healthy: true }; } }); const { app, release: target } = fixtures();
  const live: ReleaseRecord = { ...target, id: randomUUID(), version: '0.2.0', status: 'published', commit: 'd'.repeat(40), images: [`registry.test/app@sha256:${'e'.repeat(64)}`] }; live.artifactHash = releaseArtifactHash(live); app.activeReleaseId = live.id; app.status = 'published'; app.previewReleaseId = live.id;
  target.status = 'superseded'; target.evidence = { ...target.evidence, checkedAt: new Date(Date.now() - 2 * 86400000).toISOString(), feedUpdatedAt: new Date(Date.now() - 2 * 86400000).toISOString() }; target.artifactHash = releaseArtifactHash(target); const immutable = target.artifactHash;
  const maintenance = { authorization: 'Bearer maintenance-test-token-with-32-characters' }; const scanned = (releaseId: string) => ({ subject: 'app', appId: app.id, releaseId, status: 'passed', checkedAt: now(), feedUpdatedAt: now(), findings: [], coverage: [{ name: 'image', status: 'passed', detail: 'Exact image digest scanned using current advisory data' }] });
  try {
    await context.store.transaction(state => { state.apps[app.id] = app; state.releases[target.id] = target; state.releases[live.id] = live; });
    await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers: maintenance, payload: scanned(live.id) });
    const before = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${target.id}/approval`, headers: context.headers, payload: { action: 'rollback' } }); const stale = before.json().approval;
    const refused = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${stale.id}/approve`, headers: context.headers, payload: { artifactHash: stale.artifactHash } }); assert.equal(refused.statusCode, 409); assert.equal(deployed, false);
    await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers: maintenance, payload: scanned(target.id) });
    const review = await context.server.inject({ method: 'POST', url: `/api/v1/releases/${target.id}/approval`, headers: context.headers, payload: { action: 'rollback' } }); const approval = review.json().approval;
    const approved = await context.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: context.headers, payload: { artifactHash: approval.artifactHash } }); assert.equal(approved.statusCode, 200, approved.body);
    const rollback = await context.server.inject({ method: 'POST', url: `/api/v1/apps/${app.id}/rollback`, headers: context.headers, payload: { releaseId: target.id, approvalId: approval.id } }); assert.equal(rollback.statusCode, 200, rollback.body); assert.equal(deployed, true); assert.equal(await context.store.read(state => state.releases[target.id]?.artifactHash), immutable);
  } finally { await context.close(); }
});

test('setup, uncertain runtime and budget pauses carry safe distinct recovery guidance', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-attention-'));
  try {
    for (const [failure, kind] of [[new Error('No configured, locally qualified model is available for this development stage'), 'setup'], [new Error('Model connection ended without a confirmed billing outcome; the reservation remains held for reconciliation'), 'runtime_unavailable'], [new BudgetLimitError('The estimated model call exceeds the request or monthly spending limit.'), 'budget']] as const) {
      const store = new JsonStore(); const { app, job } = fixtures(); await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
      const engine = new WorkflowEngine(store, { planAndGenerate: async () => { throw failure; } }, new BudgetManager(store, 1, 5), root); await engine.run(job.id);
      const result = await store.read(state => state.jobs[job.id]?.result); assert.equal(result?.attentionKind, kind); assert.ok(result?.recoveryHint); assert.equal(result?.budgetBlocked, kind === 'budget');
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('independent review repairs preserve untouched published source and stop after three repairs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-review-repair-')); const store = new JsonStore(); const { app, job, release } = fixtures(); app.activeReleaseId = release.id; job.baseReleaseId = release.id; let generations = 0;
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.releases[release.id] = release; });
  const engine = new WorkflowEngine(store, {
    previousSource: async () => ({ files: [{ path: 'src/unchanged.ts', content: 'export const preserved = "document-data-contract";' }, { path: 'src/main.ts', content: 'export const previous = true;' }, { path: 'package-lock.json', content: '{"lockfileVersion":3}' }] }),
    planAndGenerate: async input => {
      generations++; assert.ok(input.context.previousFiles?.some(file => file.path === 'src/unchanged.ts')); assert.ok(input.context.previousFiles?.some(file => file.path === 'package-lock.json'));
      if (generations > 1) { assert.ok(input.context.previousFiles?.some(file => file.content === `export const attempt = ${generations - 1};`)); assert.match(JSON.stringify(input.context.failureEvidence), /Missing backend permission/); }
      throw Object.assign(new Error('Independent code review needs changes: Missing backend permission check'), { partialGeneration: { specification: { goal: 'Preserve documents' }, files: [{ path: 'src/main.ts', content: `export const attempt = ${generations};` }], pipeline: {}, summary: 'Partial repair' } });
    }, verify: async () => { throw new Error('Review failure must never reach a sandbox preview'); }
  }, new BudgetManager(store, 1, 5), root);
  try {
    for (let attempt = 0; attempt < 4; attempt++) await engine.run(job.id); await engine.run(job.id);
    const state = await store.read(state => state); assert.equal(generations, 4); assert.deepEqual(state.repairAttempts[job.id], { review: 3, verification: 0 }); assert.equal(state.jobs[job.id]?.stage, 'needs_attention'); assert.equal(state.jobs[job.id]?.result?.attentionKind, 'verification'); assert.equal(Object.keys(state.releases).length, 1);
    assert.match(await readFile(join(String(state.jobs[job.id]?.result?.workspacePath), 'src/unchanged.ts'), 'utf8'), /document-data-contract/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('malformed or contradictory verification cannot produce a ready release', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-verify-evidence-'));
  try {
    for (const scenario of ['duplicate', 'failed-extra', 'stale-feed', 'unknown-finding', 'wrong-app', 'missing-check', 'unlocked-image', 'no-commit']) {
      const store = new JsonStore(); const { app, job, release } = fixtures(); const evidence = structuredClone(release.evidence); let images = release.images, commit = release.commit;
      if (scenario === 'duplicate') evidence.checks.push({ name: 'security', passed: false, detail: 'Contradictory scan' });
      if (scenario === 'failed-extra') evidence.checks.push({ name: 'credential_scan', passed: false, detail: 'A credential was detected' });
      if (scenario === 'stale-feed') evidence.feedUpdatedAt = new Date(Date.now() - 2 * 86400000).toISOString();
      if (scenario === 'unknown-finding' || scenario === 'wrong-app') evidence.findings.push({ id: 'ADVISORY-TEST', severity: scenario === 'unknown-finding' ? 'UNKNOWN' : 'LOW', package: 'test', installedVersion: '1', source: 'vendor', description: 'Review required', ...(scenario === 'wrong-app' ? { appId: randomUUID() } : {}) });
      if (scenario === 'missing-check') evidence.checks = evidence.checks.filter(check => check.name !== 'acceptance');
      if (scenario === 'unlocked-image') images = ['registry.test/app:latest']; if (scenario === 'no-commit') commit = '';
      await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
      const engine = new WorkflowEngine(store, { planAndGenerate: async () => ({ specification: {}, files: [{ path: 'src/main.ts', content: 'export const ready = true;' }], pipeline: boundPipeline, summary: scenario }), verify: async input => {const snapshot=snapshotFixture();snapshot.binding={...snapshot.binding,appId:input.app.id,jobId:input.job.id,attemptId:input.attemptId,fence:input.job.runtimeFence!};snapshot.requestHash=hashArtifact(snapshot.binding);return {appId:input.app.id,attemptId:input.attemptId,filesHash:input.filesHash,sourceBindingVersion:1,inputSourceHash:input.filesHash,pipelineHash:pipelineDefinitionHash(input.pipeline),sourceHash:snapshot.binding.sourceHash,schemaVersion:1,compatibleSchemaMin:1,compatibleSchemaMax:1,migrations:[],migrationSnapshot:snapshot,evidence,images,commit,previewUrl:'https://preview.test'};} }, new BudgetManager(store, 1, 5), root); await engine.run(job.id);
      assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'needs_attention', scenario); assert.equal(await store.read(state => Object.keys(state.releases).length), 0, scenario); assert.equal(await store.read(state => state.repairAttempts[job.id]), undefined, scenario);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('connection endpoint credentials are refused before registry or secret persistence', async () => {
  const context = await setup();
  try {
    for (const endpoint of ['https://user:protected-value@example.test/mail', 'https://api.example.test/?api_key=protected-value', 'https://api.example.test/?ACCESS_TOKEN=protected-value', 'invalid-url']) {
      const response = await context.server.inject({ method: 'POST', url: '/api/v1/connections', headers: context.headers, payload: { name: 'Protected API', type: 'rest', endpoints: [endpoint] } }); assert.equal(response.statusCode, 400); assert.ok(!response.body.includes('protected-value'));
    }
    assert.equal(await context.store.read(state => Object.keys(state.connections).length), 0); assert.equal(await context.store.read(state => Object.keys(state.secrets).length), 0);
  } finally { await context.close(); }
});

test('telemetry preserves actual normalized metrics and rejects malformed broker values', async () => {
  let malformed = false; const context = await setup({ telemetry: async () => malformed ? { services: [{ name: 'control', status: 'running', cpuPercent: -2 }], broker: { available: true, detail: 'Connected' } } : { services: [{ name: 'control', status: 'running', detail: 'Actual Docker status', cpuPercent: '2.4%', memoryUsage: '150MiB / 1GiB', pids: 12, password: 'not-exposed' }, { name: 'Underlying VM', status: 'healthy', cpuCount: 4, loadAverage: [0.1, 0.2, 0.3], memoryTotalBytes: 17179869184, memoryAvailableBytes: 8589934592, diskTotalBytes: 100000000000, diskFreeBytes: 50000000000, uptimeSeconds: 123, encryptedDataMounted: true }], broker: { available: true, detail: 'Connected' } } });
  try {
    const valid = await context.server.inject({ method: 'GET', url: '/api/v1/telemetry', headers: context.headers }); assert.equal(valid.json().services[0].cpuPercent, '2.4%'); assert.equal(valid.json().services[0].pids, 12); assert.equal(valid.json().services[1].cpuCount, 4); assert.equal(valid.json().services[1].memoryTotalBytes, 17179869184); assert.deepEqual(valid.json().services[1].loadAverage, [0.1, 0.2, 0.3]); assert.equal(valid.json().services[1].encryptedDataMounted, true); assert.ok(!valid.body.includes('not-exposed'));
    malformed = true; const invalid = await context.server.inject({ method: 'GET', url: '/api/v1/telemetry', headers: context.headers }); assert.equal(invalid.statusCode, 200); assert.equal(invalid.json().broker.available, false); assert.deepEqual(invalid.json().services, []); assert.match(invalid.json().broker.detail, /malformed/);
  } finally { await context.close(); }
});

test('read unavailable coverage and identical failed backups do not create repeated notifications', async () => {
  const context = await setup(); const headers = { authorization: 'Bearer maintenance-test-token-with-32-characters' }; const initial = Date.now();
  const scan = (offset: number, detail = 'Company advisory verification unavailable') => ({ subject: 'vm', status: 'unavailable', checkedAt: new Date(initial + offset).toISOString(), feedUpdatedAt: now(), findings: [], coverage: [{ name: 'vendor-advisories', status: 'unavailable', detail }] });
  const backup = (offset: number, detail = 'Encrypted remote destination unavailable') => ({ kind: 'nightly', status: 'failed', completedAt: new Date(initial + offset).toISOString(), detail });
  try {
    for (const [url, payload] of [['/internal/v1/security-reports', scan(0)], ['/internal/v1/backup-reports', backup(0)]] as const) assert.equal((await context.server.inject({ method: 'POST', url, headers, payload })).statusCode, 200);
    await context.store.transaction(state => { for (const notification of Object.values(state.notifications)) notification.read = true; }); assert.equal(await context.store.read(state => Object.keys(state.notifications).length), 2);
    for (const [url, payload] of [['/internal/v1/security-reports', scan(1000)], ['/internal/v1/backup-reports', backup(1000)]] as const) assert.equal((await context.server.inject({ method: 'POST', url, headers, payload })).statusCode, 200);
    assert.equal(await context.store.read(state => Object.keys(state.notifications).length), 2);
    await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload: scan(2000, 'A different scanner is unavailable') }); await context.server.inject({ method: 'POST', url: '/internal/v1/backup-reports', headers, payload: backup(2000, 'Backup archive integrity check failed') });
    assert.equal(await context.store.read(state => Object.keys(state.notifications).length), 4); assert.equal(await context.store.read(state => Object.keys(state.securityReports).length), 3); assert.equal(await context.store.read(state => Object.keys(state.backupReports).length), 3);
  } finally { await context.close(); }
});

test('incomplete scans cannot report resolution, unclassified findings remain actionable and timestamp ordering is numeric', async () => {
  const context = await setup(); const headers = { authorization: 'Bearer maintenance-test-token-with-32-characters' }; const second = new Date(Math.floor(Date.now() / 1000) * 1000 - 2000).toISOString().replace('.000Z', 'Z'); const later = second.replace('Z', '.500000Z');
  const finding = { id: 'CVE-TEST-MIXED-TIME', severity: 'HIGH', package: 'example', installedVersion: '1.0', source: 'vendor', description: 'Test finding' }; const unknown = { ...finding, id: 'ADVISORY-UNCLASSIFIED', severity: 'UNKNOWN' };
  try {
    assert.equal((await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload: { subject: 'vm', status: 'failed', checkedAt: second, feedUpdatedAt: now(), findings: [finding], coverage: [{ name: 'os', status: 'passed', detail: 'Complete' }] } })).statusCode, 200);
    assert.equal((await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload: { subject: 'vm', status: 'unavailable', checkedAt: later, feedUpdatedAt: now(), findings: [unknown], coverage: [{ name: 'os', status: 'unavailable', detail: 'Could not complete' }] } })).statusCode, 200);
    assert.equal(await context.store.read(state => Object.values(state.notifications).filter(item => item.title.includes('finding resolved')).length), 0);
    const response = await context.server.inject({ method: 'GET', url: '/api/v1/security', headers: context.headers }); assert.equal(response.json().vm.checkedAt, later); assert.equal(response.json().findings.length, 1); assert.equal(response.json().findings[0].id, finding.id); assert.equal(response.json().unclassifiedFindings[0].id, unknown.id);
    assert.equal(await context.store.read(state => Object.values(state.notifications).filter(item => item.title.includes('severity needs review')).length), 1);
    const invalidScope = await context.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload: { subject: 'vm', status: 'failed', checkedAt: now(), feedUpdatedAt: now(), findings: [{ ...finding, appId: randomUUID() }], coverage: [] } }); assert.equal(invalidScope.statusCode, 400);
  } finally { await context.close(); }
});

test('open event streams stop after logout or loss of live MFA authorization', async () => {
  for (const action of ['logout', 'mfa-revoked', 'access-expired']) {
    const context = await setup(); const { app, job } = fixtures(); const cancellation = new AbortController();
    try {
      await context.store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; event(state, job, 'queued', 'Authorized initial event'); }); const address = await context.server.listen({ port: 0, host: '127.0.0.1' });
      const response = await fetch(`${address}/api/v1/jobs/${job.id}/events`, { headers: { cookie: context.headers.cookie }, signal: cancellation.signal }); const reader = response.body!.getReader(); const decoder = new TextDecoder(); assert.match(decoder.decode((await reader.read()).value), /Authorized initial event/);
      if (action === 'logout') assert.equal((await context.server.inject({ method: 'POST', url: '/api/v1/logout', headers: context.headers, payload: {} })).statusCode, 200);
      else await context.store.transaction(state => { const session = Object.values(state.sessions)[0]!; if (action === 'mfa-revoked') session.principal.mfa = false; else session.accessExpiresAt = new Date(Date.now() - 1).toISOString(); });
      await context.store.transaction(state => { event(state, state.jobs[job.id]!, 'implementation', 'Private event after revocation'); }); let output = '';
      for (;;) { const next = await reader.read(); if (next.done) break; output += decoder.decode(next.value); }
      assert.match(output, /event: session_expired/); assert.ok(!output.includes('Private event after revocation'));
    } finally { cancellation.abort(); await context.close(); }
  }
});

test('shared allowance blocks HTTP monthly-cap approval and preserves external accounting in telemetry', async () => {
  const context = await setup();
  try {
    await context.store.transaction(state => {
      state.spendingAuthorities['a'.repeat(32)] = { activatedAt: now(), authority: { schemaVersion: 1, id: 'a'.repeat(32), month: authorityMonth(), timezone: 'UTC', adminOrigin: 'https://admin.example.test', beforeLedgerSha256: 'b'.repeat(64), monthlyLimitMicrousd: 30_000_000, confirmedExternalMicrousd: 895128, conservativeExternalMicrousd: 2_000_000, allocationMicrousd: 27104872 } };
    });
    const response = await context.server.inject({ method: 'GET', url: '/api/v1/budget', headers: context.headers });
    assert.equal(response.json().externalConservativeUsd, 2); assert.equal(response.json().externalConfirmedUsd, .895128);
    const denied = await context.server.inject({ method: 'POST', url: '/api/v1/budget/monthly-approval', headers: context.headers, payload: { newMonthlyLimitUsd: 31 } });
    assert.equal(denied.statusCode, 409); assert.match(denied.body, /company-authorized/);
    assert.equal(await context.store.read(state => Object.keys(state.budgetApprovals).length), 0);
  } finally { await context.close(); }
});
