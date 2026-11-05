import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, isAbsolute } from 'node:path';
import { createServer } from '../src/server.ts';
import { JsonStore, emptyState } from '../src/store.ts';
import { latestSecurityReports, securityFindingSnapshot, type SecurityReport } from '../src/reports.ts';
import { WorkflowEngine } from '../src/engine.ts';
import { BudgetManager } from '../src/budget.ts';
import { releaseArtifactHash } from '../../../packages/core/src/index.ts';
import type { AppRecord, Finding, ReleaseRecord } from '../../../packages/core/src/types.ts';
import type { Config } from '../src/config.ts';

const token = 'history-maintenance-token-with-at-least-32-characters';
const headers = { authorization: `Bearer ${token}` };
const started = Date.now() - 600000;
const timestamp = (step = 0) => new Date(started + step * 1000).toISOString();
const finding = (severity: Finding['severity'] = 'HIGH', changes: Partial<Finding> = {}): Finding => ({ id: 'CVE-HISTORY', severity, package: 'library', installedVersion: '1.0', fixedVersion: '1.1', source: 'synthetic-vendor', description: 'Synthetic finding for local tests', ...changes });
function report(step = 0, changes: Partial<SecurityReport> = {}): SecurityReport {
  return { id: randomUUID(), subject: 'vm', status: 'failed', checkedAt: timestamp(step), receivedAt: timestamp(step), feedUpdatedAt: timestamp(step), findings: [finding()], coverage: [{ name: 'os', status: 'passed', detail: 'Synthetic complete coverage' }], ...changes };
}
function fixture() {
  const app: AppRecord = { id: randomUUID(), name: 'History app', slug: 'history-app', description: '', kind: 'web', status: 'published', activeReleaseId: null, url: 'https://history-app.example.test', previewUrl: null, createdAt: timestamp(-1), updatedAt: timestamp(-1) };
  const release: ReleaseRecord = { id: randomUUID(), appId: app.id, version: '0.1.0', summary: 'Synthetic release', artifactHash: '', commit: 'a'.repeat(40), images: [`registry.test/history@sha256:${'b'.repeat(64)}`], schemaVersion: 1, compatibleSchemaMin: 1, compatibleSchemaMax: 1, baseReleaseId: null, status: 'published', evidence: { status: 'passed', checkedAt: timestamp(-1), feedUpdatedAt: timestamp(-1), findings: [], checks: ['dependencies', 'build', 'application_tests', 'security', 'image_packaging', 'preview', 'migration_rehearsal', 'acceptance'].map(name => ({ name, passed: true, detail: 'Synthetic verified fixture' })) }, migrations: [], createdAt: timestamp(-1), publishedAt: timestamp(-1) };
  release.artifactHash = releaseArtifactHash(release); app.activeReleaseId = release.id; app.previewReleaseId = release.id; return { app, release };
}
async function setup() {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-security-history-'));
  const file = join(root, 'state.json'); const store = new JsonStore(file); await store.initialize();
  const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: root, workspaceDir: join(root, 'workspaces'), oidcClientId: 'test', secretKey: Buffer.alloc(32, 42), requestLimitUsd: 1, monthlyLimitUsd: 5, adminDist: join(root, 'absent-dist'), reportToken: token };
  let deployments = 0;
  const server = await createServer(config, store, { deploy: async () => { deployments++; return { healthy: true, url: 'https://history-app.example.test' }; } });
  const session = await server.inject({ method: 'GET', url: '/api/v1/session' }), cookie = session.cookies[0]!;
  const admin = { cookie: `${cookie.name}=${cookie.value}`, origin: config.publicOrigin, 'x-csrf-token': session.json().csrfToken as string };
  const ingest = async (value: SecurityReport) => {
    const { receivedAt: _receivedAt, ...payload } = value;
    const result = await server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload });
    assert.equal(result.statusCode, 200, result.body); return result;
  };
  const security = async () => (await server.inject({ method: 'GET', url: '/api/v1/security', headers: admin })).json();
  const notifications = () => store.read(state => Object.values(state.notifications));
  const close = async () => {
    await server.close(); await store.close();
    const placement = relative(tmpdir(), root); assert.ok(placement && !placement.startsWith('..') && !isAbsolute(placement));
    await rm(root, { recursive: true, force: true });
  };
  return { root, file, store, config, server, admin, ingest, security, notifications, close, deployments: () => deployments };
}

test('an unavailable VM scan keeps known Medium+ and unclassified findings visible', async () => {
  const c = await setup(); try {
    const findings = (['MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'] as const).map((severity, index) => finding(severity, { id: `CVE-${index}` }));
    await c.ingest(report(0, { findings }));
    await c.ingest(report(1, { status: 'unavailable', findings: [], coverage: [{ name: 'os', status: 'unavailable', detail: 'Feed expired' }] }));
    const view = await c.security(); assert.equal(view.vm.status, 'unavailable'); assert.equal(view.findings.length, 3); assert.equal(view.unclassifiedFindings.length, 1); assert.equal(view.vm.findings.length, 4);
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 0);
  } finally { await c.close(); }
});

test('unchanged app findings after an outage do not repeat notifications or remediation jobs', async () => {
  const c = await setup(); try {
    const { app, release } = fixture(); await c.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const scope = { subject: 'app' as const, appId: app.id, releaseId: release.id };
    await c.ingest(report(0, scope));
    await c.store.transaction(state => { for (const item of Object.values(state.notifications)) item.read = true; for (const job of Object.values(state.jobs)) job.stage = 'completed'; });
    await c.ingest(report(1, { ...scope, status: 'unavailable', findings: [], coverage: [{ name: 'os', status: 'unavailable', detail: 'Scanner interrupted' }] }));
    await c.ingest(report(2, scope));
    assert.equal(await c.store.read(state => Object.keys(state.jobs).length), 1);
    assert.equal((await c.notifications()).filter(item => item.title.includes('security finding')).length, 1);
    assert.equal((await c.security()).findings[0].appId, app.id);
    await c.ingest(report(3, { ...scope, status: 'passed', findings: [] }));
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 1);
    await c.ingest(report(4, scope));
    assert.equal(await c.store.read(state => Object.keys(state.jobs).length), 2);
    assert.equal((await c.notifications()).filter(item => item.title.includes('security finding')).length, 2);
    assert.equal(c.deployments(), 0);
  } finally { await c.close(); }
});

test('stale feeds, failed checks and missing previous coverage cannot resolve known findings', async () => {
  const c = await setup(); try {
    const coverage = ['os', 'kernel'].map(name => ({ name, status: 'passed' as const, detail: 'Synthetic coverage' }));
    await c.ingest(report(0, { coverage }));
    await c.ingest(report(1, { status: 'passed', findings: [], coverage, feedUpdatedAt: timestamp(-90000) }));
    await c.ingest(report(2, { findings: [], coverage: [{ name: 'os', status: 'passed', detail: 'Partial' }, { name: 'kernel', status: 'failed', detail: 'Check did not complete' }] }));
    await c.ingest(report(3, { status: 'passed', findings: [], coverage: coverage.slice(0, 1) }));
    const partial = await c.security(); assert.equal(partial.findings.length, 1); assert.equal(partial.vm.status, 'unavailable'); assert.ok(partial.vm.coverage.some((item: { name: string; status: string }) => item.name === 'kernel' && item.status === 'unavailable'));
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 0);
    await c.ingest(report(4, { status: 'passed', findings: [], coverage }));
    assert.equal((await c.security()).findings.length, 0);
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 1);
  } finally { await c.close(); }
});

test('late and equal-time scan retries cannot resurrect issues after a verified resolution', async () => {
  const c = await setup(); try {
    await c.ingest(report(0)); await c.ingest(report(3, { status: 'passed', findings: [] }));
    const completed = await c.store.read(state => latestSecurityReports(state)[0]!);
    await c.ingest(report(1)); await c.ingest(report(3, { status: 'passed', findings: [] }));
    assert.equal((await c.security()).findings.length, 0);
    assert.equal(await c.store.read(state => latestSecurityReports(state)[0]!.id), completed.id);
    assert.equal((await c.notifications()).filter(item => item.title.includes('security finding')).length, 1);
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 1);
  } finally { await c.close(); }
});

test('seven-day diagnostic pruning and reopening preserve known findings and notification deduplication', async () => {
  const c = await setup(); try {
    await c.ingest(report(0)); await c.ingest(report(1, { status: 'unavailable', findings: [] }));
    await c.store.transaction(state => { for (const item of Object.values(state.securityReports)) item.receivedAt = new Date(Date.now() - 8 * 86400000).toISOString(); for (const item of Object.values(state.notifications)) item.read = true; });
    await new WorkflowEngine(c.store, {}, new BudgetManager(c.store, 1, 5), c.config.workspaceDir).recover();
    assert.equal(await c.store.read(state => Object.keys(state.securityReports).length), 1);
    const reopened = new JsonStore(c.file); await reopened.initialize();
    assert.equal(await reopened.read(state => latestSecurityReports(state)[0]!.findings.length), 1);
    assert.equal(await reopened.read(state => Object.values(state.securityFindingStates).length), 1); await reopened.close();
    await c.ingest(report(2)); assert.equal((await c.notifications()).filter(item => item.title.includes('security finding')).length, 1);
  } finally { await c.close(); }
});

test('legacy report history is reconciled before pruning without reviving previously resolved issues', async () => {
  const c = await setup(); try {
    for (const resolved of [false, true]) {
      const state = emptyState(); const first = report(0), latest = report(2, { status: resolved ? 'passed' : 'unavailable', findings: [] });
      state.securityReports[first.id] = first; state.securityReports[latest.id] = latest;
      for (const item of Object.values(state.securityReports)) item.receivedAt = timestamp(item.id === first.id ? 0 : 2);
      // Simulate a serialized installation predating the new collection.
      const { securityFindingStates: _oldCollection, ...legacy } = state;
      const legacyFile = join(c.root, `legacy-${resolved}.json`); await writeFile(legacyFile, JSON.stringify(legacy));
      const store = new JsonStore(legacyFile); await store.initialize();
      assert.equal(await store.read(value => latestSecurityReports(value)[0]!.findings.length), resolved ? 0 : 1);
      await new WorkflowEngine(store, {}, new BudgetManager(store, 1, 5), c.config.workspaceDir).recover();
      assert.equal(await store.read(value => Object.values(value.securityFindingStates)[0]!.findings.length), resolved ? 0 : 1); await store.close();
      assert.ok(JSON.parse(await readFile(legacyFile, 'utf8')).securityFindingStates);
    }
  } finally { await c.close(); }
});

test('VM and release finding state stay independent and preserve blocked release evidence', async () => {
  const c = await setup(); try {
    const { app, release } = fixture(), other = { ...structuredClone(release), id: randomUUID(), version: '0.2.0' };
    release.evidence.findings = [finding()]; release.evidence.status = 'failed';
    await c.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; state.releases[other.id] = other; });
    await c.ingest(report(0));
    await c.ingest(report(1, { subject: 'app', appId: app.id, releaseId: release.id, status: 'unavailable', findings: [] }));
    await c.ingest(report(2, { subject: 'app', appId: app.id, releaseId: other.id }));
    await c.ingest(report(3, { subject: 'app', appId: app.id, releaseId: other.id, status: 'passed', findings: [] }));
    const findings = await c.store.read(state => latestSecurityReports(state).map(value => ({ subject: value.subject, releaseId: value.releaseId, count: value.findings.length })));
    assert.equal(findings.find(value => value.subject === 'vm')!.count, 1);
    assert.equal(findings.find(value => value.releaseId === release.id)!.count, 1);
    assert.equal(findings.find(value => value.releaseId === other.id)!.count, 0);
  } finally { await c.close(); }
});

test('partial classification cannot downgrade known severity; complete classification can resolve it', async () => {
  const c = await setup(); try {
    await c.ingest(report(0));
    await c.ingest(report(1, { status: 'unavailable', findings: [finding('UNKNOWN')] }));
    await c.ingest(report(2, { status: 'unavailable', findings: [finding('MEDIUM')] }));
    assert.equal((await c.security()).findings[0].severity, 'HIGH');
    await c.ingest(report(3, { status: 'passed', findings: [finding('LOW')] }));
    assert.equal((await c.security()).findings.length, 0);
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 1);
  } finally { await c.close(); }
});

test('finding identity is unambiguous and duplicate identities are rejected before state changes', async () => {
  const c = await setup(); try {
    const findings = [finding('HIGH', { id: 'A:B', package: 'C' }), finding('HIGH', { id: 'A', package: 'B:C' })];
    await c.ingest(report(0, { findings }));
    assert.equal((await c.security()).findings.length, 2);
    const { receivedAt: _receivedAt, ...payload } = report(1, { findings: [findings[0]!, findings[0]!] });
    const rejected = await c.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload }); assert.equal(rejected.statusCode, 400);
    assert.equal(await c.store.read(state => Object.keys(state.securityReports).length), 1);
    assert.equal(await c.store.read(state => securityFindingSnapshot(state, { subject: 'vm' }).findings.length), 2);
  } finally { await c.close(); }
});

test('incomplete clean reports cannot authorize publication over a known vulnerability', async () => {
  const c = await setup(); try {
    const { app, release } = fixture(); app.activeReleaseId = null; release.status = 'ready';
    await c.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const scope = { subject: 'app' as const, appId: app.id, releaseId: release.id };
    await c.ingest(report(0, { ...scope, coverage: ['os', 'dependencies'].map(name => ({ name, status: 'passed', detail: 'Synthetic verified scan' })) }));
    await c.ingest(report(1, { ...scope, status: 'passed', findings: [] }));
    const review = await c.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/approval`, headers: c.admin, payload: {} }); assert.equal(review.statusCode, 200, review.body);
    const approval = review.json().approval;
    const approve = await c.server.inject({ method: 'POST', url: `/api/v1/approvals/${approval.id}/approve`, headers: c.admin, payload: { artifactHash: approval.artifactHash } }); assert.equal(approve.statusCode, 409, approve.body);
    const publish = await c.server.inject({ method: 'POST', url: `/api/v1/releases/${release.id}/publish`, headers: c.admin, payload: { approvalId: approval.id } }); assert.equal(publish.statusCode, 409, publish.body); assert.equal(c.deployments(), 0);
  } finally { await c.close(); }
});

test('a delayed positive scan contributes findings and coverage after a newer outage', async () => {
  const c = await setup(); try {
    await c.ingest(report(2, { status: 'unavailable', findings: [] }));
    const delayed = report(1, { coverage: [{ name: 'dependencies', status: 'passed', detail: 'Synthetic dependency scan' }] });
    await c.ingest(delayed);
    const view = await c.security(); assert.equal(view.findings.length, 1); assert.equal(view.vm.checkedAt, timestamp(2)); assert.equal(view.vm.status, 'unavailable');
    assert.ok(view.vm.coverage.some((item: { name: string; status: string }) => item.name === 'dependencies' && item.status === 'unavailable'));
    // The same report history has the same findings when loaded without a ledger.
    assert.equal(await c.store.read(state => { const legacy = structuredClone(state); legacy.securityFindingStates = {}; return latestSecurityReports(legacy)[0]!.findings.length; }), 1);
    await c.ingest(report(3, { status: 'passed', findings: [] })); assert.equal((await c.security()).findings.length, 1);
    await c.ingest(report(4, { status: 'passed', findings: [], coverage: ['os', 'dependencies'].map(name => ({ name, status: 'passed', detail: 'Complete synthetic scan' })) }));
    assert.equal((await c.security()).findings.length, 0);
  } finally { await c.close(); }
});

test('release baseline findings require the actual broker coverage before resolution', async () => {
  const c = await setup(); try {
    const { app, release } = fixture(); release.evidence.status = 'failed'; release.evidence.findings = [finding()];
    await c.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const scope = { subject: 'app' as const, appId: app.id, releaseId: release.id };
    await c.ingest(report(0, { ...scope, status: 'passed', findings: [] }));
    assert.equal((await c.security()).findings.length, 1);
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 0);
    const coverage = ['os', 'vulnerability-feed', 'immutable-source', 'source-dependencies-configuration-secrets', 'source-security-policy', 'image-packages'].map(name => ({ name, status: 'passed' as const, detail: 'Synthetic actual broker coverage' }));
    await c.ingest(report(1, { ...scope, status: 'passed', findings: [], coverage }));
    assert.equal((await c.security()).findings.length, 0);
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 1);
  } finally { await c.close(); }
});

test('a feed older than 24 hours on receipt cannot verify resolution despite a recent scan', async () => {
  const c = await setup(); try {
    const at = (hours: number) => new Date(Date.now() - hours * 3600000).toISOString();
    await c.ingest(report(0, { checkedAt: at(25), feedUpdatedAt: at(25) }));
    await c.ingest(report(1, { status: 'passed', findings: [], checkedAt: at(23), feedUpdatedAt: at(47) }));
    assert.equal((await c.security()).findings.length, 1);
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 0);
  } finally { await c.close(); }
});

test('equal-time conflicting results fail closed until a newer complete scan', async () => {
  const c = await setup(); try {
    await c.ingest(report(0, { status: 'passed', findings: [] }));
    await c.ingest(report(0));
    const conflict = await c.security(); assert.equal(conflict.vm.status, 'unavailable'); assert.equal(conflict.findings.length, 1);
    assert.ok(conflict.vm.coverage.some((item: { name: string }) => item.name === 'conflicting-report-time'));
    await c.ingest(report(1, { status: 'passed', findings: [] }));
    assert.equal((await c.security()).vm.status, 'passed'); assert.equal((await c.security()).findings.length, 0);
  } finally { await c.close(); }
});

test('the daily app failure placeholder does not permanently poison real completed coverage', async () => {
  const c = await setup(); try {
    const { app, release } = fixture(); await c.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    const scope = { subject: 'app' as const, appId: app.id, releaseId: release.id };
    await c.ingest(report(0, { ...scope, status: 'unavailable', findings: [], coverage: [{ name: 'daily-immutable-application-security', status: 'unavailable', detail: 'Trusted receipt/source/dependency/configuration/image check failed' }] }));
    const coverage = ['vulnerability-feed', 'immutable-source', 'source-dependencies-configuration-secrets', 'source-security-policy', 'image-packages'].map(name => ({ name, status: 'passed' as const, detail: 'Synthetic actual broker coverage' }));
    await c.ingest(report(1, { ...scope, status: 'passed', findings: [], coverage }));
    assert.equal(await c.store.read(state => latestSecurityReports(state)[0]!.status), 'passed');
  } finally { await c.close(); }
});

test('a saved predecessor snapshot expands the app failure placeholder before a real completed scan', async () => {
  const c = await setup(); try {
    const { app, release } = fixture();
    const scope = { subject: 'app' as const, appId: app.id, releaseId: release.id };
    await c.store.transaction(state => {
      state.apps[app.id] = app; state.releases[release.id] = release;
      state.securityFindingStates[`app:${app.id}:${release.id}`] = { ...scope, checkedAt: timestamp(0), reportId: randomUUID(), findings: [], coverageNames: ['daily-immutable-application-security'] } as unknown as ReturnType<typeof securityFindingSnapshot>;
    });
    const coverage = ['vulnerability-feed', 'immutable-source', 'source-dependencies-configuration-secrets', 'source-security-policy', 'image-packages'].map(name => ({ name, status: 'passed' as const, detail: 'Synthetic actual broker coverage' }));
    await c.ingest(report(1, { ...scope, status: 'passed', findings: [], coverage }));
    assert.equal(await c.store.read(state => latestSecurityReports(state)[0]!.status), 'passed');
    assert.ok(await c.store.read(state => !securityFindingSnapshot(state, scope).coverageNames.includes('daily-immutable-application-security')));
  } finally { await c.close(); }
});

test('saved baseline findings without completed resolution retain mandatory broker coverage', async () => {
  const c = await setup(); try {
    const { app, release } = fixture(); release.evidence.status = 'failed'; release.evidence.findings = [finding()];
    const scope = { subject: 'app' as const, appId: app.id, releaseId: release.id };
    await c.store.transaction(state => {
      state.apps[app.id] = app; state.releases[release.id] = release;
      state.securityFindingStates[`app:${app.id}:${release.id}`] = { ...scope, checkedAt: timestamp(-1), reportId: null, findings: [finding()], coverageNames: [] } as unknown as ReturnType<typeof securityFindingSnapshot>;
    });
    await c.ingest(report(0, { ...scope, status: 'passed', findings: [] }));
    assert.equal((await c.security()).findings.length, 1);
    assert.equal((await c.notifications()).filter(item => item.title.includes('finding resolved')).length, 0);
    const saved = await c.store.read(state => securityFindingSnapshot(state, scope)); assert.equal(saved.resolvedThrough, null); assert.ok(saved.coverageNames.includes('image-packages'));
  } finally { await c.close(); }
});

test('exact report IDs are idempotent and changed content or scope under the same ID is rejected', async () => {
  const c = await setup(); try {
    const first = report(0, { status: 'passed', findings: [] }); await c.ingest(first); await c.ingest(first);
    assert.equal(await c.store.read(state => Object.keys(state.securityReports).length), 1);
    const { app, release } = fixture(); await c.store.transaction(state => { state.apps[app.id] = app; state.releases[release.id] = release; });
    for (const changes of [{ status: 'failed' as const, findings: [finding()] }, { subject: 'app' as const, appId: app.id, releaseId: release.id }]) {
      const { receivedAt: _receivedAt, ...payload } = { ...first, ...changes };
      const result = await c.server.inject({ method: 'POST', url: '/internal/v1/security-reports', headers, payload }); assert.equal(result.statusCode, 409, result.body);
    }
    assert.equal(await c.store.read(state => Object.keys(state.securityReports).length), 1); assert.equal((await c.security()).findings.length, 0);
  } finally { await c.close(); }
});

test('saved legacy report hashes are recovered or held unavailable on equal-time comparisons', async () => {
  const c = await setup(); try {
    for (const retained of [true, false]) {
      const clean = report(0, { status: 'passed', findings: [] });
      await c.store.transaction(state => {
        state.securityReports = retained ? { [clean.id]: clean } : {};
        state.securityFindingStates = { 'vm::': { subject: 'vm', checkedAt: clean.checkedAt, reportId: clean.id, findings: [], coverageNames: ['os'] } as unknown as ReturnType<typeof securityFindingSnapshot> };
      });
      await c.ingest(report(0, { status: 'unavailable', findings: [] }));
      assert.equal((await c.security()).vm.status, 'unavailable');
      assert.ok((await c.security()).vm.coverage.some((item: { name: string }) => item.name === 'conflicting-report-time'));
      await c.ingest(report(1, { status: 'passed', findings: [] })); assert.equal((await c.security()).vm.status, 'passed');
    }
  } finally { await c.close(); }
});
