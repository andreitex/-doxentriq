import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { selectPreviousSource, type PreviousSourceSelection } from '../../../packages/core/src/source-selection.ts';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';
import { stages } from '../../../packages/core/src/schemas.ts';
import type { Config } from '../src/config.ts';
import { JsonStore } from '../src/store.ts';
import { BudgetManager } from '../src/budget.ts';
import { frozenGenerationContext, frozenPreviousSourceSelection, ModelCheckpointError, attemptKey } from '../src/model-checkpoints.ts';
import { configureDependencies } from '../src/dependencies.ts';

const key = Buffer.alloc(32, 93), owner = 'source-selection-worker';
const files = [{ path: 'web/main.jsx', content: '<form>upload department metadata</form>' }, { path: 'src/auth.mjs', content: 'permissions '.repeat(4500) }, { path: 'package-lock.json', content: '{"lockfileVersion":3}' }];
const criteria = ['The upload form in web/main.jsx has optional Project code metadata'];
async function setup(file?: string) {
  const store = new JsonStore(file); await store.initialize(); const now = new Date().toISOString();
  const app: AppRecord = { id: randomUUID(), slug: 'source-documents', name: 'Documents', description: 'Preserve versions', kind: 'web', status: 'building', activeReleaseId: 'source-release-one', runtimeFence: 1, createdAt: now, updatedAt: now, url: null, previewUrl: null };
  const job: JobRecord = { id: randomUUID(), appId: app.id, request: 'Add a Project code field to the upload form in web/main.jsx', stage: 'specification', baseReleaseId: app.activeReleaseId, costUsd: 0, budgetUsd: 10, attempts: 0, runtimeFence: 1, createdAt: now, updatedAt: now };
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.leases[job.id] = { owner, until: new Date(Date.now() + 90000).toISOString() }; });
  await frozenGenerationContext(store, key, { app, job }, owner, { previousFiles: files });
  const selection = selectPreviousSource({ appId: app.id, jobId: job.id, attempt: 0, baseReleaseId: job.baseReleaseId, request: job.request, files, acceptanceCriteria: criteria });
  return { store, app, job, selection };
}
test('source selection appends encrypted evidence while the original encrypted starting snapshot remains byte exact', async () => {
  const f = await setup(), id = attemptKey(f.job.id, 0), original = await f.store.read(state => state.generationContexts[id]!.encrypted);
  const first = await frozenPreviousSourceSelection(f.store, key, f, owner, f.selection), wire = await f.store.read(state => state.generationContexts[id]!);
  assert.deepEqual(first, f.selection); assert.equal(wire.encrypted, original); assert.ok(wire.selectionEncrypted); assert.ok(!wire.selectionEncrypted!.includes('web/main.jsx'));
  const frozen = await frozenGenerationContext(f.store, key, f, owner); assert.deepEqual(frozen?.previousSourceSelection, f.selection); assert.deepEqual(frozen?.previousFiles, files);
  const second = await frozenPreviousSourceSelection(f.store, key, f, owner, f.selection); assert.deepEqual(second, first); assert.equal((await f.store.read(state => state.generationContexts[id]!)).selectionEncrypted, wire.selectionEncrypted);
});
test('retained source selection reopens and reuses its original paths, hashes and starting release after worker recovery', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'autosoft-selection-reopen-'));
  try {
    const file = join(directory, 'state.json'), f = await setup(file); await frozenPreviousSourceSelection(f.store, key, f, owner, f.selection); await f.store.close();
    const wire = await readFile(file, 'utf8'); assert.ok(!wire.includes(files[0]!.content));
    const reopened = new JsonStore(file); await reopened.initialize(); const job = { ...f.job, runtimeFence: 2 }, app = { ...f.app, runtimeFence: 2 };
    await reopened.transaction(state => { state.jobs[job.id]!.runtimeFence = 2; state.apps[app.id]!.runtimeFence = 2; state.leases[job.id] = { owner, until: new Date(Date.now() + 90000).toISOString() }; });
    assert.deepEqual((await frozenGenerationContext(reopened, key, { app, job }, owner))?.previousSourceSelection, f.selection);
    assert.deepEqual(await frozenPreviousSourceSelection(reopened, key, { app, job }, owner, f.selection), f.selection);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test('changed selected hashes, omitted hashes, criteria and copied app bindings cannot overwrite retained selection', async () => {
  const f = await setup(); await frozenPreviousSourceSelection(f.store, key, f, owner, f.selection);
  const before = await f.store.read(state => state.generationContexts);
  const variations: PreviousSourceSelection[] = [
    { ...f.selection, selected: f.selection.selected.map((item, i) => i ? item : { ...item, sha256: 'a'.repeat(64) }) },
    { ...f.selection, omitted: f.selection.omitted.map((item, i) => i ? item : { ...item, sha256: 'b'.repeat(64) }) },
    selectPreviousSource({ appId: f.app.id, jobId: f.job.id, attempt: 0, baseReleaseId: f.job.baseReleaseId, request: f.job.request, files, acceptanceCriteria: ['Change different business behavior'] }),
    { ...f.selection, appId: 'foreign-app' }
  ];
  for (const selection of variations) await assert.rejects(frozenPreviousSourceSelection(f.store, key, f, owner, selection), ModelCheckpointError);
  assert.deepEqual(await f.store.read(state => state.generationContexts), before);
});
test('stale baseline, expired lease, foreign owner and corrupted selection ciphertext cannot admit source or paid work', async () => {
  for (const failure of ['baseline', 'lease', 'owner', 'ciphertext'] as const) {
    const f = await setup(); await frozenPreviousSourceSelection(f.store, key, f, owner, f.selection);
    await f.store.transaction(state => { if (failure === 'baseline') state.apps[f.app.id]!.activeReleaseId = 'release-two'; if (failure === 'lease') state.leases[f.job.id]!.until = new Date(Date.now() - 1).toISOString(); if (failure === 'ciphertext') state.generationContexts[attemptKey(f.job.id, 0)]!.selectionEncrypted += '!'; });
    await assert.rejects(frozenPreviousSourceSelection(f.store, key, f, failure === 'owner' ? 'foreign-worker' : owner, f.selection), ModelCheckpointError);
    if (failure !== 'owner') await assert.rejects(frozenGenerationContext(f.store, key, f, owner), ModelCheckpointError);
    assert.equal(await f.store.read(state => Object.keys(state.modelCalls).length), 0);
  }
});
test('the actual configured production callback freezes selection and replays all three paid outputs without replacement calls', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'autosoft-selection-service-')), previousFetch = globalThis.fetch;
  const envNames = ['MODEL_CATALOG_FILE', 'OPENAI_API_KEY', 'OPENAI_API_KEY_FILE', 'ANTHROPIC_API_KEY', 'ANTHROPIC_API_KEY_FILE'];
  const previousEnv = Object.fromEntries(envNames.map(name => [name, process.env[name]]));
  try {
    const f = await setup(join(directory, 'state.json')), catalogFile = join(directory, 'catalog.json'), bodies: any[] = [];
    await writeFile(catalogFile, JSON.stringify({ schemaVersion: 1, pricesVerifiedAt: new Date().toISOString(), sources: [], models: [{ id: 'injected-selection-provider', provider: 'openai', tier: 'strong', inputUsdPerMillion: 1, outputUsdPerMillion: 1, cachedInputUsdPerMillion: 0, cacheWriteUsdPerMillion: 1, effort: 'high', qualified: true, maxInputTokens: 90000, maxOutputTokens: 32768 }] }));
    process.env.MODEL_CATALOG_FILE = catalogFile; process.env.OPENAI_API_KEY = 'synthetic-selection-provider-key'; delete process.env.OPENAI_API_KEY_FILE; delete process.env.ANTHROPIC_API_KEY; delete process.env.ANTHROPIC_API_KEY_FILE;
    const plan = { title: 'Project code', summary: 'Add metadata', acceptanceCriteria: criteria, questions: [] };
    globalThis.fetch = async (_url, init) => {
      const body = JSON.parse(String(init?.body)); bodies.push(body);
      const generated = { specification: plan, summary: 'Add upload Project code', manifest: { schemaVersion: 1, id: f.app.id, slug: f.app.slug, name: f.app.name, kind: 'web', template: 'node-web', auth: 'sso', permissions: [], connections: [], resources: { cpu: 1, memoryMb: 256, pids: 64 }, health: { path: '/healthz', port: 8080 }, storage: [] }, pipeline: { schemaVersion: 1, template: 'node-web', stages: stages.map(name => ({ name, commands: [], timeoutSeconds: 60 })) }, migrations: [], files: [{ path: 'web/main.jsx', content: '<form>Project code</form>' }] };
      return Response.json({ status: 'completed', service_tier: 'default', usage: { input_tokens: 1, output_tokens: 1 }, output: [{ type: 'message', content: [{ type: 'output_text', text: JSON.stringify(bodies.length === 1 ? plan : bodies.length === 2 ? generated : { approved: true, issues: [] }) }] }] });
    };
    const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: directory, workspaceDir: directory, oidcClientId: 'synthetic-selection', secretKey: key, requestLimitUsd: 10, monthlyLimitUsd: 100, openaiApiKey: 'synthetic-selection-provider-key', adminDist: directory };
    const dependencies = await configureDependencies(config, f.store), context = (await frozenGenerationContext(f.store, key, f, owner))!;
    const first = await dependencies.planAndGenerate!({ ...f, context, budgetRemainingUsd: 10 }, new BudgetManager(f.store, 10, 100).hooks(f.job.id, { owner, runtimeFence: 1 }));
    assert.equal(bodies.length, 3); assert.ok(JSON.parse(bodies[1].input).previousFiles.some((file: any) => file.path === 'web/main.jsx' && file.content === files[0]!.content));
    assert.equal(first.files.find(file => file.path === 'src/auth.mjs')?.content, files[1]!.content);
    const retained = await f.store.read(state => ({ calls: state.modelCalls, reservations: state.reservations, contexts: state.generationContexts })); await f.store.close();
    const reopened = new JsonStore(join(directory, 'state.json')); await reopened.initialize();
    await reopened.transaction(state => { state.jobs[f.job.id]!.runtimeFence = 2; state.apps[f.app.id]!.runtimeFence = 2; state.leases[f.job.id] = { owner, until: new Date(Date.now() + 90000).toISOString() }; });
    const newer = { app: { ...f.app, runtimeFence: 2 }, job: { ...f.job, runtimeFence: 2 } }, recovered = await configureDependencies(config, reopened), recoveredContext = (await frozenGenerationContext(reopened, key, newer, owner))!;
    const replay = await recovered.planAndGenerate!({ ...newer, context: recoveredContext, budgetRemainingUsd: 10 }, new BudgetManager(reopened, 10, 100).hooks(f.job.id, { owner, runtimeFence: 2 }));
    assert.deepEqual(replay, first); assert.equal(bodies.length, 3);
    assert.deepEqual(await reopened.read(state => ({ calls: state.modelCalls, reservations: state.reservations, contexts: state.generationContexts })), retained);
  } finally {
    globalThis.fetch = previousFetch; for (const name of envNames) { const value = previousEnv[name]; if (value === undefined) delete process.env[name]; else process.env[name] = value; }
    await rm(directory, { recursive: true, force: true });
  }
});
