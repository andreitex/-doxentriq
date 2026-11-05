import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ModelGateway, createGenerationService, type CompletionRequest, type ModelCatalog } from '../../../packages/core/src/models.ts';
import { stages } from '../../../packages/core/src/schemas.ts';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';
import { JsonStore, type State, type Store } from '../src/store.ts';
import { BudgetManager } from '../src/budget.ts';
import { recordModelCalls } from '../src/model-records.ts';
import { frozenGenerationContext, outputKey, ModelCheckpointError } from '../src/model-checkpoints.ts';
import { WorkflowEngine } from '../src/engine.ts';
import { createServer } from '../src/server.ts';
import type { Config } from '../src/config.ts';

const key = Buffer.alloc(32, 79), owner = 'synthetic-checkpoint-worker';
async function setup(file?: string) {
  const store = new JsonStore(file); await store.initialize(); const now = new Date().toISOString();
  const app: AppRecord = { id: randomUUID(), slug: 'checkpoint-documents', name: 'Documents', description: 'Keep folders', kind: 'api', status: 'building', activeReleaseId: null, url: null, previewUrl: null, runtimeFence: 7, createdAt: now, updatedAt: now };
  const job: JobRecord = { id: randomUUID(), appId: app.id, request: 'Keep the existing document folders', stage: 'specification', baseReleaseId: null, costUsd: 0, budgetUsd: 10, attempts: 0, runtimeFence: 7, createdAt: now, updatedAt: now };
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.leases[job.id] = { owner, until: new Date(Date.now() + 90000).toISOString() }; });
  return { store, app, job };
}
function request(job: JobRecord, overrides: Partial<CompletionRequest> = {}): CompletionRequest { return { stage: 'design', jobId: job.id, system: 'Synthetic instructions', prompt: 'Synthetic source request', callSlot: 'specification', attempt: job.attempts, runtimeFence: job.runtimeFence, maxOutputTokens: 4096, ...overrides }; }
function gateway(store: Store, output: (body: any, index: number) => string = () => 'private-paid-output') {
  const catalog: ModelCatalog = { schemaVersion: 1, pricesVerifiedAt: new Date().toISOString(), sources: [], models: [{ id: 'qualified-synthetic-model', provider: 'openai', tier: 'strong', inputUsdPerMillion: 1, outputUsdPerMillion: 1, cachedInputUsdPerMillion: 0, cacheWriteUsdPerMillion: 1, effort: 'high', qualified: true, maxInputTokens: 90000, maxOutputTokens: 32768 }] };
  const bodies: any[] = [];
  const actual = new ModelGateway({ catalog, apiKeys: { openai: 'synthetic-header-only' }, fetch: async (_url, init) => { const body = JSON.parse(String(init?.body)); bodies.push(body); return Response.json({ status: 'completed', service_tier: 'default', usage: { input_tokens: 2, output_tokens: 3 }, output: [{ type: 'message', content: [{ type: 'output_text', text: output(body, bodies.length - 1) }] }] }); } });
  return { actual, recorded: recordModelCalls(actual, store, key), bodies };
}
const hooks = (store: Store, job: JobRecord) => new BudgetManager(store, 10, 100).hooks(job.id, { owner, runtimeFence: job.runtimeFence! });
const evidence = (state: State) => ({ calls: state.modelCalls, reservations: state.reservations, jobCost: Object.values(state.jobs).map(job => job.costUsd), checkpoints: state.modelCheckpoints, events: state.events });

test('cache and provider admission require the actual caller lease owner, while worker hook metadata cannot be mutated', async () => {
  const f = await setup(), g = gateway(f.store), workerInput = { owner, runtimeFence: 7 }, budget = new BudgetManager(f.store, 10, 100).hooks(f.job.id, workerInput);
  workerInput.owner = 'unrelated'; workerInput.runtimeFence = 9;
  assert.deepEqual(budget.worker, { owner, runtimeFence: 7 }); assert.ok(Object.isFrozen(budget)); assert.ok(Object.isFrozen(budget.worker));
  assert.throws(() => { (budget.worker as { owner: string }).owner = 'other'; }, TypeError);
  const wrong = new BudgetManager(f.store, 10, 100).hooks(f.job.id, { owner: 'other-worker', runtimeFence: 7 });
  await assert.rejects(g.recorded.complete(request(f.job), wrong), ModelCheckpointError); assert.equal(g.bodies.length, 0); assert.equal(await f.store.read(state => Object.keys(state.modelCalls).length), 0);
  await g.recorded.complete(request(f.job), budget); const before = await f.store.read(evidence);
  await assert.rejects(g.recorded.complete(request(f.job), wrong), ModelCheckpointError); assert.equal(g.bodies.length, 1); assert.deepEqual(await f.store.read(evidence), before);
});

test('live business or request changes after context admission also block each paid call and cache hit', async () => {
  for (const paid of [false, true]) {
    const f = await setup(), g = gateway(f.store); await frozenGenerationContext(f.store, key, f, owner, {});
    if (paid) await g.recorded.complete(request(f.job), hooks(f.store, f.job));
    await f.store.transaction(state => { state.apps[f.app.id]!.description = 'Changed while worker was generating'; }); const before = await f.store.read(evidence);
    await assert.rejects(g.recorded.complete(request(f.job), hooks(f.store, f.job)), ModelCheckpointError); assert.equal(g.bodies.length, Number(paid)); assert.deepEqual(await f.store.read(evidence), before);
  }
});

test('actual gateway output reopens encrypted and replays without another provider call, reservation, settlement or billing event', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'autosoft-paid-checkpoint-'));
  try {
    const file = join(directory, 'state.json'), f = await setup(file), g = gateway(f.store);
    const paid = await g.recorded.complete(request(f.job), hooks(f.store, f.job)); const before = await f.store.read(evidence); await f.store.close();
    const wire = await readFile(file, 'utf8'); assert.ok(!wire.includes('private-paid-output')); assert.ok(!wire.includes('Synthetic source request')); assert.ok(!wire.includes('synthetic-header-only'));
    const reopened = new JsonStore(file); await reopened.initialize(); await reopened.transaction(state => { state.apps[f.app.id]!.runtimeFence = 8; state.jobs[f.job.id]!.runtimeFence = 8; state.jobs[f.job.id]!.budgetUsd = 15; state.leases[f.job.id] = { owner, until: new Date(Date.now() + 90000).toISOString() }; });
    let reserves = 0, settles = 0; const resumed = gateway(reopened), budget = hooks(reopened, { ...f.job, runtimeFence: 8 });
    const replay = await resumed.recorded.complete(request({ ...f.job, runtimeFence: 8 }), { worker: budget.worker, reserve: async amount => { reserves++; return budget.reserve(amount); }, settle: async (id, cost) => { settles++; return budget.settle(id, cost); } });
    assert.deepEqual(replay, paid); assert.equal(resumed.bodies.length, 0); assert.equal(reserves, 0); assert.equal(settles, 0); assert.deepEqual(await reopened.read(evidence), before);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('changed prompt, system, schema, stage or output limit on the same explicit slot pauses before spending', async () => {
  for (const alteration of [{ prompt: 'changed' }, { system: 'changed' }, { schema: { type: 'object' } }, { stage: 'review' as const }, { maxOutputTokens: 1 }]) {
    const f = await setup(), g = gateway(f.store); await g.recorded.complete(request(f.job), hooks(f.store, f.job)); const before = await f.store.read(evidence);
    await assert.rejects(g.recorded.complete(request(f.job, alteration), hooks(f.store, f.job)), ModelCheckpointError); assert.equal(g.bodies.length, 1); assert.deepEqual(await f.store.read(evidence), before);
  }
});

test('explicit implementation and review slots stay distinct when both use strong review routing', async () => {
  const f = await setup(), g = gateway(f.store, (_body, index) => `output-${index}`);
  const implementation = request(f.job, { callSlot: 'implementation', stage: 'review', prompt: 'repair implementation' }), review = request(f.job, { callSlot: 'review', stage: 'review', prompt: 'independent review' });
  const first = await g.recorded.complete(implementation, hooks(f.store, f.job)), second = await g.recorded.complete(review, hooks(f.store, f.job));
  assert.notEqual(first.text, second.text); assert.deepEqual(await g.recorded.complete(implementation, hooks(f.store, f.job)), first); assert.deepEqual(await g.recorded.complete(review, hooks(f.store, f.job)), second); assert.equal(g.bodies.length, 2);
  assert.deepEqual(await f.store.read(state => Object.values(state.modelCalls).map(call => call.callSlot)), ['implementation', 'review']);
});

test('an explicit new attempt authorizes new paid work and cannot reuse the prior attempt checkpoint', async () => {
  const f = await setup(), g = gateway(f.store, (_body, index) => `attempt-output-${index}`); await g.recorded.complete(request(f.job), hooks(f.store, f.job));
  await f.store.transaction(state => { state.jobs[f.job.id]!.attempts++; }); const newer = { ...f.job, attempts: 1 };
  const result = await g.recorded.complete(request(newer), hooks(f.store, newer)); assert.equal(result.text, 'attempt-output-1'); assert.equal(g.bodies.length, 2); assert.equal(await f.store.read(state => Object.keys(state.modelCheckpoints).length), 2);
});

test('expired lease, stale caller fence, app fence mismatch, changed baseline and cancelled work cannot replay or spend', async () => {
  const mutations: ((state: State, f: Awaited<ReturnType<typeof setup>>) => void)[] = [
    (state, f) => { state.leases[f.job.id]!.until = new Date(Date.now() - 1).toISOString(); },
    (state, f) => { state.apps[f.app.id]!.runtimeFence = 8; state.jobs[f.job.id]!.runtimeFence = 8; },
    (state, f) => { state.apps[f.app.id]!.runtimeFence = 8; },
    (state, f) => { state.apps[f.app.id]!.activeReleaseId = 'newer-release'; },
    (state, f) => { state.jobs[f.job.id]!.stage = 'cancelled'; }
  ];
  for (const mutate of mutations) { const f = await setup(), g = gateway(f.store); await g.recorded.complete(request(f.job), hooks(f.store, f.job)); await f.store.transaction(state => mutate(state, f)); const before = await f.store.read(evidence); await assert.rejects(g.recorded.complete(request(f.job), hooks(f.store, f.job)), ModelCheckpointError); assert.equal(g.bodies.length, 1); assert.deepEqual(await f.store.read(evidence), before); }
});

test('ciphertext, plaintext billing metadata and settled reservation tampering fail closed before another call', async () => {
  for (const target of ['ciphertext', 'cost', 'usage', 'reservation'] as const) {
    const f = await setup(), g = gateway(f.store); await g.recorded.complete(request(f.job), hooks(f.store, f.job));
    await f.store.transaction(state => { const call = Object.values(state.modelCalls)[0]!; const checkpoint = Object.values(state.modelCheckpoints)[0]!; if (target === 'ciphertext') checkpoint.encrypted = checkpoint.encrypted.slice(0, -1) + '!'; if (target === 'cost') call.costUsd = 99; if (target === 'usage') call.usage!.inputTokens++; if (target === 'reservation') state.reservations[call.reservationIds[0]!]!.actualUsd = null; });
    const before = await f.store.read(evidence); await assert.rejects(g.recorded.complete(request(f.job), hooks(f.store, f.job)), ModelCheckpointError); assert.equal(g.bodies.length, 1); assert.deepEqual(await f.store.read(evidence), before);
  }
});

test('a copied checkpoint and billing record cannot cross a job or application boundary', async () => {
  const f = await setup(), g = gateway(f.store); await g.recorded.complete(request(f.job), hooks(f.store, f.job));
  const app = { ...f.app, id: randomUUID() }, job = { ...f.job, id: randomUUID(), appId: app.id };
  await f.store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.leases[job.id] = { owner, until: new Date(Date.now() + 90000).toISOString() }; const old = Object.values(state.modelCalls)[0]!, copied = { ...old, id: randomUUID(), jobId: job.id, appId: app.id }; state.modelCalls[copied.id] = copied; const record = Object.values(state.modelCheckpoints)[0]!; state.modelCheckpoints[outputKey(job.id, 0, 'specification')] = { ...record, jobId: job.id, appId: app.id, callId: copied.id }; for (const id of copied.reservationIds) state.reservations[id]!.jobId = job.id; });
  await assert.rejects(g.recorded.complete(request(job), hooks(f.store, job)), ModelCheckpointError); assert.equal(g.bodies.length, 1);
});

test('missing output and legacy completed metadata pause instead of charging to recreate paid output', async () => {
  for (const legacy of [false, true]) {
    const f = await setup(), g = gateway(f.store); await g.recorded.complete(request(f.job), hooks(f.store, f.job)); await f.store.transaction(state => { state.modelCheckpoints = {}; if (legacy) { const call = Object.values(state.modelCalls)[0]!; delete call.callSlot; delete call.requestHash; delete call.attempt; } });
    const before = await f.store.read(evidence); await assert.rejects(g.recorded.complete(request(f.job), hooks(f.store, f.job)), ModelCheckpointError); assert.equal(g.bodies.length, 1); assert.deepEqual(await f.store.read(evidence), before);
  }
});

function faultStore(store: Store, afterCommit: boolean): Store {
  let faulted = false;
  return { mode: store.mode, close: () => store.close(), read: action => store.read(action), transaction: async action => {
    let completion = false;
    const result = await store.transaction(async state => { const value = await action(state); completion = !faulted && Object.values(state.modelCalls).some(call => call.status === 'completed') && Object.keys(state.modelCheckpoints).length > 0; if (completion && !afterCommit) { faulted = true; throw new Error('Injected completion commit interruption'); } return value; });
    if (completion && afterCommit) { faulted = true; throw new Error('Injected commit acknowledgement interruption'); } return result;
  } };
}

test('failure before the atomic output commit keeps paid settlement but holds the uncheckpointed call', async () => {
  const f = await setup(), faulty = faultStore(f.store, false), g = gateway(faulty); await assert.rejects(g.recorded.complete(request(f.job), hooks(faulty, f.job)), /Injected completion commit/);
  const state = await f.store.read(state => state); assert.equal(Object.values(state.modelCalls)[0]?.status, 'uncertain'); assert.equal(Object.keys(state.modelCheckpoints).length, 0); assert.ok(Object.values(state.reservations)[0]?.actualUsd! > 0); assert.ok(state.jobs[f.job.id]!.costUsd > 0);
  await assert.rejects(g.recorded.complete(request(f.job), hooks(faulty, f.job)), /reconcil/i); assert.equal(g.bodies.length, 1);
});

test('lost acknowledgement after the atomic output commit never overwrites completed evidence in the catch path', async () => {
  const f = await setup(), faulty = faultStore(f.store, true), g = gateway(faulty); await assert.rejects(g.recorded.complete(request(f.job), hooks(faulty, f.job)), /Injected commit acknowledgement/);
  const before = await f.store.read(evidence); assert.equal(Object.values(before.calls)[0]?.status, 'completed'); assert.equal(Object.keys(before.checkpoints).length, 1);
  assert.equal((await g.recorded.complete(request(f.job), hooks(faulty, f.job))).text, 'private-paid-output'); assert.equal(g.bodies.length, 1); assert.deepEqual(await f.store.read(evidence), before);
});

test('an actual unknown provider outcome creates no checkpoint and remains held after worker recovery', async () => {
  const f = await setup(), g = gateway(f.store); let dispatches = 0;
  const actual = g.actual as unknown as { request: typeof fetch }; actual.request = async () => { dispatches++; throw new Error('Injected network interruption'); };
  await assert.rejects(g.recorded.complete(request(f.job), hooks(f.store, f.job)), /without a confirmed billing/); await f.store.transaction(state => { state.leases[f.job.id]!.until = new Date(Date.now() - 1000).toISOString(); });
  await new WorkflowEngine(f.store, {}, new BudgetManager(f.store, 10, 100), 'unused', key).recover(); const state = await f.store.read(state => state);
  assert.equal(dispatches, 1); assert.equal(Object.values(state.modelCalls)[0]?.status, 'uncertain'); assert.equal(Object.keys(state.modelCheckpoints).length, 0); assert.equal(Object.values(state.reservations)[0]?.actualUsd, null); assert.equal(state.jobs[f.job.id]?.result?.modelBillingHold, true);
});

test('the model-call API exposes routing and billing evidence without encrypted or plaintext outputs', async () => {
  const f = await setup(), g = gateway(f.store); await g.recorded.complete(request(f.job), hooks(f.store, f.job));
  const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: 'unused', workspaceDir: 'unused', oidcClientId: 'test', secretKey: key, requestLimitUsd: 10, monthlyLimitUsd: 100, adminDist: 'absent-checkpoint-test-dist' };
  const server = await createServer(config, f.store);
  try { const session = await server.inject({ method: 'GET', url: '/api/v1/session' }), cookie = session.cookies[0]!; const response = await server.inject({ method: 'GET', url: `/api/v1/jobs/${f.job.id}/model-calls`, headers: { cookie: `${cookie.name}=${cookie.value}` } }); assert.equal(response.statusCode, 200); assert.equal(response.json().calls[0].model, 'qualified-synthetic-model'); assert.ok(!/private-paid-output|encrypted|modelCheckpoints|generationContexts|Synthetic source request/.test(response.body)); } finally { await server.close(); }
});

test('frozen context survives workflow metadata changes but rejects changed business inputs, scope and tampering', async () => {
  for (const change of ['none', 'request', 'answer', 'app', 'schema', 'ciphertext'] as const) {
    const f = await setup(), context = { previousSpecification: { title: 'Original' }, previousFiles: [{ path: 'server.mjs', content: 'original source' }], connectionInventory: { schemaVersion: 1 as const, connections: [] } }; await frozenGenerationContext(f.store, key, f, owner, context);
    await f.store.transaction(state => { const job = state.jobs[f.job.id]!; job.specification = { title: 'Generated' }; job.result = { workspacePath: 'captured-new-workspace', filesHash: 'generated' }; job.runtimeFence = 8; state.apps[f.app.id]!.runtimeFence = 8; state.apps[f.app.id]!.updatedAt = new Date().toISOString(); if (change === 'request') job.request += ' changed'; if (change === 'answer') job.result.answer = 'Changed'; if (change === 'app') state.apps[f.app.id]!.description = 'Changed'; if (change === 'schema') state.apps[f.app.id]!.databaseSchemaVersion = 2; if (change === 'ciphertext') Object.values(state.generationContexts)[0]!.encrypted += '!'; });
    if (change === 'none') assert.deepEqual(await frozenGenerationContext(f.store, key, { app: f.app, job: { ...f.job, runtimeFence: 8 } }, owner), context); else await assert.rejects(frozenGenerationContext(f.store, key, { app: f.app, job: { ...f.job, runtimeFence: 8 } }, owner), ModelCheckpointError);
  }
});

test('workflow recovery uses frozen original source and three paid outputs after workspace capture changed', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'autosoft-generation-checkpoint-'));
  try {
    const file = join(directory, 'state.json'), f = await setup(file), specification = { title: 'Documents', summary: 'Preserve folders', acceptanceCriteria: ['Folders preserved'], questions: [] };
    const proposed = { specification, summary: 'Preserve folders', manifest: { schemaVersion: 1, id: f.app.id, slug: f.app.slug, name: f.app.name, kind: 'api', template: 'node-api', auth: 'sso', permissions: [], connections: [], resources: { cpu: 1, memoryMb: 256, pids: 64 }, health: { path: '/healthz', port: 8080 }, storage: [] }, pipeline: { schemaVersion: 1, template: 'node-api', stages: stages.map(name => ({ name, commands: [], timeoutSeconds: 60 })) }, files: [{ path: 'server.mjs', content: 'export const preservedFolders = true;' }], migrations: [] };
    const g = gateway(f.store, (_body, index) => JSON.stringify([specification, proposed, { approved: true, issues: [] }][index])), context = { previousSpecification: { title: 'Before paid generation' }, previousFiles: [{ path: 'old.mjs', content: 'original preserved source' }], connectionInventory: { schemaVersion: 1 as const, connections: [] } };
    await frozenGenerationContext(f.store, key, f, owner, context); const service = createGenerationService({ gateway: g.recorded }); await service({ ...f, context, budgetRemainingUsd: 10 }, hooks(f.store, f.job));
    const before = await f.store.read(evidence); await f.store.transaction(state => { state.jobs[f.job.id]!.stage = 'verification'; state.jobs[f.job.id]!.specification = specification; state.jobs[f.job.id]!.result = { workspacePath: 'changed-path-must-not-be-read', filesHash: 'changed' }; state.leases[f.job.id]!.until = new Date(Date.now() - 1000).toISOString(); }); await f.store.close();
    const reopened = new JsonStore(file); await reopened.initialize(); const resumed = gateway(reopened); let verification = 0;
    const engine = new WorkflowEngine(reopened, { generationConnections: async () => context.connectionInventory, planAndGenerate: createGenerationService({ gateway: resumed.recorded }), verify: async input => { verification++; assert.equal(await readFile(join(input.workspacePath, 'old.mjs'), 'utf8'), 'original preserved source'); assert.equal(await readFile(join(input.workspacePath, 'server.mjs'), 'utf8'), proposed.files[0]!.content); throw new Error('Synthetic verification service unavailable'); } }, new BudgetManager(reopened, 10, 100), join(directory, 'workspaces'), key);
    await engine.recover(); await engine.run(f.job.id); assert.equal(verification, 1); assert.equal(resumed.bodies.length, 0); const after = await reopened.read(evidence); assert.deepEqual(after.calls, before.calls); assert.deepEqual(after.reservations, before.reservations); assert.deepEqual(after.jobCost, before.jobCost); assert.deepEqual(after.checkpoints, before.checkpoints); assert.deepEqual(await reopened.read(state => state.jobs[f.job.id]?.specification), specification);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('a changed protected connection scope stops recovered workflow before cached output or provider execution', async () => {
  const f = await setup(), inventory = { schemaVersion: 1 as const, connections: [] }; await frozenGenerationContext(f.store, key, f, owner, { connectionInventory: inventory }); await f.store.transaction(state => { state.leases[f.job.id]!.until = new Date(Date.now() - 1).toISOString(); }); let calls = 0;
  const engine = new WorkflowEngine(f.store, { generationConnections: async () => ({ schemaVersion: 1, connections: [{ id: 'new-connection', name: 'New', type: 'filesystem', appIds: [f.app.id], roots: ['archive'], capabilities: ['files.list'], expiresAt: null, status: 'unavailable', reason: 'not_configured' }] }), planAndGenerate: async () => { calls++; throw new Error('Should never reach generation'); } }, new BudgetManager(f.store, 10, 100), 'unused', key);
  await engine.run(f.job.id); assert.equal(calls, 0); assert.equal(await f.store.read(state => Object.keys(state.reservations).length), 0); assert.equal(await f.store.read(state => state.jobs[f.job.id]?.stage), 'needs_attention');
});

test('unavailable frozen research and oversized private checkpoints cannot silently authorize replacement calls', async () => {
  const f = await setup(), asOf = new Date(Date.now() - 2 * 86400000).toISOString();
  await assert.rejects(frozenGenerationContext(f.store, key, f, owner, { integrationResearch: { schemaVersion: 1, appId: f.app.id, jobId: f.job.id, catalogHash: 'a'.repeat(64), contextHash: 'b'.repeat(64), evidenceHash: 'c'.repeat(64), asOf, expiresAt: new Date(Date.now() - 86400000).toISOString(), integrations: [] } }), /stale/);
  await assert.rejects(frozenGenerationContext(f.store, key, f, owner, { answer: 'x'.repeat(12 * 1024 * 1024) }), ModelCheckpointError);
  assert.equal(await f.store.read(state => Object.keys(state.generationContexts).length), 0);
  const g = recordModelCalls({ complete: async (_input, budget) => { const id = await budget.reserve(.1); await budget.settle(id, .01); return { text: 'x'.repeat(8 * 1024 * 1024), model: 'synthetic-large', provider: 'openai', costUsd: .01, usage: { inputTokens: 1, outputTokens: 1, cachedTokens: 0, cacheWriteTokens: 0 } }; } } as Pick<ModelGateway, 'complete'>, f.store, key);
  await assert.rejects(g.complete(request(f.job), hooks(f.store, f.job)), ModelCheckpointError); assert.equal(await f.store.read(state => Object.keys(state.modelCheckpoints).length), 0); assert.equal(await f.store.read(state => Object.values(state.modelCalls)[0]?.status), 'uncertain');
});
