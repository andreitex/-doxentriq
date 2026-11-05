import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';
import type { ModelGateway } from '../../../packages/core/src/models.ts';
import { JsonStore, enqueue } from '../src/store.ts';
import { BudgetManager } from '../src/budget.ts';
import { WorkflowEngine } from '../src/engine.ts';
import { recordModelCalls } from '../src/model-records.ts';
import { createServer } from '../src/server.ts';
import type { Config } from '../src/config.ts';

async function setup(file?: string) {
  const store = new JsonStore(file); await store.initialize(); const now = new Date().toISOString();
  const app: AppRecord = { id: randomUUID(), name: 'Documents', slug: 'documents-hold', description: '', kind: 'web', status: 'building', activeReleaseId: null, url: null, previewUrl: null, runtimeFence: 3, createdAt: now, updatedAt: now };
  const job: JobRecord = { id: randomUUID(), appId: app.id, request: 'Preserve document folders', stage: 'specification', baseReleaseId: null, costUsd: 0, budgetUsd: 1, attempts: 0, runtimeFence: 3, createdAt: now, updatedAt: now };
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
  const budgets = new BudgetManager(store, 1, 5); return { store, app, job, budgets };
}
async function interrupted(context: Awaited<ReturnType<typeof setup>>, status: 'running' | 'uncertain' = 'running', ageMs = 120000) {
  const reservationId = await context.budgets.hooks(context.job.id).reserve(.4), callId = randomUUID();
  await context.store.transaction(state => {
    state.modelCalls[callId] = { id: callId, jobId: context.job.id, stage: 'design', status, model: null, provider: null, costUsd: null, usage: null, reservationIds: [reservationId], runtimeFence: 3, startedAt: new Date(Date.now() - ageMs).toISOString(), completedAt: null };
    state.leases[context.job.id] = { owner: 'interrupted-worker', until: new Date(Date.now() - 1000).toISOString() };
  });
  return { reservationId, callId };
}

test('interrupted model recovery retains billing evidence and records attention instead of another dispatch', async () => {
  const context = await setup(), { store, app, job, budgets } = context;
  const { callId, reservationId } = await interrupted(context);
  await new WorkflowEngine(store, {}, budgets, 'unused').recover();
  const state = await store.read(state => state);
  assert.equal(state.modelCalls[callId]?.status, 'uncertain'); assert.equal(state.reservations[reservationId]?.actualUsd, null);
  assert.equal(state.jobs[job.id]?.stage, 'needs_attention'); assert.equal(state.jobs[job.id]?.result?.modelBillingHold, true);
  assert.equal(state.jobs[job.id]?.result?.attentionKind, 'runtime_unavailable'); assert.match(String(state.jobs[job.id]?.result?.recoveryHint), /reconcil/i);
  assert.equal(state.jobs[job.id]?.costUsd, 0); assert.equal(state.apps[app.id]?.runtimeFence, 3); assert.equal(Object.keys(state.outbox).length, 0);
});

test('a lost lease with a recently started model call still blocks replay without inventing free billing', async () => {
  const context = await setup(), { store, job, budgets } = context;
  const { callId, reservationId } = await interrupted(context, 'running', 1000);
  await new WorkflowEngine(store, {}, budgets, 'unused').recover();
  assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'needs_attention');
  assert.equal(await store.read(state => state.modelCalls[callId]?.status), 'uncertain');
  assert.equal(await store.read(state => state.reservations[reservationId]?.actualUsd), null);
});

test('reopened attention state and stale queued deliveries cannot make another provider call', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'autosoft-model-hold-'));
  try {
    const file = join(directory, 'state.json'), context = await setup(file);
    await interrupted(context); await context.store.transaction(state => enqueue(state, context.job.id));
    await new WorkflowEngine(context.store, {}, context.budgets, 'unused').recover();
    const reopened = new JsonStore(file); await reopened.initialize(); let calls = 0;
    const engine = new WorkflowEngine(reopened, { planAndGenerate: async () => { calls++; throw new Error('Duplicate provider dispatch'); } }, new BudgetManager(reopened, 1, 5), 'unused');
    await engine.recover(); await engine.run(context.job.id);
    assert.equal(calls, 0); assert.equal(await reopened.read(state => state.jobs[context.job.id]?.result?.modelBillingHold), true);
    assert.equal(await reopened.read(state => Object.keys(state.leases).length), 0); assert.equal(await reopened.read(state => Object.keys(state.reservations).length), 1);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('worker admission blocks an unresolved call even before the recovery sweep runs', async () => {
  const context = await setup(), { store, app, job, budgets } = context; await interrupted(context);
  await store.transaction(state => { delete state.leases[job.id]; state.jobs[job.id]!.stage = 'queued'; });
  let calls = 0;
  await new WorkflowEngine(store, { planAndGenerate: async () => { calls++; throw new Error('Duplicate provider dispatch'); } }, budgets, 'unused').run(job.id);
  assert.equal(calls, 0); assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'needs_attention');
  assert.equal(await store.read(state => state.apps[app.id]?.runtimeFence), 3); assert.equal(await store.read(state => Object.keys(state.leases).length), 0);
});

test('a crash between reservation commit and call linkage keeps the unlinked cost held', async () => {
  const context = await setup(), { store, job, budgets } = context; const { callId, reservationId } = await interrupted(context);
  await store.transaction(state => { state.modelCalls[callId]!.reservationIds = []; });
  const engine = new WorkflowEngine(store, { planAndGenerate: async () => { throw new Error('Unlinked reservation must not permit dispatch'); } }, budgets, 'unused');
  await engine.recover(); await engine.run(job.id);
  assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'needs_attention');
  assert.equal(await store.read(state => state.reservations[reservationId]?.actualUsd), null);
  assert.equal(await store.read(state => state.modelCalls[callId]?.reservationIds.length), 0);
  assert.equal(await store.read(state => Object.keys(state.reservations).length), 1);
});

test('more budget and a confirmed settlement do not silently reconcile an uncertain call record', async () => {
  const context = await setup(), { store, job, budgets } = context;
  const { reservationId } = await interrupted(context, 'uncertain');
  await store.transaction(state => { state.jobs[job.id]!.budgetUsd = 10; });
  await assert.rejects(budgets.hooks(job.id).reserve(.1), /reconcil/i);
  await budgets.hooks(job.id).settle(reservationId, .2);
  await assert.rejects(budgets.hooks(job.id).reserve(.1), /reconcil/i);
  assert.equal(await store.read(state => Object.keys(state.reservations).length), 1); assert.equal(await store.read(state => state.jobs[job.id]?.costUsd), .2);
});

test('manual resume rejects unresolved billing before any workflow or application mutation', async () => {
  const context = await setup(), { store, job } = context; await interrupted(context, 'uncertain');
  await store.transaction(state => { state.jobs[job.id]!.stage = 'needs_attention'; state.jobs[job.id]!.result = { attentionKind: 'runtime_unavailable' }; });
  const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: 'unused', workspaceDir: 'unused', oidcClientId: 'test', secretKey: Buffer.alloc(32, 42), requestLimitUsd: 1, monthlyLimitUsd: 5, adminDist: 'absent-model-hold-dist' };
  const server = await createServer(config, store, {});
  try {
    const session = await server.inject({ method: 'GET', url: '/api/v1/session' }), cookie = session.cookies[0]!;
    const before = await store.read(state => ({ jobs: state.jobs, apps: state.apps, outbox: state.outbox, calls: state.modelCalls, reservations: state.reservations, events: state.events }));
    const response = await server.inject({ method: 'POST', url: `/api/v1/jobs/${job.id}/resume`, headers: { cookie: `${cookie.name}=${cookie.value}`, origin: config.publicOrigin, 'x-csrf-token': session.json().csrfToken }, payload: { answer: 'Retry after increasing the budget' } });
    assert.equal(response.statusCode, 409, response.body); assert.match(response.json().error.message, /reconcil/i);
    assert.deepEqual(await store.read(state => ({ jobs: state.jobs, apps: state.apps, outbox: state.outbox, calls: state.modelCalls, reservations: state.reservations, events: state.events })), before);
  } finally { await server.close(); }
});

test('a real recorded uncertain completion sets the same billing hold without waiting for a crash', async () => {
  const context = await setup(), { store, job, budgets } = context;
  const gateway = recordModelCalls({ complete: async (_input, hooks) => { await hooks.reserve(.4); throw new Error('Model connection ended without a confirmed billing outcome; the reservation remains held for reconciliation'); } } as Pick<ModelGateway, 'complete'>, store);
  await new WorkflowEngine(store, { planAndGenerate: async (input, hooks) => { await gateway.complete({ stage: 'design', jobId: input.job.id, system: 'Synthetic', prompt: 'Synthetic' }, hooks); throw new Error('No completion'); } }, budgets, 'unused').run(job.id);
  const state = await store.read(state => state);
  assert.equal(state.jobs[job.id]?.result?.modelBillingHold, true); assert.equal(state.jobs[job.id]?.stage, 'needs_attention');
  assert.equal(Object.values(state.modelCalls)[0]?.status, 'uncertain'); assert.equal(Object.values(state.reservations)[0]?.actualUsd, null); assert.equal(Object.keys(state.outbox).length, 0);
});

test('non-model interruption and confirmed completed or refused calls retain normal recovery', async () => {
  for (const status of [undefined, 'completed', 'failed'] as const) {
    const context = await setup(), { store, job, budgets } = context;
    if (status) { const { callId, reservationId } = await interrupted(context); await budgets.hooks(job.id).settle(reservationId, status === 'completed' ? .1 : 0); await store.transaction(state => { state.modelCalls[callId]!.status = status; }); }
    await store.transaction(state => { state.leases[job.id] = { owner: 'lost-worker', until: new Date(Date.now() - 1000).toISOString() }; });
    let calls = 0; const engine = new WorkflowEngine(store, { planAndGenerate: async () => { calls++; return { specification: { questions: ['Which folders?'] }, files: [], pipeline: null, summary: '' }; } }, budgets, 'unused');
    await engine.recover(); assert.equal(await store.read(state => Object.keys(state.outbox).length), 1); await engine.run(job.id);
    assert.equal(calls, 1, String(status)); assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'clarification');
  }
});

test('a current billing hold restores the app badge while retaining draft or published data', async () => {
  for (const published of [false, true]) {
    const context = await setup(); await interrupted(context);
    await context.store.transaction(state => { if (published) state.apps[context.app.id]!.activeReleaseId = 'preserved-active-release'; });
    const before = await context.store.read(state => state.apps[context.app.id]);
    await new WorkflowEngine(context.store, {}, context.budgets, 'unused').recover();
    assert.deepEqual(await context.store.read(state => state.apps[context.app.id]), { ...before, status: published ? 'published' : 'draft' });
    assert.equal(await context.store.read(state => state.jobs[context.job.id]?.result?.modelBillingHold), true);
  }
});

test('an older held workflow cannot change a newer application build badge or fence', async () => {
  const context = await setup(); await interrupted(context);
  await context.store.transaction(state => { state.apps[context.app.id]!.runtimeFence = 4; });
  const before = await context.store.read(state => state.apps[context.app.id]);
  await new WorkflowEngine(context.store, {}, context.budgets, 'unused').recover();
  assert.deepEqual(await context.store.read(state => state.apps[context.app.id]), before);
  assert.equal(await context.store.read(state => state.jobs[context.job.id]?.stage), 'needs_attention');
});
