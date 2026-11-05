import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Completion, ModelGateway } from '../../../packages/core/src/models.ts';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';
import { JsonStore } from '../src/store.ts';
import { BudgetManager } from '../src/budget.ts';
import { recordModelCalls } from '../src/model-records.ts';
import { WorkflowEngine } from '../src/engine.ts';

async function setup(file?: string) {
  const store = new JsonStore(file); await store.initialize(); const now = new Date().toISOString();
  const app: AppRecord = { id: randomUUID(), name: 'Documents', slug: 'documents-test', description: '', kind: 'web', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt: now, updatedAt: now };
  const job: JobRecord = { id: randomUUID(), appId: app.id, request: 'Create a document app', stage: 'specification', baseReleaseId: null, costUsd: 0, budgetUsd: 1, attempts: 0, createdAt: now, updatedAt: now };
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; }); return { store, app, job, hooks: new BudgetManager(store, 1, 5).hooks(job.id) };
}
const request = (jobId: string) => ({ stage: 'design' as const, jobId, system: 'Never persist this secret setup instruction', prompt: 'Do not record this production-sensitive test prompt.' });

test('model records persist actual routing and billing metadata without prompt, output or provider credentials', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-model-records-')); const file = join(root, 'state.json'); const { store, job, hooks } = await setup(file);
  const gateway: Pick<ModelGateway, 'complete'> = { complete: async (_input, budget) => { const id = await budget.reserve(0.4); await budget.settle(id, 0.12); return { model: 'qualified-model-from-provider', provider: 'anthropic', text: 'Generated body must not be persisted in billing metadata', costUsd: 0.12, usage: { inputTokens: 123, outputTokens: 45, cachedTokens: 20, cacheWriteTokens: 3 } }; } };
  try {
    await recordModelCalls(gateway, store).complete(request(job.id), hooks); const record = await store.read(state => Object.values(state.modelCalls)[0]!);
    assert.equal(record.status, 'completed'); assert.equal(record.model, 'qualified-model-from-provider'); assert.equal(record.provider, 'anthropic'); assert.equal(record.costUsd, 0.12); assert.equal(record.reservationIds.length, 1); assert.deepEqual(record.usage, { inputTokens: 123, outputTokens: 45, cachedTokens: 20, cacheWriteTokens: 3 });
    const persisted = await readFile(file, 'utf8'); assert.ok(!persisted.includes('production-sensitive test prompt')); assert.ok(!persisted.includes('secret setup instruction')); assert.ok(!persisted.includes('Generated body must not be persisted'));
    const reopened = new JsonStore(file); await reopened.initialize(); assert.equal(await reopened.read(state => Object.values(state.modelCalls)[0]?.provider), 'anthropic');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('uncertain provider outcomes keep their reservation and never invent zero billing or provider selection', async () => {
  const { store, job, hooks } = await setup();
  const gateway: Pick<ModelGateway, 'complete'> = { complete: async (_input, budget) => { await budget.reserve(0.4); throw new Error('Connection interrupted with password=secret-provider-diagnostic'); } };
  await assert.rejects(recordModelCalls(gateway, store).complete(request(job.id), hooks), /Connection interrupted/);
  const state = await store.read(state => state); const record = Object.values(state.modelCalls)[0]!; assert.equal(record.status, 'uncertain'); assert.equal(record.costUsd, null); assert.equal(record.model, null); assert.equal(record.provider, null); assert.ok(!record.error?.includes('secret-provider-diagnostic')); assert.equal(Object.values(state.reservations)[0]?.actualUsd, null); assert.equal(state.jobs[job.id]?.costUsd, 0);
});

test('malformed usage is refused even when provider charges were confirmed', async () => {
  const { store, job, hooks } = await setup();
  const gateway: Pick<ModelGateway, 'complete'> = { complete: async (_input, budget) => { const id = await budget.reserve(0.4); await budget.settle(id, 0.1); return { model: 'model-test', provider: 'openai', text: 'invalid output', costUsd: 0.1, usage: {} } as Completion; } };
  await assert.rejects(recordModelCalls(gateway, store).complete(request(job.id), hooks), /metadata is malformed/); const record = await store.read(state => Object.values(state.modelCalls)[0]!); assert.equal(record.status, 'failed'); assert.equal(record.costUsd, 0.1); assert.equal(record.usage, null); assert.equal(record.model, null);
});

test('worker recovery marks interrupted call evidence uncertain and preserves held reservations', async () => {
  const { store, job, hooks } = await setup(); const reservationId = await hooks.reserve(0.4); const id = randomUUID();
  await store.transaction(state => { state.modelCalls[id] = { id, jobId: job.id, stage: 'review', status: 'running', model: null, provider: null, costUsd: null, usage: null, reservationIds: [reservationId], startedAt: new Date(Date.now() - 120000).toISOString(), completedAt: null }; state.leases[job.id] = { owner: 'interrupted-worker', until: new Date(Date.now() - 1000).toISOString() }; });
  await new WorkflowEngine(store, {}, new BudgetManager(store, 1, 5), 'unused-workspace').recover(); const state = await store.read(state => state); assert.equal(state.modelCalls[id]?.status, 'uncertain'); assert.equal(state.reservations[reservationId]?.actualUsd, null); assert.equal(state.jobs[job.id]?.stage, 'needs_attention'); assert.equal(state.jobs[job.id]?.result?.modelBillingHold, true); assert.ok(!Object.values(state.outbox).some(entry => entry.jobId === job.id));
});

test('stale worker spending is fenced atomically while incurred charges and completion metadata remain durable', async () => {
  const { store, job } = await setup(); const budgets = new BudgetManager(store, 1, 5); let entered!: () => void, finish!: () => void;
  const started = new Promise<void>(resolve => { entered = resolve; }); const blocked = new Promise<void>(resolve => { finish = resolve; }); let reservationId = '';
  await store.transaction(state => { state.jobs[job.id]!.runtimeFence = 1; state.leases[job.id] = { owner: 'old-worker', until: new Date(Date.now() + 90000).toISOString() }; });
  const oldHooks = budgets.hooks(job.id, { owner: 'old-worker', runtimeFence: 1 });
  const gateway: Pick<ModelGateway, 'complete'> = { complete: async (_input, budget) => { reservationId = await budget.reserve(0.4); entered(); await blocked; await budget.settle(reservationId, 0.1); return { model: 'actual-incurred-model', provider: 'openai', text: 'old output', costUsd: 0.1, usage: { inputTokens: 10, outputTokens: 10, cachedTokens: 0, cacheWriteTokens: 0 } }; } };
  const running = recordModelCalls(gateway, store).complete(request(job.id), oldHooks);
  await started; await store.transaction(state => { state.jobs[job.id]!.runtimeFence = 2; state.jobs[job.id]!.stage = 'implementation'; state.leases[job.id] = { owner: 'replacement-worker', until: new Date(Date.now() + 90000).toISOString() }; });
  finish(); await running;
  await assert.rejects(oldHooks.reserve(0.1), /no further model spending/); assert.equal(await store.read(state => Object.keys(state.reservations).length), 1);
  const state = await store.read(state => state); const call = Object.values(state.modelCalls)[0]!; assert.equal(call.status, 'completed'); assert.equal(call.runtimeFence, 1); assert.equal(call.model, 'actual-incurred-model'); assert.equal(state.reservations[reservationId]?.actualUsd, 0.1); assert.equal(state.jobs[job.id]?.costUsd, 0.1); assert.equal(state.jobs[job.id]?.stage, 'implementation'); assert.equal(state.events.length, 0, 'Old completion must not emit replacement-worker progress.');
  const replacement = await budgets.hooks(job.id, { owner: 'replacement-worker', runtimeFence: 2 }).reserve(0.2); assert.ok(replacement);
});
