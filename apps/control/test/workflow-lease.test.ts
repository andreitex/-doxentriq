import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';
import { JsonStore } from '../src/store.ts';
import { BudgetManager } from '../src/budget.ts';
import { WorkflowEngine, type GenerationResult } from '../src/engine.ts';

function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const clarification = (question: string): GenerationResult => ({ specification: { questions: [question] }, files: [], pipeline: null, summary: '' });

async function fixture() {
  const store = new JsonStore(), now = new Date().toISOString();
  const app: AppRecord = { id: randomUUID(), slug: 'lease-test', name: 'Lease test', description: '', kind: 'web', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt: now, updatedAt: now };
  const job: JobRecord = { id: randomUUID(), appId: app.id, request: 'Clarify document requirements', stage: 'queued', baseReleaseId: null, costUsd: 0, budgetUsd: 1, attempts: 0, createdAt: now, updatedAt: now };
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; });
  return { store, app, job, budgets: new BudgetManager(store, 1, 5) };
}

test('same-engine takeover rejects old clarification and preserves the replacement lease', async () => {
  const { store, app, job, budgets } = await fixture();
  const entered = [deferred<void>(), deferred<void>()], replies = [deferred<GenerationResult>(), deferred<GenerationResult>()];
  let calls = 0;
  const engine = new WorkflowEngine(store, { planAndGenerate: async () => { const index = calls++; entered[index]!.resolve(); return replies[index]!.promise; } }, budgets, 'unused-lease-workspace');
  const old = engine.run(job.id); let replacement: Promise<void> | undefined;
  try {
    await entered[0]!.promise;
    await store.transaction(state => { state.leases[job.id]!.until = new Date(Date.now() - 1).toISOString(); });
    replacement = engine.run(job.id); await entered[1]!.promise;
    const current = await store.read(state => state);
    assert.equal(current.apps[app.id]?.runtimeFence, 2); assert.equal(current.leases[job.id]?.owner, engine.workerId);
    replies[0]!.resolve(clarification('Stale question')); await old;
    assert.deepEqual(await store.read(state => state), current);
    replies[1]!.resolve(clarification('Current question')); await replacement;
    assert.deepEqual(await store.read(state => state.jobs[job.id]?.specification?.questions), ['Current question']);
    assert.equal(await store.read(state => state.leases[job.id]), undefined);
  } finally { replies[0]!.resolve(clarification('Cleanup')); replies[1]!.resolve(clarification('Cleanup')); await Promise.all([old, replacement]); }
});

test('stale implementation output cannot overwrite a newer same-engine attempt', async () => {
  const { store, job, budgets } = await fixture();
  const entered = [deferred<void>(), deferred<void>()], replies = [deferred<GenerationResult>(), deferred<GenerationResult>()];
  let calls = 0, verifications = 0;
  const engine = new WorkflowEngine(store, { planAndGenerate: async () => { const index = calls++; entered[index]!.resolve(); return replies[index]!.promise; }, verify: async () => { verifications++; throw new Error('Stale output must not reach verification'); } }, budgets, 'unused-lease-workspace');
  const old = engine.run(job.id); let replacement: Promise<void> | undefined;
  try {
    await entered[0]!.promise;
    await store.transaction(state => { state.leases[job.id]!.until = new Date(Date.now() - 1).toISOString(); });
    replacement = engine.run(job.id); await entered[1]!.promise;
    const current = await store.read(state => state);
    replies[0]!.resolve({ specification: { goal: 'Stale implementation' }, files: [{ path: 'src/main.ts', content: 'stale' }], pipeline: {}, summary: 'Stale' });
    await old;
    assert.deepEqual(await store.read(state => state), current); assert.equal(verifications, 0);
    replies[1]!.resolve(clarification('Current')); await replacement;
  } finally { replies[0]!.resolve(clarification('Cleanup')); replies[1]!.resolve(clarification('Cleanup')); await Promise.all([old, replacement]); }
});

test('an old job failure cannot reset the app or publish attention during a newer job', async () => {
  const { store, app, job, budgets } = await fixture();
  const nextJob: JobRecord = { ...job, id: randomUUID(), request: 'A newer request' };
  await store.transaction(state => { state.jobs[nextJob.id] = nextJob; });
  const firstEntered = deferred<void>(), nextEntered = deferred<void>(), oldReply = deferred<GenerationResult>(), nextReply = deferred<GenerationResult>();
  const engine = new WorkflowEngine(store, { planAndGenerate: async input => { if (input.job.id === job.id) { firstEntered.resolve(); return oldReply.promise; } nextEntered.resolve(); return nextReply.promise; } }, budgets, 'unused-lease-workspace');
  const old = engine.run(job.id); let next: Promise<void> | undefined;
  try {
    await firstEntered.promise;
    await store.transaction(state => { state.leases[job.id]!.until = new Date(Date.now() - 1).toISOString(); });
    next = engine.run(nextJob.id); await nextEntered.promise;
    const current = await store.read(state => state);
    oldReply.reject(new Error('Stale worker lost its response')); await old;
    const after = await store.read(state => state);
    assert.deepEqual(after.apps[app.id], current.apps[app.id]); assert.deepEqual(after.jobs, current.jobs);
    assert.deepEqual(after.events, current.events); assert.deepEqual(after.notifications, current.notifications);
    assert.deepEqual(after.leases[nextJob.id], current.leases[nextJob.id]); assert.equal(after.leases[job.id], undefined);
    nextReply.resolve(clarification('Newer request')); await next;
  } finally { oldReply.resolve(clarification('Cleanup')); nextReply.resolve(clarification('Cleanup')); await Promise.all([old, next]); }
});

test('expired and malformed lease expiry cannot accept a late result and remain recoverable', async () => {
  for (const until of [new Date(Date.now() - 1).toISOString(), 'not-a-date']) {
    const { store, job, budgets } = await fixture(), entered = deferred<void>(), reply = deferred<GenerationResult>();
    const engine = new WorkflowEngine(store, { planAndGenerate: async () => { entered.resolve(); return reply.promise; } }, budgets, 'unused-lease-workspace');
    const running = engine.run(job.id);
    try {
      await entered.promise; await store.transaction(state => { state.leases[job.id]!.until = until; });
      reply.resolve(clarification('Expired result')); await running;
      assert.equal(await store.read(state => state.jobs[job.id]?.stage), 'specification');
      assert.equal(await store.read(state => state.jobs[job.id]?.result), undefined);
      assert.equal(await store.read(state => state.leases[job.id]), undefined);
      await engine.recover(); assert.equal(await store.read(state => Object.values(state.outbox).filter(item => item.jobId === job.id).length), 1);
    } finally { reply.resolve(clarification('Cleanup')); await running; }
  }
});

test('an expired heartbeat cannot renew its original lease', async t => {
  const { store, job, budgets } = await fixture(), entered = deferred<void>(), reply = deferred<GenerationResult>();
  const nativeInterval = globalThis.setInterval; let heartbeat!: () => void;
  t.mock.method(globalThis, 'setInterval', ((callback: () => void) => { heartbeat = callback; return nativeInterval(callback, 3600000); }) as typeof setInterval);
  const engine = new WorkflowEngine(store, { planAndGenerate: async () => { entered.resolve(); return reply.promise; } }, budgets, 'unused-lease-workspace');
  const running = engine.run(job.id);
  try {
    await entered.promise; const expired = new Date(Date.now() - 1).toISOString();
    await store.transaction(state => { state.leases[job.id]!.until = expired; });
    heartbeat(); assert.equal(await store.read(state => state.leases[job.id]?.until), expired);
    reply.resolve(clarification('Expired')); await running;
  } finally { reply.resolve(clarification('Cleanup')); await running; }
});

test('a changed baseline at acquisition records attention instead of requeuing forever', async () => {
  const { store, app, job, budgets } = await fixture(), currentRelease = randomUUID();
  await store.transaction(state => { state.apps[app.id]!.activeReleaseId = currentRelease; state.apps[app.id]!.status = 'published'; });
  let calls = 0;
  const engine = new WorkflowEngine(store, { planAndGenerate: async () => { calls++; return clarification('Must not generate'); } }, budgets, 'unused-lease-workspace');
  await engine.run(job.id);
  const after = await store.read(state => state);
  assert.equal(calls, 0); assert.equal(after.jobs[job.id]?.stage, 'needs_attention');
  assert.match(String(after.jobs[job.id]?.result?.error), /application changed while this request was paused/);
  assert.equal(after.apps[app.id]?.status, 'published'); assert.equal(after.apps[app.id]?.activeReleaseId, currentRelease);
  assert.equal(after.leases[job.id], undefined);
  await engine.recover(); assert.equal(await store.read(state => Object.keys(state.outbox).length), 0);
});

test('a changed baseline during generation refuses partial attachment and automatic repair', async () => {
  const { store, app, job, budgets } = await fixture(), entered = deferred<void>(), reply = deferred<GenerationResult>(), currentRelease = randomUUID();
  const engine = new WorkflowEngine(store, { planAndGenerate: async () => { entered.resolve(); return reply.promise; } }, budgets, 'unused-lease-workspace');
  const running = engine.run(job.id);
  try {
    await entered.promise; await store.transaction(state => { state.apps[app.id]!.activeReleaseId = currentRelease; });
    reply.reject(Object.assign(new Error('Independent code review needs changes: Stale partial source'), { partialGeneration: { specification: { goal: 'Stale' }, files: [{ path: 'src/main.ts', content: 'stale' }], pipeline: {}, summary: 'Stale' } }));
    await running;
    const after = await store.read(state => state);
    assert.equal(after.jobs[job.id]?.stage, 'needs_attention'); assert.equal(after.jobs[job.id]?.specification, undefined);
    assert.equal(after.jobs[job.id]?.result?.workspacePath, undefined); assert.equal(after.repairAttempts[job.id], undefined);
    assert.equal(after.apps[app.id]?.status, 'published'); assert.equal(after.apps[app.id]?.activeReleaseId, currentRelease);
    assert.equal(after.leases[job.id], undefined); assert.equal(Object.keys(after.outbox).length, 0);
  } finally { reply.resolve(clarification('Cleanup')); await running; }
});
