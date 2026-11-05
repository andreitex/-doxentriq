import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JsonStore } from '../src/store.ts';
import { BudgetManager, budgetSummary } from '../src/budget.ts';
import { authorityMonth, spendingAuthoritySchema, assertAuthorityCeiling, type SpendingAuthority } from '../src/spending-authority.ts';
import type { JobRecord } from '../../../packages/core/src/types.ts';

function grant(): SpendingAuthority {
  return { schemaVersion: 1, id: 'a'.repeat(32), month: authorityMonth('Europe/Bucharest'), timezone: 'Europe/Bucharest', adminOrigin: 'https://admin.example.test', beforeLedgerSha256: 'b'.repeat(64), monthlyLimitMicrousd: 30_000_000, confirmedExternalMicrousd: 895128, conservativeExternalMicrousd: 2_000_000, allocationMicrousd: 27104872 };
}
async function fixture(store = new JsonStore()) {
  await store.initialize();
  await store.transaction(state => {
    state.jobs.job = { id: 'job', appId: 'app', request: 'Synthetic accounting only', stage: 'implementation', baseReleaseId: null, costUsd: 0, budgetUsd: 30, attempts: 0, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() } satisfies JobRecord;
  });
  const authority = grant(), manager = new BudgetManager(store, 1, 30, authority);
  await manager.initialize(); return { store, authority, manager, hooks: manager.hooks('job') };
}
test('historical confirmed charges and conservative debit consume one allowance without becoming platform invoices', async () => {
  const f = await fixture(); const summary = await f.store.read(s => budgetSummary(s, 1, 30));
  assert.equal(summary.externalConfirmedUsd, .895128); assert.equal(summary.externalConservativeUsd, 2);
  assert.equal(summary.workflowSpentUsd, 0); assert.equal(summary.remainingUsd, 27.104872);
  const results = await Promise.allSettled([f.hooks.reserve(20), f.hooks.reserve(20)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const id = (results.find(r => r.status === 'fulfilled') as PromiseFulfilledResult<string>).value;
  await f.hooks.settle(id, 1); await f.hooks.settle(id, 1);
  assert.equal((await f.store.read(s => budgetSummary(s, 1, 30))).remainingUsd, 26.104872);
});
test('idempotent adoption and reservations survive restart; missing or changed authority blocks a worker', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-budget-'));
  try {
    const f = await fixture(new JsonStore(join(root, 'state.json'))); await f.hooks.reserve(20); await f.store.close();
    const reopened = new JsonStore(join(root, 'state.json')); await reopened.initialize();
    const manager = new BudgetManager(reopened, 1, 30, f.authority); await manager.initialize(); await manager.initialize();
    await assert.rejects(manager.hooks('job').reserve(8), /spending limit/);
    await assert.rejects(new BudgetManager(reopened, 1, 30).initialize(), /missing or changed/);
    await assert.rejects(new BudgetManager(reopened, 1, 30).hooks('job').reserve(.1), /missing or changed/);
    await assert.rejects(new BudgetManager(reopened, 1, 30, { ...f.authority, id: 'c'.repeat(32) }).initialize(), /missing or changed/);
    assert.equal(await reopened.read(s => Object.keys(s.spendingAuthorities).length), 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('a recurring UI policy and environment cannot raise the delegated ceiling', async () => {
  const f = await fixture(); await f.store.transaction(s => { s.settings.budget = { monthlyLimitUsd: 100 }; });
  assert.equal((await f.store.read(s => budgetSummary(s, 1, 100))).monthlyLimitUsd, 30);
  await assert.rejects(f.store.read(s => assertAuthorityCeiling(s, 31)), /company-authorized/);
  await assert.rejects(f.hooks.reserve(27.104873), /spending limit/);
  const id = await f.hooks.reserve(27.104872); assert.ok(id);
});
test('an expired handover never silently renews, and old unresolved reservations remain visible', async () => {
  const f = await fixture(); const old = { ...f.authority, month: '2000-01' };
  await f.store.transaction(s => {
    s.spendingAuthorities[f.authority.id]!.authority = old;
    s.reservations.old = { id: 'old', jobId: 'job', month: '2000-01', amountUsd: 2, actualUsd: null, createdAt: '2000-01-01T00:00:00Z' };
  });
  const summary = await f.store.read(s => budgetSummary(s, 1, 30));
  assert.equal(summary.authorityExpired, true); assert.equal(summary.remainingUsd, 0); assert.equal(summary.reservedUsd, 2);
  await assert.rejects(new BudgetManager(f.store, 1, 30, old).hooks('job').reserve(.1), /spending limit/);
});
test('adoption refuses existing workflow accounting, expired grants and malformed monetary allocations', async () => {
  const store = new JsonStore(); await store.transaction(s => { s.reservations.old = { id: 'old', jobId: 'job', month: authorityMonth(), amountUsd: 1, actualUsd: 0, createdAt: new Date().toISOString() }; });
  await assert.rejects(new BudgetManager(store, 1, 30, grant()).initialize(), /Existing platform model accounting/);
  await assert.rejects(new BudgetManager(new JsonStore(), 1, 30, { ...grant(), month: '2000-01' }).initialize(), /expired/);
  for (const changed of [{ allocationMicrousd: 30_000_000 }, { confirmedExternalMicrousd: -1 }, { month: '2026-13' }, { timezone: 'invalid-zone' }, { adminOrigin: 'https://admin.example.test/path' }, { adminOrigin: 'not-a-url' }, { unexpected: true }]) {
    assert.equal(spendingAuthoritySchema.safeParse({ ...grant(), ...changed }).success, false);
  }
});
test('month boundaries use the company ledger timezone', () => {
  const instant = new Date('2026-10-31T22:30:00Z');
  assert.equal(authorityMonth('UTC', instant), '2026-10'); assert.equal(authorityMonth('Europe/Bucharest', instant), '2026-11');
});

test('sub-microdollar estimates are conservatively rounded before a shared reservation', async () => {
  const f = await fixture(); const id = await f.hooks.reserve(.000000001);
  assert.equal(await f.store.read(s => s.reservations[id]!.amountUsd), .000001);
  await f.hooks.settle(id, .000000001);
  const summary = await f.store.read(s => budgetSummary(s, 1, 30));
  assert.equal(summary.workflowSpentUsd, .000001); assert.equal(summary.remainingUsd, 27.104871);
});
