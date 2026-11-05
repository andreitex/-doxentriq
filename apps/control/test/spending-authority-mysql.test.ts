import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createPool } from 'mysql2/promise';
import { MysqlStore } from '../src/store.ts';
import { BudgetManager, budgetSummary } from '../src/budget.ts';
import { authorityMonth, type SpendingAuthority } from '../src/spending-authority.ts';

const connectionFile = process.env.AUTOSOFT_BUDGET_FIXTURE_CONNECTION_FILE;
test('two actual MySQL workers serialize one shared allowance; restart preserves holds and missing configuration blocks calls', { skip: !connectionFile }, async () => {
  const connection = JSON.parse(await readFile(connectionFile!, 'utf8')) as { host: string; database: string; user: string; password: string; ssl: { ca: string; rejectUnauthorized: boolean; verifyIdentity: boolean } };
  assert.match(connection.database, /^autosoft_budget_fixture_[a-f0-9]{16}$/);
  assert.match(connection.user, /^budget_[a-f0-9]{12}$/);
  assert.equal(connection.ssl.rejectUnauthorized, true); assert.equal(connection.ssl.verifyIdentity, true);
  const open = () => new MysqlStore(createPool({ ...connection, connectionLimit: 2 }));
  const first = open(), second = open(); let reopened: MysqlStore | undefined;
  try {
    await first.initialize(); await second.initialize();
    const authority: SpendingAuthority = { schemaVersion: 1, id: 'a'.repeat(32), month: authorityMonth('Europe/Bucharest'), timezone: 'Europe/Bucharest', adminOrigin: 'https://admin.example.test', beforeLedgerSha256: 'b'.repeat(64), monthlyLimitMicrousd: 30_000_000, confirmedExternalMicrousd: 895128, conservativeExternalMicrousd: 2_000_000, allocationMicrousd: 27104872 };
    await first.transaction(s => { for (const id of ['one', 'two']) s.jobs[id] = { id, appId: 'app', request: 'Synthetic isolated database only', stage: 'implementation', baseReleaseId: null, costUsd: 0, budgetUsd: 30, attempts: 0, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }; });
    const a = new BudgetManager(first, 1, 30, authority), b = new BudgetManager(second, 1, 30, authority);
    await Promise.all([a.initialize(), b.initialize()]);
    const attempts = await Promise.allSettled([a.hooks('one').reserve(20), b.hooks('two').reserve(20)]);
    assert.equal(attempts.filter(result => result.status === 'fulfilled').length, 1);
    reopened = open(); await reopened.initialize();
    const c = new BudgetManager(reopened, 1, 100, authority); await c.initialize();
    const summary = await reopened.read(s => budgetSummary(s, 1, 100));
    assert.equal(summary.monthlyLimitUsd, 30); assert.equal(summary.reservedUsd, 20); assert.equal(summary.remainingUsd, 7.104872);
    await assert.rejects(c.hooks('one').reserve(8), /spending limit/);
    await assert.rejects(new BudgetManager(reopened, 1, 100).hooks('one').reserve(1), /missing or changed/);
  } finally { await Promise.allSettled([first.close(), second.close(), reopened?.close()]); }
});
