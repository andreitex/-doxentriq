import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.ts';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authorityMonth } from '../src/spending-authority.ts';

test('production requires explicit positive spending policies while development retains local defaults', async () => {
  const names = ['AUTH_MODE', 'HOST', 'PUBLIC_ORIGIN', 'MYSQL_URL', 'MYSQL_URL_FILE', 'MYSQL_HOST', 'MYSQL_USER', 'MYSQL_DATABASE', 'OIDC_ISSUER', 'OWNER_SUBJECT', 'SECRET_KEY', 'SECRET_KEY_FILE', 'REQUEST_LIMIT_USD', 'MONTHLY_LIMIT_USD', 'JOB_BUDGET_USD', 'MONTHLY_BUDGET_USD', 'SPENDING_AUTHORITY_FILE'];
  const previous = new Map(names.map(name => [name, process.env[name]]));
  try {
    for (const name of names) delete process.env[name]; process.env.AUTH_MODE = 'oidc';
    await assert.rejects(loadConfig(), /explicit per-request and monthly spending limits/);
    process.env.REQUEST_LIMIT_USD = '5'; await assert.rejects(loadConfig(), /explicit per-request and monthly spending limits/);
    delete process.env.REQUEST_LIMIT_USD; process.env.MONTHLY_LIMIT_USD = '100'; await assert.rejects(loadConfig(), /explicit per-request and monthly spending limits/);
    process.env.SECRET_KEY = Buffer.alloc(32, 42).toString('base64'); process.env.MYSQL_URL = 'mysql://control:test-fixture@mysql/platform'; process.env.OIDC_ISSUER = 'https://identity.example.test/realms/platform'; process.env.PUBLIC_ORIGIN = 'https://admin.example.test'; process.env.OWNER_SUBJECT = 'test-owner'; process.env.JOB_BUDGET_USD = '3'; delete process.env.MONTHLY_LIMIT_USD; process.env.MONTHLY_BUDGET_USD = '90';
    const production = await loadConfig(); assert.equal(production.requestLimitUsd, 3); assert.equal(production.monthlyLimitUsd, 90);
    process.env.REQUEST_LIMIT_USD = '0'; await assert.rejects(loadConfig(), /positive finite/);
    process.env.AUTH_MODE = 'development'; process.env.HOST = '127.0.0.1'; for (const name of ['REQUEST_LIMIT_USD', 'MONTHLY_LIMIT_USD', 'JOB_BUDGET_USD', 'MONTHLY_BUDGET_USD']) delete process.env[name];
    const development = await loadConfig(); assert.equal(development.requestLimitUsd, 5); assert.equal(development.monthlyLimitUsd, 100);
  } finally { for (const name of names) { const value = previous.get(name); if (value === undefined) delete process.env[name]; else process.env[name] = value; } }
});

test('protected spending configuration is bound to the exact administrator origin', async () => {
  const names = ['AUTH_MODE', 'HOST', 'PUBLIC_ORIGIN', 'SECRET_KEY', 'SECRET_KEY_FILE', 'SPENDING_AUTHORITY_FILE'];
  const previous = new Map(names.map(name => [name, process.env[name]]));
  const root = await mkdtemp(join(tmpdir(), 'autosoft-authority-config-'));
  try {
    process.env.AUTH_MODE = 'development'; process.env.HOST = '127.0.0.1'; process.env.PUBLIC_ORIGIN = 'https://admin.example.test';
    process.env.SECRET_KEY = Buffer.alloc(32, 42).toString('base64'); delete process.env.SECRET_KEY_FILE;
    const path = join(root, 'authority.json'); process.env.SPENDING_AUTHORITY_FILE = path;
    await writeFile(path, JSON.stringify({ schemaVersion: 1, id: 'a'.repeat(32), month: authorityMonth(), timezone: 'UTC', adminOrigin: 'https://admin.example.test', beforeLedgerSha256: 'b'.repeat(64), monthlyLimitMicrousd: 30_000_000, confirmedExternalMicrousd: 895128, conservativeExternalMicrousd: 2_000_000, allocationMicrousd: 27104872 }));
    assert.equal((await loadConfig()).spendingAuthority?.allocationMicrousd, 27104872);
    process.env.PUBLIC_ORIGIN = 'https://another-customer.example.test';
    await assert.rejects(loadConfig(), /different administrator origin/);
  } finally {
    for (const name of names) { const value = previous.get(name); if (value === undefined) delete process.env[name]; else process.env[name] = value; }
    await rm(root, { recursive: true, force: true });
  }
});
