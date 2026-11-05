import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createPool, type PoolOptions } from 'mysql2/promise';
import { loadConfig, type Config } from './config.ts';
import { JsonStore, MysqlStore, type Store } from './store.ts';
import { BudgetManager } from './budget.ts';
import { WorkflowEngine, type EngineDependencies } from './engine.ts';
import { observableStore } from './progress-bus.ts';
export function mysqlPoolOptions(config: Pick<Config, 'mysqlUrl' | 'authMode'>, ca?: string): PoolOptions {
  if (!config.mysqlUrl) throw new Error('A MySQL connection URL is required.');
  const uri = new URL(config.mysqlUrl);
  if (uri.protocol !== 'mysql:' || !uri.hostname || !uri.pathname.slice(1)) throw new Error('A valid MySQL host and database are required.');
  const ssl = ca ? { ca, rejectUnauthorized: true, verifyIdentity: true, minVersion: 'TLSv1.2' } : undefined;
  if (config.authMode === 'oidc' && !ssl) throw new Error('Production MySQL requires MYSQL_CA_FILE for verified TLS.');
  return { host: uri.hostname, port: Number(uri.port || 3306), user: decodeURIComponent(uri.username), password: decodeURIComponent(uri.password), database: decodeURIComponent(uri.pathname.slice(1)), ssl, connectionLimit: 8, dateStrings: true };
}
export async function createRuntime(dependencies: EngineDependencies = {}) {
  const config = await loadConfig(); let store: Store;
  if (config.mysqlUrl) {
    const ca = process.env.MYSQL_CA_FILE ? await readFile(process.env.MYSQL_CA_FILE, 'utf8') : undefined;
    const mysql = new MysqlStore(createPool(mysqlPoolOptions(config, ca))); await mysql.initialize(); store = mysql;
  } else {
    if (config.authMode !== 'development') throw new Error('Production requires MySQL.');
    const json = new JsonStore(resolve(config.dataDir, 'development-state.json')); await json.initialize(); store = json;
  }
  if (config.authMode === 'oidc' && (!config.redisUrl?.startsWith('rediss:') || !process.env.REDIS_CA_FILE)) throw new Error('Production Redis requires REDIS_URL_FILE with verified TLS and REDIS_CA_FILE.');
  store = await observableStore(store, config.redisUrl);
  const budgets = new BudgetManager(store, config.requestLimitUsd, config.monthlyLimitUsd, config.spendingAuthority);
  try { await budgets.initialize(); } catch (failure) { await store.close(); throw failure; }
  const engine = new WorkflowEngine(store, dependencies, budgets, config.workspaceDir, config.secretKey); return { config, store, budgets, engine };
}
