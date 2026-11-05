import { spendingAuthoritySchema, type SpendingAuthority } from './spending-authority.ts';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { resolve, dirname } from 'node:path';

export type Config = {
  authMode: 'oidc' | 'development'; host: string; port: number; publicOrigin: string; dataDir: string; workspaceDir: string;
  mysqlUrl?: string; rabbitUrl?: string; redisUrl?: string; oidcIssuer?: string; oidcClientId: string; oidcClientSecret?: string;
  ownerSubject?: string; mfaAcr?: string; secretKey: Buffer; requestLimitUsd: number; monthlyLimitUsd: number;
  brokerUrl?: string; brokerToken?: string; modelCatalogFile?: string; openaiApiKey?: string; anthropicApiKey?: string;
  adminDist: string; appsOrigin?: string;
  reportToken?: string;
  metricsToken?: string;
  spendingAuthority?: SpendingAuthority;
  tlsCertFile?: string; tlsKeyFile?: string;
};
async function secret(name: string): Promise<string | undefined> {
  const path = process.env[`${name}_FILE`]; return path ? (await readFile(path, 'utf8')).trim() : process.env[name];
}
export async function loadConfig(): Promise<Config> {
  const authMode = process.env.AUTH_MODE === 'development' ? 'development' : 'oidc';
  if (authMode === 'oidc' && (!(process.env.REQUEST_LIMIT_USD || process.env.JOB_BUDGET_USD) || !(process.env.MONTHLY_LIMIT_USD || process.env.MONTHLY_BUDGET_USD))) throw new Error('Production requires explicit per-request and monthly spending limits through REQUEST_LIMIT_USD and MONTHLY_LIMIT_USD (or their budget aliases).');
  const host = process.env.HOST ?? (authMode === 'development' ? '127.0.0.1' : '0.0.0.0');
  if (authMode === 'development' && !['127.0.0.1', '::1', 'localhost'].includes(host)) throw new Error('Development authentication must bind to loopback.');
  const dataDir = resolve(process.env.DATA_DIR ?? '.local-data');
  let key = await secret('SECRET_KEY');
  if (!key && authMode === 'development') {
    const keyPath = resolve(dataDir, 'development.key');
    try { key = (await readFile(keyPath, 'utf8')).trim(); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      key = randomBytes(32).toString('base64'); await mkdir(dirname(keyPath), { recursive: true, mode: 0o700 }); await writeFile(keyPath, key, { mode: 0o600, flag: 'wx' });
    }
  }
  const secretKey = Buffer.from(key ?? '', 'base64'); if (secretKey.length !== 32) throw new Error('SECRET_KEY or SECRET_KEY_FILE must contain a base64-encoded 32-byte encryption key.');
  const port = Number(process.env.PORT ?? 3000); const publicOrigin = process.env.PUBLIC_ORIGIN ?? `http://127.0.0.1:${port}`;
  let mysqlUrl = await secret('MYSQL_URL'); const oidcIssuer = process.env.OIDC_ISSUER;
  if (!mysqlUrl && process.env.MYSQL_HOST && process.env.MYSQL_USER && process.env.MYSQL_DATABASE) {
    const password = await secret('MYSQL_PASSWORD');
    if (!password) throw new Error('MYSQL_PASSWORD_FILE is required for the configured database.');
    mysqlUrl = `mysql://${encodeURIComponent(process.env.MYSQL_USER)}:${encodeURIComponent(password)}@${process.env.MYSQL_HOST}:${Number(process.env.MYSQL_PORT ?? 3306)}/${encodeURIComponent(process.env.MYSQL_DATABASE)}`;
  }
  if (authMode === 'oidc') {
    if (!mysqlUrl || !oidcIssuer || !process.env.OWNER_SUBJECT) throw new Error('Production requires MYSQL_URL, OIDC_ISSUER and OWNER_SUBJECT.');
    if (new URL(publicOrigin).protocol !== 'https:' || new URL(oidcIssuer).protocol !== 'https:') throw new Error('Production admin and identity URLs require HTTPS.');
  }
  const requestLimitUsd = Number(process.env.REQUEST_LIMIT_USD ?? process.env.JOB_BUDGET_USD ?? 5); const monthlyLimitUsd = Number(process.env.MONTHLY_LIMIT_USD ?? process.env.MONTHLY_BUDGET_USD ?? 100);
  if (![requestLimitUsd, monthlyLimitUsd].every(value => Number.isFinite(value) && value > 0)) throw new Error('Spending limits must be positive finite amounts.');
  const authorityFile = process.env.SPENDING_AUTHORITY_FILE;
  const spendingAuthority = authorityFile ? spendingAuthoritySchema.parse(JSON.parse(await readFile(authorityFile, 'utf8'))) : undefined;
  if (spendingAuthority && spendingAuthority.adminOrigin !== new URL(publicOrigin).origin) throw new Error('The spending handover belongs to a different administrator origin.');
  return { authMode, host, port, publicOrigin: new URL(publicOrigin).origin, dataDir, workspaceDir: resolve(process.env.WORKSPACE_DIR ?? resolve(dataDir, 'workspaces')),
    mysqlUrl, rabbitUrl: await secret('RABBITMQ_URL'), redisUrl: await secret('REDIS_URL'), oidcIssuer,
    oidcClientId: process.env.OIDC_CLIENT_ID ?? 'autosoft-admin', oidcClientSecret: await secret('OIDC_CLIENT_SECRET'),
    ownerSubject: process.env.OWNER_SUBJECT, mfaAcr: process.env.MFA_ACR, secretKey, requestLimitUsd, monthlyLimitUsd, spendingAuthority,
    brokerUrl: process.env.BROKER_URL, brokerToken: await secret('BROKER_TOKEN'), modelCatalogFile: process.env.MODEL_CATALOG_FILE,
    openaiApiKey: await secret('OPENAI_API_KEY'), anthropicApiKey: await secret('ANTHROPIC_API_KEY'),
    adminDist: resolve('apps/admin/dist'), appsOrigin: process.env.APPS_ORIGIN ?? process.env.APPS_BASE_URL, reportToken: await secret('REPORT_TOKEN'), metricsToken: await secret('METRICS_TOKEN'), tlsCertFile: process.env.CONTROL_TLS_CERT_FILE, tlsKeyFile: process.env.CONTROL_TLS_KEY_FILE };
}
