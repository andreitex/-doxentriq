import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkServerIdentity, type PeerCertificate } from 'node:tls';
import { createPool } from 'mysql2/promise';
import { mysqlPoolOptions } from '../src/runtime.ts';

test('production MySQL refuses absent trust material and activates mysql2 hostname verification', async () => {
  const config = { authMode: 'oidc' as const, mysqlUrl: 'mysql://control:p%40ss@mysql.internal.test:3306/platform' };
  assert.throws(() => mysqlPoolOptions(config), /verified TLS/);
  const options = mysqlPoolOptions(config, 'test-ca-material'); const pool = createPool(options);
  try {
    const actual = (pool as unknown as { pool: { config: { connectionConfig: { host: string; ssl: { verifyIdentity: boolean; rejectUnauthorized: boolean; minVersion: string } } } } }).pool.config.connectionConfig;
    assert.equal(actual.host, 'mysql.internal.test'); assert.equal(actual.ssl.verifyIdentity, true); assert.equal(actual.ssl.rejectUnauthorized, true); assert.equal(actual.ssl.minVersion, 'TLSv1.2');
    const certificate = { subjectaltname: 'DNS:mysql.internal.test' } as PeerCertificate;
    assert.equal(checkServerIdentity(actual.host, certificate), undefined);
    assert.equal((checkServerIdentity('different.internal.test', certificate) as NodeJS.ErrnoException | undefined)?.code, 'ERR_TLS_CERT_ALTNAME_INVALID');
  } finally { await pool.end(); }
});
