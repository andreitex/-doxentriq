import { fileURLToPath } from 'node:url';
import { DmsService } from './src/domain.mjs';
import { FileStorage } from './src/storage.mjs';
import { connectMySql } from './src/mysql.mjs';
import { loadAuth } from './src/auth.mjs';
import { loadConnector } from './src/connector.mjs';
import { createApplication } from './src/http.mjs';
import { loadTls } from './src/tls.mjs';

async function main() {
  const environment = process.env;
  if (!environment.APP_ORIGIN || new URL(environment.APP_ORIGIN).protocol !== 'https:' || new URL(environment.APP_ORIGIN).origin !== environment.APP_ORIGIN) throw new Error('The exact HTTPS APP_ORIGIN is required.');
  const tls = await loadTls(environment);
  const auth = await loadAuth(environment), repository = await connectMySql(environment), storage = new FileStorage(environment.APP_STORAGE_ROOT, Number(environment.APP_STORAGE_QUOTA_BYTES));
  await storage.initialize();
  const service = new DmsService({ appId: environment.APP_ID, repository, storage, connector: await loadConnector(environment) });
  const server = createApplication({ service, ...auth, tls, allowInsecureHttp: !tls && ['test', 'local'].includes(environment.NODE_ENV), origin: environment.APP_ORIGIN, staticRoot: fileURLToPath(new URL('./dist/', import.meta.url)), ready: () => repository.ready() });
  server.listen(8080, '0.0.0.0', () => process.stdout.write('DMS ready on port 8080\n'));
  const stop = () => { server.close(() => { void repository.close().finally(() => process.exit(0)); }); setTimeout(() => process.exit(1), 15000).unref(); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
}
void main().catch(() => { process.stderr.write('DMS startup failed. Check app-scoped identity, database TLS, migrations, origin, and encrypted storage configuration.\n'); process.exitCode = 1; });
