import { createRuntime } from './runtime.ts';
import { configureDependencies } from './dependencies.ts';
import { createServer } from './server.ts';
import { RabbitDispatcher, startLocalWorker, type LocalWorker } from './messaging.ts';
import type { EngineDependencies } from './engine.ts';
import { observePublishedReleases } from './observation.ts';
import { reconcileAccessOperations } from './access.ts';
import { reconcileConnectorOperations } from './connectors.ts';
import { createShutdown, drainTogether, installTerminationHandlers, WorkDrain } from './shutdown.ts';

const dependencies: EngineDependencies = {}, background = new WorkDrain();
let runtime: Awaited<ReturnType<typeof createRuntime>> | undefined;
let server: Awaited<ReturnType<typeof createServer>> | undefined;
let dispatcher: RabbitDispatcher | undefined, local: LocalWorker | undefined;
let cleanupTimer: NodeJS.Timeout | undefined, serverClosing: Promise<void> | undefined;
let stopping = false, startup: Promise<void> = Promise.resolve();
const close = createShutdown({
  stopAdmission: () => {
    stopping = true; if (cleanupTimer) clearInterval(cleanupTimer); background.stopAdmission(); local?.stopAdmission(); dispatcher?.stopAdmission();
    if (server) { serverClosing = server.close(); void serverClosing.catch(() => undefined); }
  },
  drain: async () => {
    await startup;
    await drainTogether([() => serverClosing ?? server?.close() ?? Promise.resolve(), () => background.drain(), () => local?.close() ?? Promise.resolve()]);
  },
  closeResources: () => dispatcher?.close() ?? Promise.resolve(),
  closeStore: () => runtime?.store.close() ?? Promise.resolve()
});
installTerminationHandlers(close, message => { if (server) server.log.error(message); else console.error(message); });
startup = (async () => {
  runtime = await createRuntime(dependencies); if (stopping) return;
  Object.assign(dependencies, await configureDependencies(runtime.config, runtime.store)); if (stopping) return;
  if (runtime.config.authMode === 'oidc' && (!runtime.config.tlsCertFile || !runtime.config.tlsKeyFile)) throw new Error('Production control requires CONTROL_TLS_CERT_FILE and CONTROL_TLS_KEY_FILE for authenticated internal TLS.');
  if (runtime.config.authMode === 'oidc' && (!runtime.config.metricsToken || runtime.config.metricsToken.length < 32 || !runtime.config.reportToken || runtime.config.reportToken.length < 32)) throw new Error('Production control requires independent METRICS_TOKEN_FILE and REPORT_TOKEN_FILE secrets of at least 32 characters.');
  server = await createServer(runtime.config, runtime.store, dependencies); if (stopping) return;
  if (runtime.store.mode === 'development') {
    server.log.warn('Explicit development mode: loopback-only local owner, JSON persistence, single-process worker. No sandbox checks or deployments will be claimed unless a real broker is configured.');
    await runtime.engine.recover(); if (stopping) return; local = startLocalWorker(runtime.store, runtime.engine);
  } else {
    if (!runtime.config.rabbitUrl) throw new Error('Production requires RABBITMQ_URL or RABBITMQ_URL_FILE.');
    if (!runtime.config.rabbitUrl.startsWith('amqps:') || !process.env.RABBITMQ_CA_FILE) throw new Error('Production RabbitMQ requires verified TLS (amqps and RABBITMQ_CA_FILE).');
    dispatcher = new RabbitDispatcher(runtime.store, runtime.config.rabbitUrl); await dispatcher.start(); if (stopping) return;
  }
  await server.listen({ host: runtime.config.host, port: runtime.config.port }); if (stopping) return;
  const current = runtime, currentServer = server;
  const report = (error: unknown) => currentServer.log.error(error);
  void background.run(() => observePublishedReleases(current.store, dependencies))?.catch(report);
  cleanupTimer = setInterval(() => {
    void background.run(async () => {
      await current.engine.recover(); await observePublishedReleases(current.store, dependencies);
      await reconcileAccessOperations(current.store, dependencies); await reconcileConnectorOperations(current.store, dependencies);
    })?.catch(report);
  }, 60000); cleanupTimer.unref();
})();
await startup;
