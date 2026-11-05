import { createRuntime } from './runtime.ts';
import { configureDependencies } from './dependencies.ts';
import { RabbitDispatcher } from './messaging.ts';
import type { EngineDependencies } from './engine.ts';
import { createShutdown, installTerminationHandlers, WorkDrain } from './shutdown.ts';

const dependencies: EngineDependencies = {}, background = new WorkDrain();
let runtime: Awaited<ReturnType<typeof createRuntime>> | undefined, dispatcher: RabbitDispatcher | undefined;
let recoveryTimer: NodeJS.Timeout | undefined, stopping = false, startup: Promise<void> = Promise.resolve();
const close = createShutdown({
  stopAdmission: () => { stopping = true; if (recoveryTimer) clearInterval(recoveryTimer); background.stopAdmission(); dispatcher?.stopAdmission(); },
  drain: async () => { await startup; await background.drain(); },
  closeResources: () => dispatcher?.close() ?? Promise.resolve(),
  closeStore: () => runtime?.store.close() ?? Promise.resolve()
});
installTerminationHandlers(close, message => console.error(message));
startup = (async () => {
  runtime = await createRuntime(dependencies); if (stopping) return;
  Object.assign(dependencies, await configureDependencies(runtime.config, runtime.store)); if (stopping) return;
  if (runtime.store.mode !== 'mysql') throw new Error('A separate worker requires MySQL. The local JSON development worker runs inside the API process.');
  if (!runtime.config.rabbitUrl) throw new Error('RABBITMQ_URL or RABBITMQ_URL_FILE is required.');
  if (runtime.config.authMode === 'oidc' && (!runtime.config.rabbitUrl.startsWith('amqps:') || !process.env.RABBITMQ_CA_FILE)) throw new Error('Production RabbitMQ requires verified TLS.');
  await runtime.engine.recover(); if (stopping) return;
  dispatcher = new RabbitDispatcher(runtime.store, runtime.config.rabbitUrl); await dispatcher.start(runtime.engine); if (stopping) return;
  const current = runtime;
  recoveryTimer = setInterval(() => void background.run(() => current.engine.recover())?.catch(() => undefined), 60000); recoveryTimer.unref();
})();
await startup;
