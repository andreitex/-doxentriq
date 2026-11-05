import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import type { ChannelModel, ConfirmChannel, ConsumeMessage } from 'amqplib';
import { JsonStore, type Store } from '../src/store.ts';
import { RabbitDispatcher, startLocalWorker, type DispatcherOptions } from '../src/messaging.ts';
import { createShutdown, DrainDeadline, DrainTimeoutError, drainTogether, installTerminationHandlers, WorkDrain } from '../src/shutdown.ts';

function deferred<T = void>() { let resolve!: (value: T | PromiseLike<T>) => void, reject!: (reason?: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const message = (jobId: string = randomUUID()) => ({ content: Buffer.from(JSON.stringify({ jobId })), fields: {}, properties: {} }) as ConsumeMessage;
class Channel extends EventEmitter {
  callback?: (message: ConsumeMessage | null) => void;
  acked: ConsumeMessage[] = []; nacked: { message: ConsumeMessage; requeue: boolean }[] = []; cancelled: string[] = [];
  sends: { id: string; confirm: (error?: Error) => void }[] = [];
  consumeGate?: ReturnType<typeof deferred<{ consumerTag: string }>>;
  assertGate?: ReturnType<typeof deferred<{}>>;
  automaticConfirms = true;
  async assertQueue() { return this.assertGate ? this.assertGate.promise : {}; }
  async prefetch() { return {}; }
  async consume(_queue: string, callback: (message: ConsumeMessage | null) => void) { this.callback = callback; return this.consumeGate ? this.consumeGate.promise : { consumerTag: 'test-consumer' }; }
  async cancel(tag: string) { this.cancelled.push(tag); return {}; }
  ack(item: ConsumeMessage) { this.acked.push(item); }
  nack(item: ConsumeMessage, _multiple: boolean, requeue: boolean) { this.nacked.push({ message: item, requeue }); }
  sendToQueue(_queue: string, _body: Buffer, options: { messageId: string }, confirm: (error?: Error) => void) { this.sends.push({ id: options.messageId, confirm }); if (this.automaticConfirms) queueMicrotask(() => confirm()); return true; }
}
class Connection extends EventEmitter {
  closes = 0; channel = new Channel();
  channelGate?: ReturnType<typeof deferred<ConfirmChannel>>;
  beforeClose?: () => void;
  async createConfirmChannel() { return this.channelGate ? this.channelGate.promise : this.channel as unknown as ConfirmChannel; }
  async close() { this.beforeClose?.(); this.closes++; this.emit('close'); }
}
function fixture(connection = new Connection(), extra: DispatcherOptions = {}) {
  const store = new JsonStore(), events: string[] = []; let closed = false;
  const guarded: Store = {
    mode: 'development',
    read: async action => { assert.equal(closed, false, 'read after store close'); return store.read(action); },
    transaction: async action => { assert.equal(closed, false, 'transaction after store close'); const result = await store.transaction(action); events.push('transaction'); return result; },
    close: async () => { closed = true; events.push('store-close'); await store.close(); }
  };
  const dispatcher = new RabbitDispatcher(guarded, 'amqp://synthetic.invalid', { connect: async () => connection as unknown as ChannelModel, readTlsFile: async () => Buffer.from('synthetic TLS'), flushMs: 60000, ...extra });
  return { connection, store, guarded, dispatcher, events, closed: () => closed };
}
async function enqueue(store: Store, jobId = randomUUID()) { const id = randomUUID(); await store.transaction(state => { state.outbox[id] = { id, jobId, createdAt: new Date().toISOString(), publishedAt: null }; }); return id; }

test('shutdown synchronously closes admission and drains HTTP, background, resources and storage exactly once', async () => {
  const http = deferred(), background = deferred(), order: string[] = []; let accepting = true;
  const close = createShutdown({ stopAdmission: () => { accepting = false; order.push('stop'); }, drain: () => drainTogether([() => http.promise, () => background.promise]), closeResources: async () => { order.push('resources'); }, closeStore: async () => { order.push('store'); } });
  const first = close(); assert.equal(accepting, false); assert.equal(close(), first); await turn();
  http.resolve(); await turn(); assert.deepEqual(order, ['stop']); background.resolve(); await first; assert.deepEqual(order, ['stop', 'resources', 'store']);
});

test('a whole shutdown deadline never closes storage after a late provider-like callback finishes', async () => {
  const provider = deferred(); const record = { status: 'running', reservation: 'held' }; let resources = 0, stores = 0;
  const close = createShutdown({ stopAdmission: () => undefined, drain: () => provider.promise, closeResources: async () => { resources++; }, closeStore: async () => { stores++; } }, 20);
  await assert.rejects(close(), DrainTimeoutError); assert.deepEqual(record, { status: 'running', reservation: 'held' }); assert.equal(resources, 0); assert.equal(stores, 0);
  provider.resolve(); await turn(); assert.equal(resources, 0); assert.equal(stores, 0);
});

test('all shutdown phases share one budget rather than granting each phase another timeout', async () => {
  const deadline = new DrainDeadline(30), first = deferred(); const timer = setTimeout(() => first.resolve(), 20);
  await deadline.wait(() => first.promise); await assert.rejects(deadline.wait(() => new Promise<void>(() => undefined)), DrainTimeoutError); clearTimeout(timer);
  assert.throws(() => new DrainDeadline(50001)); assert.throws(() => new DrainDeadline(0));
});

test('background recovery and observation admitted before stopping drain; subsequent timer callbacks cannot run', async () => {
  const work = new WorkDrain(), recovery = deferred(), observation = deferred(); let runs = 0;
  const a = work.run(async () => { runs++; await recovery.promise; })!, b = work.run(async () => { runs++; await observation.promise; })!;
  work.stopAdmission(); assert.equal(work.run(async () => { runs++; }), undefined); const draining = work.drain(); let ended = false; void draining.then(() => { ended = true; });
  await turn(); recovery.resolve(); await a; await turn(); assert.equal(ended, false); observation.resolve(); await b; await draining; assert.equal(runs, 2);
});

test('an admitted background failure prevents resource and storage closure while other admitted work is still awaited', async () => {
  const work = new WorkDrain(), hold = deferred(), fail = deferred(); const long = work.run(() => hold.promise)!, bad = work.run(() => fail.promise)!; void bad.catch(() => undefined);
  let resources = 0, stores = 0;
  const close = createShutdown({ stopAdmission: () => work.stopAdmission(), drain: () => work.drain(), closeResources: async () => { resources++; }, closeStore: async () => { stores++; } });
  const closing = close(); let rejected = false; void closing.catch(() => { rejected = true; }); fail.reject(new Error('synthetic reconciliation failure')); await turn(); assert.equal(rejected, false);
  hold.resolve(); await long; await assert.rejects(closing, AggregateError); assert.equal(resources, 0); assert.equal(stores, 0);
});

test('repeated signals exit once with success only after draining, and errors or synchronous admission failure exit nonzero', async () => {
  for (const mode of ['success', 'failure', 'admission-error']) {
    const target = new EventEmitter(), exitCodes: number[] = [], reports: string[] = [], pending = deferred(); let closes = 0;
    const close = createShutdown({ stopAdmission: () => { closes++; if (mode === 'admission-error') throw new Error('synthetic stop failure'); }, drain: () => pending.promise, closeResources: async () => undefined, closeStore: async () => undefined });
    installTerminationHandlers(close, text => reports.push(text), Object.assign(target, { exit: (code: number) => { exitCodes.push(code); } }) as unknown as Pick<NodeJS.Process, 'on' | 'exit'>);
    target.emit('SIGTERM'); target.emit('SIGINT'); await turn();
    if (mode === 'success') { assert.deepEqual(exitCodes, []); pending.resolve(); } else if (mode === 'failure') pending.reject(new Error('synthetic shutdown failure'));
    await turn(); assert.equal(closes, 1); assert.deepEqual(exitCodes, [mode === 'success' ? 0 : 1]); assert.equal(reports.length, mode === 'success' ? 0 : 1);
    if (reports[0]) assert.match(reports[0], /not confirmed cancelled/);
  }
});

test('Rabbit shutdown rejects new deliveries while admitted job commits and its original acknowledgement finish before connection/store close', async () => {
  const f = fixture(), hold = deferred(); let active = false, runs = 0;
  await f.dispatcher.start({ run: async () => { active = true; runs++; await hold.promise; await f.guarded.transaction(state => { state.settings.drain = { monthlyLimitUsd: 9 }; }); active = false; } });
  const admitted = message(), rejected = message(); f.connection.channel.callback!(admitted); await turn();
  f.connection.beforeClose = () => { assert.equal(active, false); assert.deepEqual(f.connection.channel.acked, [admitted]); f.events.push('connection-close'); };
  const close = createShutdown({ stopAdmission: () => f.dispatcher.stopAdmission(), drain: async () => undefined, closeResources: () => f.dispatcher.close(), closeStore: () => f.guarded.close() });
  const closing = close(); f.connection.channel.callback!(rejected); await turn(); assert.equal(f.closed(), false); assert.equal(f.connection.closes, 0); assert.deepEqual(f.connection.channel.cancelled, ['test-consumer']);
  hold.resolve(); await closing; assert.equal(runs, 1); assert.deepEqual(f.connection.channel.nacked, [{ message: rejected, requeue: true }]); assert.ok(f.events.indexOf('connection-close') < f.events.indexOf('store-close'));
});

test('an admitted publisher confirmation and its outbox transaction finish before shutdown closes the connection', async () => {
  const f = fixture(); await f.dispatcher.start(); const id = await enqueue(f.guarded); f.connection.channel.automaticConfirms = false;
  const flushing = f.dispatcher.flush(); await turn(); const closing = f.dispatcher.close(); assert.equal(f.dispatcher.close(), closing); await turn(); assert.equal(f.connection.closes, 0);
  assert.equal(await f.store.read(state => state.outbox[id]!.publishedAt), null); f.connection.channel.sends[0]!.confirm(); await flushing; await closing;
  assert.notEqual(await f.store.read(state => state.outbox[id]!.publishedAt), null); assert.equal(f.connection.closes, 1);
});

test('shutdown publishes outbox entries created by the drained job and more than one hundred pending entries', async () => {
  const f = fixture(), hold = deferred(); let next: string | undefined;
  await f.dispatcher.start({ run: async () => { await hold.promise; next = await enqueue(f.guarded); } }); f.connection.channel.callback!(message()); await turn();
  for (let index = 0; index < 102; index++) await enqueue(f.guarded);
  const closing = f.dispatcher.close(); hold.resolve(); await closing;
  assert.equal(f.connection.channel.sends.length, 103); assert.ok(next); assert.equal(await f.store.read(state => Object.values(state.outbox).filter(item => !item.publishedAt).length), 0);
});

test('a delivery admitted on a disconnected channel is never acknowledged or rejected on its replacement', async () => {
  const first = new Connection(), second = new Connection(), hold = deferred(); let connects = 0, runs = 0;
  const f = fixture(first, { connect: async () => (++connects === 1 ? first : second) as unknown as ChannelModel, reconnectMs: 1 });
  await f.dispatcher.start({ run: async () => { runs++; await hold.promise; } }); first.channel.callback!(message()); await turn(); first.emit('close');
  for (let index = 0; index < 20 && !second.channel.callback; index++) await new Promise(resolve => setTimeout(resolve, 2));
  assert.ok(second.channel.callback); hold.resolve(); await turn(); await f.dispatcher.close();
  assert.equal(runs, 1); assert.deepEqual(first.channel.acked, []); assert.deepEqual(first.channel.nacked, []); assert.deepEqual(second.channel.acked, []); assert.deepEqual(second.channel.nacked, []); assert.equal(connects, 2);
});

test('shutdown during pending connect closes the late connection without creating a consumer or accessing storage', async () => {
  const gate = deferred<ChannelModel>(), late = new Connection(); let connects = 0;
  const f = fixture(late, { connect: async () => { connects++; return gate.promise; } }); const starting = f.dispatcher.start({ run: async () => assert.fail('late delivery') }); await turn();
  const closing = f.dispatcher.close(); await turn(); gate.resolve(late as unknown as ChannelModel); await starting; await closing; await f.dispatcher.start();
  assert.equal(connects, 1); assert.equal(late.closes, 1); assert.equal(late.channel.callback, undefined); assert.deepEqual(f.events, []);
});

test('shutdown during consume registration rejects delivery and cancels the tag returned after admission closes', async () => {
  const f = fixture(), registration = deferred<{ consumerTag: string }>(); f.connection.channel.consumeGate = registration; let runs = 0;
  const starting = f.dispatcher.start({ run: async () => { runs++; } }); await turn(); assert.ok(f.connection.channel.callback);
  const closing = f.dispatcher.close(), late = message(); f.connection.channel.callback!(late); registration.resolve({ consumerTag: 'late-consumer' }); await starting; await closing;
  assert.equal(runs, 0); assert.deepEqual(f.connection.channel.cancelled, ['late-consumer']); assert.deepEqual(f.connection.channel.nacked, [{ message: late, requeue: true }]); assert.equal(f.connection.closes, 1);
});

test('pending reconnect is cancelled by shutdown and stale connection events cannot restart a closed dispatcher', async () => {
  let connects = 0; const f = fixture(new Connection(), { connect: async () => { connects++; return f.connection as unknown as ChannelModel; }, reconnectMs: 15 });
  await f.dispatcher.start(); f.connection.emit('close'); await f.dispatcher.close(); await new Promise(resolve => setTimeout(resolve, 25)); f.connection.emit('close'); await f.dispatcher.start(); assert.equal(connects, 1);
});

test('reconnect timer and manual publisher cannot publish or advertise a replacement before its queue is asserted', async () => {
  const first = new Connection(), second = new Connection(), assertion = deferred<{}>(); second.channel.assertGate = assertion; let connects = 0;
  const f = fixture(first, { connect: async () => (++connects === 1 ? first : second) as unknown as ChannelModel, reconnectMs: 1, flushMs: 1 });
  await f.dispatcher.start(); first.emit('close');
  for (let index = 0; index < 20 && connects < 2; index++) await new Promise(resolve => setTimeout(resolve, 2));
  const id = await enqueue(f.guarded); await f.dispatcher.flush(); await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(f.dispatcher.available(), false); assert.deepEqual(second.channel.sends, []); assert.equal(await f.store.read(state => state.outbox[id]!.publishedAt), null);
  assertion.resolve({});
  for (let index = 0; index < 20 && !second.channel.sends.length; index++) await new Promise(resolve => setTimeout(resolve, 2));
  assert.equal(f.dispatcher.available(), true); assert.equal(second.channel.sends.length, 1); assert.notEqual(await f.store.read(state => state.outbox[id]!.publishedAt), null); await f.dispatcher.close();
});

test('diagnostic logging failure still terminates once with a nonzero exit status', async () => {
  const target = new EventEmitter(), exitCodes: number[] = [];
  installTerminationHandlers(async () => { throw new Error('synthetic drain failure'); }, () => { throw new Error('synthetic logger failure'); }, Object.assign(target, { exit: (code: number) => { exitCodes.push(code); } }) as unknown as Pick<NodeJS.Process, 'on' | 'exit'>);
  target.emit('SIGTERM'); target.emit('SIGINT'); await turn(); assert.deepEqual(exitCodes, [1]);
});

test('unexpected admitted job failure requeues on its original channel and fails shutdown without closing storage', async () => {
  const f = fixture(), hold = deferred(); await f.dispatcher.start({ run: () => hold.promise }); const item = message(); f.connection.channel.callback!(item); await turn();
  const close = createShutdown({ stopAdmission: () => f.dispatcher.stopAdmission(), drain: async () => undefined, closeResources: () => f.dispatcher.close(), closeStore: () => f.guarded.close() });
  const closing = close(); hold.reject(new Error('synthetic run failure')); await assert.rejects(closing, AggregateError); assert.equal(f.closed(), false); assert.equal(f.connection.closes, 0); assert.deepEqual(f.connection.channel.nacked, [{ message: item, requeue: true }]);
});

test('a failed admitted publisher remains unpublished and its error survives before delayed dispatcher close', async () => {
  const f = fixture(); await f.dispatcher.start(); const id = await enqueue(f.guarded); f.connection.channel.automaticConfirms = false;
  const flushing = f.dispatcher.flush(); await turn(); f.dispatcher.stopAdmission(); f.connection.channel.sends[0]!.confirm(new Error('synthetic negative confirm')); await assert.rejects(flushing); await turn();
  await assert.rejects(f.dispatcher.close(), AggregateError); assert.equal(await f.store.read(state => state.outbox[id]!.publishedAt), null); assert.equal(f.connection.closes, 0);
});

test('the development worker drains its active job, is idempotent and never admits another outbox entry after stop', async () => {
  const store = new JsonStore(), first = await enqueue(store), hold = deferred(); let runs = 0, committed = false;
  const local = startLocalWorker(store, { run: async () => { runs++; await hold.promise; await store.transaction(state => { state.settings.drain = { monthlyLimitUsd: 8 }; }); committed = true; } }, 60000);
  const tick = local.tick(); await turn(); const next = await enqueue(store), closing = local.close(); assert.equal(local.close(), closing); await turn(); assert.equal(committed, false);
  hold.resolve(); await tick; await closing; await local.tick(); assert.equal(runs, 1); assert.equal(committed, true); assert.notEqual(await store.read(state => state.outbox[first]!.publishedAt), null); assert.equal(await store.read(state => state.outbox[next]!.publishedAt), null);
});

test('malformed Rabbit deliveries are rejected without running jobs or interfering with draining valid work', async () => {
  const f = fixture(); let runs = 0; await f.dispatcher.start({ run: async () => { runs++; } }); const malformed = { ...message(), content: Buffer.from('{') }, invalid = message('invalid');
  f.connection.channel.callback!(malformed); f.connection.channel.callback!(invalid); await turn(); await f.dispatcher.close(); assert.equal(runs, 0); assert.deepEqual(f.connection.channel.nacked, [{ message: malformed, requeue: false }, { message: invalid, requeue: false }]);
});
