import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import type { ServerResponse } from 'node:http';
import { createServer } from '../src/server.ts';
import { JsonStore, type Store } from '../src/store.ts';
import type { Config } from '../src/config.ts';
import { createShutdown, DrainTimeoutError } from '../src/shutdown.ts';

function deferred() { let resolve!: () => void, reject!: (error?: unknown) => void; const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const config: Config = { authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: 'unused', workspaceDir: 'unused', oidcClientId: 'unused', secretKey: Buffer.alloc(32, 41), requestLimitUsd: 1, monthlyLimitUsd: 5, adminDist: 'absent-sse-shutdown-dist' };
async function fixture() {
  const durable = new JsonStore(), jobId = randomUUID(), now = new Date().toISOString();
  await durable.transaction(state => { state.jobs[jobId] = { id: jobId, appId: randomUUID(), request: 'Synthetic progress stream', stage: 'queued', baseReleaseId: null, costUsd: 0, budgetUsd: 1, attempts: 0, createdAt: now, updatedAt: now }; });
  let reads = 0, allReads = 0, unsubscribes = 0, storeClosed = false, closing = false, raw: ServerResponse | undefined;
  let admissionGate: { pending: ReturnType<typeof deferred>; entered: ReturnType<typeof deferred> } | undefined;
  const listeners: (() => void)[] = [], gates: { pending: ReturnType<typeof deferred>; entered: ReturnType<typeof deferred> }[] = [];
  const writes: { closing: boolean; ended: boolean; chunk: string }[] = [];
  const store: Store = {
    mode: 'development', transaction: action => durable.transaction(action),
    read: async action => {
      assert.equal(storeClosed, false); allReads++; const result = await durable.read(action);
      if (result === undefined && admissionGate) {
        const gate = admissionGate; admissionGate = undefined; gate.entered.resolve(); await gate.pending.promise;
        assert.equal(storeClosed, false, 'Initial SSE admission read completed after storage closure');
      }
      if (result && typeof result === 'object' && 'authorized' in result && 'events' in result) {
        reads++; const gate = gates.shift(); if (gate) { gate.entered.resolve(); await gate.pending.promise; }
        assert.equal(storeClosed, false, 'SSE read completed after storage closure');
      }
      return result;
    },
    subscribe: (_jobId, listener) => { listeners.push(listener); return () => { unsubscribes++; }; },
    close: async () => { storeClosed = true; await durable.close(); }
  };
  const server = await createServer(config, store);
  server.addHook('onRequest', async (request, reply) => {
    if (!request.url.endsWith('/events')) return; raw = reply.raw;
    const write = raw.write;
    raw.write = function (this: ServerResponse, ...args: unknown[]) { writes.push({ closing, ended: this.writableEnded || this.destroyed, chunk: String(args[0]) }); return Reflect.apply(write, this, args); } as typeof write;
  });
  const session = await server.inject({ method: 'GET', url: '/api/v1/session' }), cookie = session.cookies[0]!;
  const open = () => server.inject({ method: 'GET', url: `/api/v1/jobs/${jobId}/events`, headers: { cookie: `${cookie.name}=${cookie.value}` } });
  const delay = () => { const gate = { pending: deferred(), entered: deferred() }; gates.push(gate); return gate; };
  const delayAdmission = () => { assert.equal(admissionGate, undefined); const gate = { pending: deferred(), entered: deferred() }; admissionGate = gate; return gate; };
  return { server, store, open, delay, delayAdmission, listeners, writes, raw: () => raw!, reads: () => reads, allReads: () => allReads, unsubscribes: () => unsubscribes, storeClosed: () => storeClosed, markClosing: () => { closing = true; } };
}

test('actual Fastify SSE close waits an admitted read, unsubscribes immediately and suppresses late wakeups and writes', { timeout: 3000 }, async () => {
  const f = await fixture(), gate = f.delay(), response = f.open(); await gate.entered.promise;
  assert.equal(f.reads(), 1); assert.equal(f.listeners.length, 1);
  f.markClosing(); const closing = f.server.close(); let complete = false; void closing.then(() => { complete = true; }); await turn();
  assert.equal(f.unsubscribes(), 1); assert.equal(f.raw().writableEnded, true); assert.equal(complete, false);
  f.listeners[0]!(); f.listeners[0]!(); await turn(); assert.equal(f.reads(), 1);
  gate.pending.resolve(); await closing; const result = await response; await f.store.close();
  assert.equal(result.statusCode, 200); assert.equal(f.storeClosed(), true); assert.deepEqual(f.writes, []); f.listeners[0]!(); await turn(); assert.equal(f.reads(), 1);
});

test('a client-disconnected SSE read remains tracked until it completes, although the stream was removed', { timeout: 3000 }, async () => {
  const f = await fixture(), gate = f.delay(), response = f.open(); await gate.entered.promise;
  const disconnected = response.then(() => assert.fail('Disconnected injection must report its reset'), error => { assert.equal((error as NodeJS.ErrnoException).code, 'LIGHT_ECONNRESET'); });
  f.raw().emit('close'); assert.equal(f.unsubscribes(), 1); assert.equal(f.raw().writableEnded, true);
  f.markClosing(); const closing = f.server.close(); let complete = false; void closing.then(() => { complete = true; }); await turn(); assert.equal(complete, false);
  f.listeners[0]!(); assert.equal(f.reads(), 1); gate.pending.resolve(); await closing; await disconnected; await f.store.close(); assert.deepEqual(f.writes, []); assert.equal(f.unsubscribes(), 1);
});

test('a queued subscriber read after initial replay is drained and cannot write a heartbeat after close', { timeout: 3000 }, async () => {
  const f = await fixture(), response = f.open(); await turn(); await turn(); assert.equal(f.reads(), 1); assert.equal(f.writes.length, 1); assert.equal(f.writes[0]!.chunk, ': heartbeat\n\n');
  const gate = f.delay(); f.listeners[0]!(); await gate.entered.promise; assert.equal(f.reads(), 2);
  f.markClosing(); const closing = f.server.close(); await turn(); f.listeners[0]!(); await turn(); assert.equal(f.reads(), 2); assert.equal(f.unsubscribes(), 1);
  gate.pending.resolve(); await closing; await response; await f.store.close(); assert.equal(f.writes.length, 1); assert.equal(f.writes.some(write => write.closing || write.ended), false);
});

test('a failed admitted SSE read settles silently after shutdown without writing unavailable diagnostics', { timeout: 3000 }, async () => {
  const f = await fixture(), gate = f.delay(), response = f.open(); await gate.entered.promise;
  f.markClosing(); const closing = f.server.close(); await turn(); gate.pending.reject(new Error('synthetic database read failure')); await closing; await response; await f.store.close(); assert.deepEqual(f.writes, []);
});

test('a hanging actual SSE read is governed by the outer shutdown deadline and late settlement never closes storage', { timeout: 3000 }, async () => {
  const f = await fixture(), gate = f.delay(), response = f.open(); await gate.entered.promise;
  let httpClosing: Promise<void> | undefined, resourcesClosed = false;
  const close = createShutdown({ stopAdmission: () => { f.markClosing(); httpClosing = f.server.close(); }, drain: () => httpClosing!, closeResources: async () => { resourcesClosed = true; }, closeStore: () => f.store.close() }, 20);
  await assert.rejects(close(), DrainTimeoutError); assert.equal(f.storeClosed(), false); assert.equal(resourcesClosed, false); assert.equal(f.unsubscribes(), 1);
  gate.pending.resolve(); await httpClosing; await response; await turn(); assert.equal(f.storeClosed(), false); assert.equal(resourcesClosed, false); assert.deepEqual(f.writes, []); await f.store.close();
});

test('a disconnected initial SSE admission read remains drained before any stream or subscription exists', { timeout: 3000 }, async () => {
  const f = await fixture(), gate = f.delayAdmission(), response = f.open(); await gate.entered.promise;
  const disconnected = response.then(() => assert.fail('Disconnected admission must report its reset'), error => { assert.equal((error as NodeJS.ErrnoException).code, 'LIGHT_ECONNRESET'); });
  f.raw().destroy(); assert.equal(f.listeners.length, 0); assert.equal(f.reads(), 0);
  f.markClosing(); const closing = f.server.close(); let complete = false; void closing.then(() => { complete = true; }); await turn(); assert.equal(complete, false);
  gate.pending.resolve(); await closing; await disconnected; assert.equal(f.listeners.length, 0); assert.equal(f.reads(), 0); assert.deepEqual(f.writes, []); await f.store.close();
});

test('shutdown during the initial admission read rejects stream creation and subsequent injections start no reads', { timeout: 3000 }, async () => {
  const f = await fixture(), gate = f.delayAdmission(), response = f.open(); await gate.entered.promise;
  f.markClosing(); const closing = f.server.close(); await turn(); gate.pending.resolve(); const result = await response; await closing;
  assert.equal(result.statusCode, 503); assert.equal(result.headers['content-type']?.startsWith('application/json'), true); assert.equal(f.listeners.length, 0); assert.equal(f.reads(), 0);
  const before = f.allReads(); await assert.rejects(f.open(), /closed|closing|reopen/i); assert.equal(f.allReads(), before); await f.store.close();
});
