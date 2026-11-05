import test from 'node:test';
import assert from 'node:assert/strict';
import http, { type ClientRequest } from 'node:http';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { HttpDrain } from '../src/http-drain.ts';
import { createShutdown, DrainTimeoutError } from '../src/shutdown.ts';

function deferred() { let resolve!: () => void; const promise = new Promise<void>(yes => { resolve = yes; }); return { promise, resolve }; }
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
async function bounded<T>(promise: PromiseLike<T>): Promise<T> {
  let timer!: NodeJS.Timeout;
  try { return await Promise.race([Promise.resolve(promise), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('Local fixture did not reach its boundary')), 1500); })]); }
  finally { clearTimeout(timer); }
}
function fixture() {
  const server = Fastify({ logger: false }), drain = new HttpDrain(); drain.install(server);
  server.addHook('preClose', async () => { drain.stopAdmission(); await drain.drain(); });
  return { server, drain };
}
async function loopback(server: FastifyInstance, path: string) {
  await server.listen({ host: '127.0.0.1', port: 0 });
  const address = server.server.address(); assert(address && typeof address !== 'string'); assert.equal(address.address, '127.0.0.1');
  let client!: ClientRequest;
  const response = new Promise<{ status: number; body: string }>((resolve, reject) => {
    client = http.request({ host: '127.0.0.1', port: address.port, path, agent: false }, raw => {
      let body = ''; raw.setEncoding('utf8'); raw.on('data', chunk => { body += chunk; });
      raw.on('end', () => resolve({ status: raw.statusCode!, body })); raw.on('error', reject);
    }); client.on('error', reject); client.setTimeout(1800, () => client.destroy(new Error('Local request timed out'))); client.end();
  });
  // Every deliberate disconnect has an attached rejection observer before it occurs.
  void response.catch(() => {}); return { client, response };
}

test('actual loopback close waits an aborted handler promise before storage can close', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(), entered = deferred(), disconnected = deferred(); let client: ClientRequest | undefined, closing: Promise<void> | undefined, storeClosed = false, effects = 0;
  f.server.get('/work', async (_request, reply) => { reply.raw.once('close', disconnected.resolve); entered.resolve(); await gate.promise; assert.equal(storeClosed, false); effects++; return { done: true }; });
  try {
    const request = await loopback(f.server, '/work'); client = request.client; await bounded(entered.promise); client.destroy(); await bounded(disconnected.promise);
    const close = createShutdown({ stopAdmission: () => { closing = f.server.close(); }, drain: () => closing!, closeResources: async () => {}, closeStore: async () => { storeClosed = true; } });
    const shutdown = close(); let complete = false; void shutdown.then(() => { complete = true; }); await turn();
    assert.equal(complete, false); assert.equal(storeClosed, false); assert.equal(effects, 0);
    gate.resolve(); await bounded(shutdown); assert.equal(effects, 1); assert.equal(storeClosed, true);
  } finally { gate.resolve(); client?.destroy(); await bounded(closing ?? f.server.close()); }
});

test('actual loopback aborted authentication stays drained and cannot admit a later handler', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(), entered = deferred(), disconnected = deferred(); let client: ClientRequest | undefined, closing: Promise<void> | undefined, handlerCalls = 0, authFinished = false;
  f.server.addHook('onRequest', async (_request, reply) => { reply.raw.once('close', disconnected.resolve); entered.resolve(); await gate.promise; authFinished = true; });
  f.server.get('/private', async () => { handlerCalls++; return { private: true }; });
  try {
    const request = await loopback(f.server, '/private'); client = request.client; await bounded(entered.promise); client.destroy(); await bounded(disconnected.promise);
    closing = f.server.close(); let complete = false; void closing.then(() => { complete = true; }); await turn(); assert.equal(complete, false);
    gate.resolve(); await bounded(closing); await turn(); assert.equal(authFinished, true); assert.equal(handlerCalls, 0);
  } finally { gate.resolve(); client?.destroy(); await bounded(closing ?? f.server.close()); }
});

test('actual loopback early reply does not release work still awaited by the handler', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(); let client: ClientRequest | undefined, closing: Promise<void> | undefined, workFinished = false;
  f.server.get('/early', async (_request, reply) => { reply.send({ accepted: true }); await gate.promise; workFinished = true; });
  try {
    const request = await loopback(f.server, '/early'); client = request.client; assert.equal((await bounded(request.response)).status, 200);
    closing = f.server.close(); let complete = false; void closing.then(() => { complete = true; }); await turn(); assert.equal(complete, false); assert.equal(workFinished, false);
    gate.resolve(); await bounded(closing); assert.equal(workFinished, true);
  } finally { gate.resolve(); client?.destroy(); await bounded(closing ?? f.server.close()); }
});

test('actual loopback encapsulated 404 authentication drains after disconnect and refuses its fallback handler', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(), entered = deferred(), disconnected = deferred(); let client: ClientRequest | undefined, closing: Promise<void> | undefined, fallbackCalls = 0;
  f.server.register(async child => {
    assert.equal(Object.hasOwn(child, 'setNotFoundHandler'), true); assert.equal(Object.hasOwn(child, 'addHook'), true);
    child.addHook('onRequest', async function (_request, reply) { assert.equal(this, child); reply.raw.once('close', disconnected.resolve); entered.resolve(); await gate.promise; });
    child.setNotFoundHandler(async function () { assert.equal(this, child); fallbackCalls++; return { absent: true }; });
  }, { prefix: '/protected' });
  try {
    const request = await loopback(f.server, '/protected/missing'); client = request.client; await bounded(entered.promise); client.destroy(); await bounded(disconnected.promise);
    closing = f.server.close(); let complete = false; void closing.then(() => { complete = true; }); await turn(); assert.equal(complete, false);
    gate.resolve(); await bounded(closing); await turn(); assert.equal(fallbackCalls, 0);
  } finally { gate.resolve(); client?.destroy(); await bounded(closing ?? f.server.close()); }
});

test('an open request delayed in a hook receives 503 and starts no later business phase', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(), entered = deferred(); let client: ClientRequest | undefined, closing: Promise<void> | undefined, laterCalls = 0;
  f.server.addHook('onRequest', async () => { entered.resolve(); await gate.promise; });
  f.server.addHook('preHandler', async () => { laterCalls++; }); f.server.get('/pending', async () => { laterCalls++; return {}; });
  try {
    const request = await loopback(f.server, '/pending'); client = request.client; await bounded(entered.promise); closing = f.server.close(); await turn(); gate.resolve();
    const result = await bounded(request.response); await bounded(closing); assert.equal(result.status, 503); assert.equal(laterCalls, 0); assert.equal(JSON.parse(result.body).error.code, 503);
  } finally { gate.resolve(); client?.destroy(); await bounded(closing ?? f.server.close()); }
});

test('default-parameter callback remains pending after an early reply until actual done', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(), entered = deferred(); let closing: Promise<void> | undefined, effects = 0;
  f.server.addHook('onRequest', function (_request, reply, done = (() => {}) as (error?: Error) => void) { reply.send({ early: true }); entered.resolve(); void gate.promise.then(() => { effects++; done(); }); });
  f.server.get('/default', async () => assert.fail('Early reply cannot enter the handler'));
  try {
    const response = f.server.inject('/default'); await bounded(entered.promise); assert.equal((await response).statusCode, 200);
    closing = f.server.close(); let complete = false; void closing.then(() => { complete = true; }); await turn(); assert.equal(complete, false);
    gate.resolve(); await bounded(closing); assert.equal(effects, 1);
  } finally { gate.resolve(); await bounded(closing ?? f.server.close()); }
});

test('rest-parameter callback and callback handover preserve context and cannot run a closed next phase', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(), entered = deferred(); let closing: Promise<void> | undefined, handlerCalls = 0;
  f.server.addHook('preHandler', function (this: FastifyInstance, ...args: [FastifyRequest, FastifyReply, (error?: Error) => void]) { assert.equal(this, f.server); assert.equal(args[0].url, '/rest'); entered.resolve(); void gate.promise.then(() => args[2]()); });
  f.server.get('/rest', function () { handlerCalls++; return {}; });
  try {
    const response = f.server.inject('/rest'); await bounded(entered.promise); closing = f.server.close(); await turn(); gate.resolve(); assert.equal((await response).statusCode, 503); await bounded(closing); assert.equal(handlerCalls, 0);
  } finally { gate.resolve(); await bounded(closing ?? f.server.close()); }
});

test('global, encapsulated, per-route arrays and late onRoute replacements preserve callback and promise semantics', { timeout: 3000 }, async () => {
  const f = fixture(), events: string[] = []; let scoped!: FastifyInstance;
  f.server.addHook('onRequest', function (request, _reply, done) { assert.equal(this, scoped); events.push(`global:${request.url}`); done(); });
  f.server.register(async child => {
    scoped = child;
    child.addHook('preValidation', async function () { assert.equal(this, child); events.push('scoped'); });
    child.addHook('onRoute', options => { if (options.method === 'GET') { options.handler = function (this: FastifyInstance) { assert.equal(this, child); events.push('replacement'); return { ok: true }; }; options.preHandler = [function (this: FastifyInstance, _request, _reply, done) { assert.equal(this, child); events.push('late-route'); done(); }]; } });
    child.get('/scoped', { preSerialization: [function (this: FastifyInstance, _request, _reply, payload, done) { assert.equal(this, child); events.push('serialize'); done(null, { ...payload as object, transformed: true }); }], onSend: async function (_request, _reply, payload) { events.push('send'); return payload; } }, async () => assert.fail('onRoute must replace the original handler'));
  });
  try { const result = await f.server.inject('/scoped'); assert.equal(result.statusCode, 200); assert.deepEqual(result.json(), { ok: true, transformed: true }); assert.deepEqual(events, ['global:/scoped', 'scoped', 'late-route', 'replacement', 'serialize', 'send']); }
  finally { await bounded(f.server.close()); }
});

test('encapsulated explicit not-found handler and option hooks retain promised work after response delivery', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(), entered = deferred(); let closing: Promise<void> | undefined, hookCalls = 0, complete = false;
  f.server.register(async child => {
    child.setNotFoundHandler({ preValidation: function (_request, _reply, done) { assert.equal(this, child); hookCalls++; done(); }, preHandler: async function () { assert.equal(this, child); hookCalls++; } }, async function (_request, reply) { assert.equal(this, child); reply.code(404).send({ absent: true }); entered.resolve(); await gate.promise; complete = true; });
  }, { prefix: '/child' });
  try {
    const response = f.server.inject('/child/missing'); await bounded(entered.promise); assert.equal((await response).statusCode, 404); assert.equal(hookCalls, 2);
    closing = f.server.close(); let closed = false; void closing.then(() => { closed = true; }); await turn(); assert.equal(closed, false); gate.resolve(); await bounded(closing); assert.equal(complete, true);
  } finally { gate.resolve(); await bounded(closing ?? f.server.close()); }
});

test('promise rejection, synchronous throw and callback errors keep ordinary Fastify error behavior', { timeout: 3000 }, async () => {
  const f = fixture();
  f.server.get('/promise', async () => { throw new Error('promise failed'); }); f.server.get('/sync', () => { throw new Error('sync failed'); });
  f.server.get('/callback', { preHandler: (_request, _reply, done) => done(new Error('callback failed')) }, async () => assert.fail('Failed hook cannot admit its handler'));
  try { for (const [path, message] of [['promise', 'promise failed'], ['sync', 'sync failed'], ['callback', 'callback failed']]) { const result = await f.server.inject(`/${path}`); assert.equal(result.statusCode, 500); assert.equal(result.json().message, message); } }
  finally { await bounded(f.server.close()); }
});

test('wrappers preserve Fastify validation for invalid hooks and mixed callback/async signatures', { timeout: 3000 }, async () => {
  const code = (expected: string) => (error: unknown) => (error as { code: string }).code === expected;
  const f = fixture();
  try {
    assert.throws(() => f.server.addHook('onRequest', (async function (_request: unknown, _reply: unknown, _done: unknown) {}) as never), code('FST_ERR_HOOK_INVALID_ASYNC_HANDLER'));
    assert.throws(() => f.server.addHook('onRequest', null as never), code('FST_ERR_HOOK_INVALID_HANDLER'));
    assert.throws(() => f.server.addHook('onRequestAbort', (async function () {}) as never), code('FST_ERR_HOOK_INVALID_ASYNC_HANDLER'));
    assert.throws(() => f.server.get('/invalid-scalar', { preHandler: (async function (_request: unknown, _reply: unknown, _done: unknown) {}) as never }, async () => ({})), code('FST_ERR_HOOK_INVALID_ASYNC_HANDLER'));
    assert.throws(() => f.server.get('/invalid-array', { onSend: [(async function (_request: unknown, _reply: unknown, _payload: unknown, _done: unknown) {}) as never] }, async () => ({})), code('FST_ERR_HOOK_INVALID_ASYNC_HANDLER'));
    assert.throws(() => f.server.setNotFoundHandler({ preHandler: (async function (_request: unknown, _reply: unknown, _done: unknown) {}) as never }, async () => ({})), code('FST_ERR_HOOK_INVALID_ASYNC_HANDLER'));
    assert.throws(() => f.server.get('/invalid-type', { preHandler: 7 as never }, async () => ({})), code('FST_ERR_HOOK_INVALID_HANDLER'));
  } finally { await bounded(f.server.close()); }
});

test('unsupported hook names and non-function hooks retain Fastify deferred startup validation', { timeout: 3000 }, async () => {
  for (const [name, fn, code] of [['toString', () => {}, 'FST_ERR_HOOK_NOT_SUPPORTED'], ['onRequest', 7, 'FST_ERR_HOOK_INVALID_HANDLER']] as const) {
    const f = fixture(); f.server.addHook(name as never, fn as never);
    try { await assert.rejects(Promise.resolve(f.server.ready()), (error: unknown) => (error as { code: string }).code === code); }
    finally { await bounded(f.server.close()); }
  }
});

test('callback payload hooks and plain functions returning promises preserve actual pipeline arguments', { timeout: 3000 }, async () => {
  const f = fixture(), events: string[] = [];
  f.server.addHook('preParsing', function (request, reply, payload, done) { assert.equal(this, f.server); assert.equal(request.url, '/payload'); assert.equal(reply.statusCode, 200); assert.equal(typeof payload.pipe, 'function'); events.push('parse'); done(null, payload); });
  f.server.post('/payload', { preHandler: function (_request, _reply) { events.push('promise-hook'); return Promise.resolve(); }, preSerialization: function (_request, _reply, payload, done) { events.push('serialize'); done(null, { ...payload as object, added: true }); }, onSend: function (_request, _reply, payload, done) { events.push('send'); done(null, payload); } }, request => ({ input: request.body }));
  try { const response = await f.server.inject({ method: 'POST', url: '/payload', payload: { value: 7 } }); assert.equal(response.statusCode, 200); assert.deepEqual(response.json(), { input: { value: 7 }, added: true }); assert.deepEqual(events, ['parse', 'promise-hook', 'serialize', 'send']); }
  finally { await bounded(f.server.close()); }
});

test('an admitted onResponse callback outlives response delivery and stays drained until done', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(), entered = deferred(); let closing: Promise<void> | undefined, effects = 0;
  f.server.addHook('onResponse', function (_request, _reply, done) { entered.resolve(); void gate.promise.then(() => { effects++; done(); }); }); f.server.get('/response', async () => ({}));
  try { const response = f.server.inject('/response'); await bounded(entered.promise); await response; closing = f.server.close(); let complete = false; void closing.then(() => { complete = true; }); await turn(); assert.equal(complete, false); gate.resolve(); await bounded(closing); assert.equal(effects, 1); }
  finally { gate.resolve(); await bounded(closing ?? f.server.close()); }
});

test('a hanging HTTP lifetime uses the existing outer deadline and late completion cannot close storage', { timeout: 3000 }, async () => {
  const f = fixture(), gate = deferred(), entered = deferred(); let closing: Promise<void> | undefined, storeClosed = false, resourcesClosed = false;
  f.server.get('/hang', async (_request, reply) => { reply.send({ accepted: true }); entered.resolve(); await gate.promise; });
  try {
    const response = f.server.inject('/hang'); await bounded(entered.promise); await response;
    const close = createShutdown({ stopAdmission: () => { closing = f.server.close(); }, drain: () => closing!, closeResources: async () => { resourcesClosed = true; }, closeStore: async () => { storeClosed = true; } }, 20);
    await assert.rejects(close(), DrainTimeoutError); assert.equal(resourcesClosed, false); assert.equal(storeClosed, false); gate.resolve(); await bounded(closing!); await turn(); assert.equal(resourcesClosed, false); assert.equal(storeClosed, false);
  } finally { gate.resolve(); await bounded(closing ?? f.server.close()); }
});
