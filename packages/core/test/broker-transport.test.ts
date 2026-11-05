import assert from 'node:assert/strict';
import test from 'node:test';
import { BrokerClient } from '../src/broker.ts';

const client = (fetch: typeof globalThis.fetch) => new BrokerClient({ url: 'https://broker.example:8090', token: 'synthetic-token', approvalKey: Buffer.alloc(32), fetch });

test('malformed broker URLs cannot disclose their raw input or dispatch a request', () => {
  let calls = 0;
  assert.throws(() => new BrokerClient({ url: 'private-key@invalid-config', token: 'synthetic', approvalKey: Buffer.alloc(32), fetch: async () => { calls++; throw new Error(); } }), error => {
    assert.match(String(error), /trusted HTTPS origin/); assert.doesNotMatch(String(error), /private-key/);
    assert.equal(Object.hasOwn(error as object, 'input'), false); assert.equal(Object.hasOwn(error as object, 'cause'), false); return true;
  });
  assert.equal(calls, 0);
});

test('broker credentials require a complete HTTPS origin or explicit loopback development', () => {
  for (const url of ['http://broker.example:8090', 'https://user:secret@broker.example', 'https://broker.example/subpath', 'https://broker.example?secret=q', 'https://broker.example#fragment', 'file:///broker'])
    assert.throws(() => new BrokerClient({ url, token: 'synthetic', approvalKey: Buffer.alloc(32) }), /trusted HTTPS origin/);
  for (const url of ['https://broker.example:8090', 'http://127.0.0.1:8090', 'http://localhost:8090', 'http://[::1]:8090'])
    assert.doesNotThrow(() => new BrokerClient({ url, token: 'synthetic', approvalKey: Buffer.alloc(32) }));
});

test('actual operation requests refuse redirects and preserve exact body and bearer boundaries', async () => {
  let calls = 0;
  const broker = client(async (url, init) => {
    calls++; assert.equal(String(url), 'https://broker.example:8090/v1/operation');
    assert.equal(init?.redirect, 'error'); assert.equal(init?.method, 'POST');
    assert.equal((init?.headers as Record<string, string>).authorization, 'Bearer synthetic-token');
    assert.deepEqual(JSON.parse(String(init?.body)), { operationId: 'exact-operation' });
    return Response.json({ status: 'unknown' });
  });
  assert.deepEqual(await broker.operation({ operationId: 'exact-operation' }), { status: 'unknown' }); assert.equal(calls, 1);
});

test('network and redirect failures remain uncertain without exporting raw errors or retrying', async () => {
  let calls = 0;
  const broker = client(async () => { calls++; throw new Error('password=private /private/path'); });
  await assert.rejects(broker.operation({ operationId: 'exact-operation' }), error => {
    assert.match(String(error), /outcome is unavailable/); assert.doesNotMatch(String(error), /password|private\/path/);
    assert.notEqual((error as { confirmedRejected?: unknown }).confirmedRejected, true); return true;
  });
  assert.equal(calls, 1);
});

test('declared excessive or invalid response lengths are cancelled before receipt reading', async () => {
  for (const length of [String(8 * 1024 ** 2 + 1), '-1', 'NaN', '1e4']) {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
    await assert.rejects(client(async () => new Response(stream, { headers: { 'content-length': length } })).telemetry(), /byte limit/);
    assert.equal(cancelled, true);
  }
});

test('unannounced oversized receipt stops reading and cancels the remaining stream', async () => {
  let pulls = 0, cancelled = false;
  const stream = new ReadableStream<Uint8Array>({ pull(controller) { pulls++; controller.enqueue(new Uint8Array(4 * 1024 ** 2 + 1)); }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
  await assert.rejects(client(async () => new Response(stream)).telemetry(), /byte limit/);
  assert.equal(pulls, 2); assert.equal(cancelled, true);
});

test('invalid UTF8 JSON scalar empty body and stream failure cannot become a successful receipt', async () => {
  for (const response of [new Response(new Uint8Array([255])), new Response('{'), Response.json(null), Response.json([]), Response.json('accepted'), new Response(null), new Response('{}', { headers: { 'content-length': '3' } })])
    await assert.rejects(client(async () => response).operation({ operationId: 'exact-operation' }), /receipt.*unavailable|receipt.*malformed/);
  const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.error(new Error('password=private')); } });
  await assert.rejects(client(async () => new Response(stream)).operation({ operationId: 'exact-operation' }), error => { assert.doesNotMatch(String(error), /password/); return true; });
});

test('only the observed bounded rejected-before-execution boolean confirms a refusal', async () => {
  for (const rejectedBeforeExecution of [true, false, 'true', 1, undefined]) {
    await assert.rejects(client(async () => Response.json({ error: 'password=private', rejectedBeforeExecution }, { status: 409 })).operation({ operationId: 'exact-operation' }), error => {
      assert.equal((error as { confirmedRejected?: unknown }).confirmedRejected, rejectedBeforeExecution === true);
      assert.match(String(error), /HTTP 409/); assert.doesNotMatch(String(error), /password/); return true;
    });
  }
});

test('oversized refusal or a nonfinal HTTP success leaves the operation uncertain', async () => {
  await assert.rejects(client(async () => new Response(' '.repeat(65537), { status: 409 })).operation({ operationId: 'exact-operation' }), error => {
    assert.notEqual((error as { confirmedRejected?: unknown }).confirmedRejected, true); return true;
  });
  await assert.rejects(client(async () => Response.json({ rejectedBeforeExecution: true }, { status: 202 })).operation({ operationId: 'exact-operation' }), error => {
    assert.equal((error as { confirmedRejected?: unknown }).confirmedRejected, false); assert.match(String(error), /HTTP 202/); return true;
  });
});

test('source uses its separate JSON encoding bound without weakening ordinary receipt limits', async () => {
  const oversized = String(128 * 1024 ** 2 + 1);
  await assert.rejects(client(async () => new Response(null, { headers: { 'content-length': oversized } })).source({ appId: 'app-one', commit: 'a'.repeat(40) }), /byte limit/);
  assert.deepEqual(await client(async () => Response.json({ files: [{ path: 'server.ts', content: 'export {}' }] })).source({ appId: 'app-one', commit: 'a'.repeat(40) }), { files: [{ path: 'server.ts', content: 'export {}' }] });
});
