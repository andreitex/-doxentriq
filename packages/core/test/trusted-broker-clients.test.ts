import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac } from 'node:crypto';
import { AccessBrokerClient } from '../src/access.ts';
import { ConnectorBrokerClient } from '../src/connectors.ts';
import { AdapterBrokerClient } from '../src/connector-adapters.ts';
import { ConnectionRevocationClient } from '../src/connection-revocation.ts';
import { DirectoryBrokerClient } from '../src/directory.ts';

const key = Buffer.alloc(32, 7), token = 'synthetic-private-token';
type Config = { url: string; token: string; approvalKey: Buffer; fetch?: typeof fetch };
const identity = { appId: 'app-one', connectionId: 'connection-one', operationId: 'operation-one', approvalId: 'approval-one', artifactHash: 'a'.repeat(64) };
const cases = [
  { name: 'access', construct: (config: Config) => new AccessBrokerClient(config), call: (client: unknown) => (client as AccessBrokerClient).snapshot({ appId: 'app-one' }), route: '/v1/access/snapshot', maximum: 1048576, reply: { appId: 'app-one' } },
  { name: 'Samba', construct: (config: Config) => new ConnectorBrokerClient(config), call: (client: unknown) => (client as ConnectorBrokerClient).status(identity), route: '/v1/connectors/status', maximum: 65536, reply: { status: 'unknown' } },
  { name: 'filesystem', construct: (config: Config) => new AdapterBrokerClient(config), call: (client: unknown) => (client as AdapterBrokerClient).filesystemSources('app-one'), route: '/v1/connectors/filesystem/sources', maximum: 65536, reply: { schemaVersion: 1, appId: 'app-one', sources: [] } },
  { name: 'withdrawal', construct: (config: Config) => new ConnectionRevocationClient(config), call: (client: unknown) => (client as ConnectionRevocationClient).status(identity), route: '/v1/connectors/revocation/status', maximum: 65536, reply: { ...identity, schemaVersion: 1, type: 'filesystem', status: 'unknown', tombstone: false, snapshotHash: '0'.repeat(64), stoppedContainerIds: [], checkedAt: '2026-10-11T09:00:00.000Z' } },
  { name: 'directory', construct: (config: Config) => new DirectoryBrokerClient(config), call: (client: unknown) => (client as DirectoryBrokerClient).keys({ appId: 'app-one' }), route: '/v1/access/directory-keys', maximum: 1048576, reply: { appId: 'app-one' } },
];
const config = (fetch?: typeof globalThis.fetch): Config => ({ url: 'https://broker.example:8090', token, approvalKey: key, fetch });
function isUncertain(error: unknown): boolean {
  assert.ok(error instanceof Error); assert.equal((error as { confirmedRejected?: unknown }).confirmedRejected, false);
  assert.doesNotMatch(String(error), /synthetic-private|private-path|provider-body/);
  assert.equal(Object.hasOwn(error, 'input'), false); assert.equal(Object.hasOwn(error, 'cause'), false); return true;
}

test('all credential-bearing broker clients reject malformed or foreign origins before dispatch', () => {
  for (const item of cases) {
    let calls = 0;
    for (const url of ['synthetic-private@invalid', 'http://foreign.example', 'https://user:synthetic-private@broker.example', 'https://broker.example/path', 'https://broker.example?secret=synthetic-private', 'https://broker.example#fragment']) {
      assert.throws(() => item.construct({ ...config(async () => { calls++; throw new Error(); }), url }), error => {
        assert.ok(error instanceof Error); assert.match(error.message, /exact trusted HTTPS/); assert.doesNotMatch(error.message, /synthetic-private/);
        assert.equal(Object.hasOwn(error, 'input'), false); assert.equal(Object.hasOwn(error, 'cause'), false); return true;
      });
    }
    for (const url of ['http://127.0.0.1:8090', 'http://localhost:8090', 'http://[::1]:8090']) assert.doesNotThrow(() => item.construct({ ...config(), url }));
    assert.equal(calls, 0);
  }
});

for (const item of cases) {
  test(`${item.name} uses one exact authenticated POST and observes only HTTP200`, async () => {
    let calls = 0;
    const client = item.construct(config(async (url, init) => {
      calls++; assert.equal(String(url), `https://broker.example:8090${item.route}`); assert.equal(init?.method, 'POST'); assert.equal(init?.redirect, 'error');
      const headers = init?.headers as Record<string, string>; assert.equal(headers.authorization, `Bearer ${token}`);
      if (item.name === 'directory') assert.equal(headers['x-autosoft-proof'], createHmac('sha256', key).update(String(init?.body)).digest('hex'));
      assert.ok(init?.signal); return Response.json(item.reply);
    }));
    assert.deepEqual(await item.call(client), item.reply); assert.equal(calls, 1);
    for (const status of [201, 202, 204]) {
      await assert.rejects(item.call(item.construct(config(async () => status === 204 ? new Response(null, { status }) : Response.json({ rejectedBeforeExecution: true }, { status })))), isUncertain);
    }
  });

  test(`${item.name} bounds streamed replies and leaves failed reads or uncertain refusals retained`, async () => {
    for (const length of ['-1', '01', '1e5', String(item.maximum + 1)]) {
      let cancelled = false;
      const stream = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
      await assert.rejects(item.call(item.construct(config(async () => new Response(stream, { headers: { 'content-length': length } })))), isUncertain);
      assert.equal(cancelled, true);
    }
    let cancelled = false, pulls = 0;
    const stream = new ReadableStream<Uint8Array>({ pull(controller) { pulls++; controller.enqueue(new Uint8Array(item.maximum + 1)); }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
    await assert.rejects(item.call(item.construct(config(async () => new Response(stream)))), isUncertain);
    assert.equal(pulls, 1); assert.equal(cancelled, true);
    for (const response of [new Response(new Uint8Array([255])), new Response('{'), Response.json(null), Response.json([]), new Response('{}', { headers: { 'content-length': '3' } }), new Response('provider-body'.repeat(7000), { status: 409 })])
      await assert.rejects(item.call(item.construct(config(async () => response))), isUncertain);
  });
}

test('network, redirected or foreign response outcomes cannot leak details or forge confirmed rejection', async () => {
  for (const item of cases) {
    for (const mode of ['network', 'redirected', 'foreign-url', 'broken-stream']) {
      let calls = 0;
      const client = item.construct(config(async () => {
        calls++;
        if (mode === 'network') throw Object.assign(new Error('synthetic-private private-path'), { confirmedRejected: true });
        if (mode === 'broken-stream') return new Response(new ReadableStream({ start(controller) { controller.error(Object.assign(new Error('provider-body synthetic-private'), { confirmedRejected: true })); } }));
        const response = Response.json(item.reply);
        if (mode === 'redirected') Object.defineProperty(response, 'redirected', { value: true });
        else Object.defineProperty(response, 'url', { value: 'https://foreign.example/private-path' });
        return response;
      }));
      await assert.rejects(item.call(client), isUncertain); assert.equal(calls, 1);
    }
  }
});

test('only an observed bounded negative receipt confirms rejection before execution', async () => {
  for (const item of cases) for (const rejectedBeforeExecution of [true, false, 'true', 1, null]) {
    await assert.rejects(item.call(item.construct(config(async () => Response.json({ rejectedBeforeExecution, detail: 'provider-body synthetic-private' }, { status: 409 })))), error => {
      assert.ok(error instanceof Error); assert.match(error.message, /HTTP 409/); assert.doesNotMatch(error.message, /provider-body|synthetic-private/);
      assert.equal((error as { confirmedRejected?: unknown }).confirmedRejected, rejectedBeforeExecution === true); return true;
    });
  }
});

test('invitation credentials and Samba credentials preserve exact signed bodies without dispatch retries', async () => {
  const input = { operationId: 'exact-operation', credentials: { username: 'synthetic-user', password: 'synthetic-private-password' }, password: 'synthetic-private-password' };
  for (const make of [(c: Config) => { const client = new AccessBrokerClient(c); return () => client.acceptInvitation(input as never); }, (c: Config) => { const client = new ConnectorBrokerClient(c); return () => client.provision(input as never); }]) {
    let calls = 0;
    const call = make(config(async (_url, init) => {
      calls++; assert.equal(String(init?.body), JSON.stringify(input));
      assert.equal((init?.headers as Record<string, string>)['x-autosoft-proof'], createHmac('sha256', key).update(JSON.stringify(input)).digest('hex'));
      throw new Error('synthetic-private-password');
    }));
    await assert.rejects(call(), isUncertain); assert.equal(calls, 1);
  }
});
