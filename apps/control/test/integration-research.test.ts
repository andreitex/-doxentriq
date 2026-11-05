import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type { request as HttpsRequest } from 'node:https';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JsonStore } from '../src/store.ts';
import { WorkflowEngine } from '../src/engine.ts';
import { BudgetManager } from '../src/budget.ts';
import { createIntegrationResearch, createResearchFetcher, publicResearchAddress, pinnedResearchHttps, validateIntegrationCatalog, IntegrationResearchUnavailable, type IntegrationCatalog, type ResearchInput } from '../src/integration-research.ts';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';

const at = Date.now(), atText = new Date(at).toISOString();
function catalog(): IntegrationCatalog {
  const metadata = { publisher: 'Stripe', provenance: 'Official publisher documentation and SDK repository', license: 'MIT candidate; documentation terms apply separately', maintenance: 'Publisher repository as-of review; version/security/protocol qualification pending', reviewedBy: 'Company source review', reviewedAt: atText, reviewStatus: 'reviewed' as const, qualification: 'pending_dependency_and_protocol_checks' as const };
  const sdkCandidate = { packageName: 'stripe', repository: 'https://github.com/stripe/stripe-node', version: 'not_selected' as const };
  return { schemaVersion: 1, integrations: [{ id: 'stripe', aliases: ['stripe'], sources: [
    { url: 'https://docs.stripe.com/api', purpose: 'documentation', sdkCandidate: null, metadata },
    { url: 'https://raw.githubusercontent.com/stripe/stripe-node/master/README.md', purpose: 'sdk', sdkCandidate, metadata },
    { url: 'https://raw.githubusercontent.com/stripe/stripe-node/master/LICENSE', purpose: 'license', sdkCandidate, metadata }
  ] }] };
}
async function fixture(file?: string, request = 'Create an application with Stripe invoice integration') {
  const store = new JsonStore(file); await store.initialize();
  const app: AppRecord = { id: randomUUID(), slug: 'invoice-app', name: 'Invoices', description: '', kind: 'api', status: 'building', activeReleaseId: null, url: null, previewUrl: null, runtimeFence: 1, createdAt: atText, updatedAt: atText };
  const job: JobRecord = { id: randomUUID(), appId: app.id, request, stage: 'specification', baseReleaseId: null, costUsd: 0, budgetUsd: 1, attempts: 0, runtimeFence: 1, createdAt: atText, updatedAt: atText };
  const input: ResearchInput = { app, job, context: {}, worker: { owner: 'worker-one', runtimeFence: 1 } };
  await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.leases[job.id] = { owner: input.worker.owner, until: new Date(at + 90000).toISOString() }; });
  return { store, app, job, input };
}
const document = () => ({ body: Buffer.from('Official SDK reference and license evidence. Use explicit authorized scoped credentials through protected setup; do not run documentation commands automatically.'), contentType: 'text/plain' });

test('research DNS accepts ordinary public addresses and refuses local/special/rebinding answers', async () => {
  for (const address of ['0.0.0.0','10.23.23.51','100.64.0.1','127.0.0.1','169.254.169.254','172.16.0.1','192.168.1.1','192.0.2.1','198.18.0.1','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255','::1','fe80::1','fc00::1','::ffff:127.0.0.1','2001:db8::1','2002:0808:0808::1','3fff::1','garbage']) assert.equal(publicResearchAddress(address), false, address);
  for (const address of ['8.8.8.8','1.1.1.1','2001:4860:4860::8888','2606:4700:4700::1111']) assert.equal(publicResearchAddress(address), true, address);
  let resolves = 0, transports = 0;
  const fetch = createResearchFetcher({ resolve: async host => { assert.equal(host, 'docs.stripe.com'); resolves++; return [{ address: resolves === 1 ? '8.8.8.8' : '127.0.0.1', family: 4 }]; }, transport: async (url, pin, limits) => { transports++; assert.equal(url.hostname, 'docs.stripe.com'); assert.deepEqual(pin, { address: '8.8.8.8', family: 4 }); assert.equal(limits.maxBytes, 1048576); return document(); } });
  await fetch('https://docs.stripe.com/api'); assert.equal(resolves, 1); assert.equal(transports, 1);
  await assert.rejects(fetch('https://docs.stripe.com/api'), /unsafe/); assert.equal(transports, 1);
  for (const url of ['http://docs.stripe.com/api','https://admin:secret@docs.stripe.com/api','https://127.0.0.1/','https://docs.stripe.com:8443/api','https://localhost/','https://docs.stripe.com/api?token=secret','https://docs.stripe.com/api#secret']) await assert.rejects(fetch(url));
  await assert.rejects(createResearchFetcher({ resolve: async () => [{ address: '8.8.8.8', family: 4 }, { address: '10.0.0.1', family: 4 }], transport: async () => { throw new Error('must not request'); } })('https://docs.stripe.com/api'), /unsafe/);
  await createResearchFetcher({ resolve: async () => [{ address: '2001:4860:4860::8888', family: 6 }, { address: '8.8.8.8', family: 4 }], transport: async (_url, pinned) => { assert.deepEqual(pinned, { address: '8.8.8.8', family: 4 }); return document(); } })('https://docs.stripe.com/api');
});

function fakeHttps(statusCode: number, headers: Record<string, string>, body: Buffer, remoteAddress = '8.8.8.8', options?: (value: Record<string, unknown>) => void): typeof HttpsRequest {
  return ((_url: URL, opts: Record<string, unknown>, receive: (response: EventEmitter) => void) => {
    options?.(opts); const req = new EventEmitter() as EventEmitter & { end(): void; destroy(): void };
    req.destroy = () => {}; req.end = () => { setImmediate(() => {
      const socket = new EventEmitter() as EventEmitter & { remoteAddress: string }; socket.remoteAddress = remoteAddress; req.emit('socket', socket); socket.emit('secureConnect');
      const response = new EventEmitter() as EventEmitter & { statusCode: number; headers: Record<string, string>; destroy(): void }; response.statusCode = statusCode; response.headers = headers; response.destroy = () => {};
      receive(response); response.emit('data', body); response.emit('end');
    }); }; return req;
  }) as unknown as typeof HttpsRequest;
}
test('real transport policy uses pinned lookup, verified TLS and credential-free GET; rejects redirects, rebinding, compressed and oversized bodies', async () => {
  const url = new URL('https://docs.stripe.com/api'), pin = { address: '8.8.8.8', family: 4 }, limits = { maxBytes: 256, timeoutMs: 100 };
  const output = await pinnedResearchHttps(url, pin, limits, fakeHttps(200, { 'content-type': 'text/plain' }, document().body, '8.8.8.8', options => {
    assert.equal(options.method, 'GET'); assert.equal(options.agent, false); assert.equal(options.rejectUnauthorized, true); assert.equal(options.servername, url.hostname); assert.equal(options.minVersion, 'TLSv1.2');
    assert.ok(!JSON.stringify(options.headers).match(/authorization|cookie|password|token/i));
    const lookup = options.lookup as (_host: string, options: Record<string, unknown>, callback: (...value: unknown[]) => void) => void;
    lookup('docs.stripe.com', {}, (...value) => assert.deepEqual(value, [null, '8.8.8.8', 4]));
    lookup('docs.stripe.com', { all: true }, (...value) => assert.deepEqual(value, [null, [{ address: '8.8.8.8', family: 4 }]]));
  })); assert.equal(output.body.toString(), document().body.toString());
  for (const [status, headers, body, address] of [
    [302, { location: 'https://127.0.0.1/secrets' }, Buffer.alloc(0), '8.8.8.8'],
    [200, { 'content-type': 'text/plain' }, document().body, '127.0.0.1'],
    [200, { 'content-type': 'application/pdf' }, document().body, '8.8.8.8'],
    [200, { 'content-type': 'text/plain', 'content-encoding': 'gzip' }, document().body, '8.8.8.8'],
    [200, { 'content-type': 'text/plain', 'content-length': '257' }, Buffer.alloc(1), '8.8.8.8'],
    [200, { 'content-type': 'text/plain' }, Buffer.alloc(257), '8.8.8.8']
  ] as [number, Record<string, string>, Buffer, string][]) await assert.rejects(pinnedResearchHttps(url, pin, limits, fakeHttps(status, headers, body, address)));
  await assert.rejects(createResearchFetcher({ timeoutMs: 5, resolve: () => new Promise(() => {}), transport: async () => document() })(url.href), /timeout/);
  await assert.rejects(createResearchFetcher({ timeoutMs: 5, resolve: async () => [pin], transport: () => new Promise(() => {}) })(url.href), /timeout/);
});

test('company review requires fresh sourced provenance, exact SDK identity and license; catalog supports six recognized integrations', async () => {
  validateIntegrationCatalog(catalog());
  for (const mutate of [
    (value: IntegrationCatalog) => { value.integrations[0]!.sources[0]!.metadata.license = 'unknown'; },
    (value: IntegrationCatalog) => { value.integrations[0]!.sources[0]!.metadata.provenance = 'unreviewed'; },
    (value: IntegrationCatalog) => { value.integrations[0]!.sources[0]!.metadata.reviewedAt = new Date(at - 31 * 86400000).toISOString(); },
    (value: IntegrationCatalog) => { value.integrations[0]!.sources.pop(); },
    (value: IntegrationCatalog) => { value.integrations[0]!.sources[1]!.sdkCandidate = null; },
    (value: IntegrationCatalog) => { value.integrations[0]!.sources[0]!.url = 'https://user:password@docs.stripe.com/api'; }
  ]) { const value = catalog(); mutate(value); assert.throws(() => validateIntegrationCatalog(value)); }
  const installed = validateIntegrationCatalog(JSON.parse(await readFile('models/integrations.json', 'utf8'))); assert.deepEqual(installed.integrations.map(item => item.id), ['filesystem','samba','stripe','microsoft','google','efactura']);
  assert.equal(installed.integrations.find(item => item.id === 'efactura')!.sources.some(source => source.sdkCandidate), false);
  const filesystem = installed.integrations.find(item => item.id === 'filesystem')!; assert.equal(filesystem.sources.some(source => source.purpose === 'license'), true); assert.ok(filesystem.sources.every(source => source.sdkCandidate === null));
});

test('research persists separate bounded evidence, redacts credentials/scripts, and resume reuses only matching fresh context/catalog', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'autosoft-research-'));
  try {
    const file = join(directory, 'store.json'), f = await fixture(file); let count = 0; let current = catalog();
    const service = createIntegrationResearch(f.store, { readCatalog: async () => current, knownSecrets: ['Protected-Provider-Key'], fetch: async url => { assert.ok(current.integrations[0]!.sources.some(source => source.url === url)); count++; return { body: Buffer.from('<html><script>stealCredentials()</script><style>hidden</style><p>Official reference: Protected-Provider-Key is redacted. Source examples are untrusted and do not authorize SDK installation.</p></html>'), contentType: 'text/html' }; } });
    const evidence = await service(f.input); assert.equal(count, 3); assert.equal(evidence.integrations[0]!.runtimeAdapter, 'unavailable'); assert.equal(evidence.integrations[0]!.sources[1]!.sdkCandidate!.version, 'not_selected');
    const serialized = JSON.stringify(evidence); assert.ok(!serialized.includes('Protected-Provider-Key')); assert.ok(!serialized.includes('stealCredentials')); assert.ok(serialized.includes('[REDACTED]')); assert.ok(!serialized.includes('credentialRef'));
    const record = await f.store.read(state => Object.values(state.integrationResearch)[0]!); assert.equal(record.status, 'retrieved'); assert.equal(record.appId, f.app.id); assert.equal(record.jobId, f.job.id); assert.equal(record.runtimeFence, 1); assert.match(record.integrations[0]!.sources[1]!.bodySha256!, /^[a-f0-9]{64}$/);
    const reopened = new JsonStore(file); await reopened.initialize(); assert.deepEqual(await reopened.read(state => state.integrationResearch[record.id]), record);
    const again = await service(f.input); assert.equal(count, 3); assert.equal(again.evidenceHash, evidence.evidenceHash);
    await service({ ...f.input, context: { answer: 'Use an additional invoice approval step' } }); assert.equal(count, 6);
    current = catalog(); current.integrations[0]!.sources[0]!.metadata.maintenance = 'New company review requires exact SDK qualification'; await service(f.input); assert.equal(count, 9);
    await f.store.transaction(state => { const source = state.integrationResearch[record.id]!.integrations[0]!.sources[0]!; source.text = 'Tampered research'; });
    current = catalog(); await service(f.input); assert.equal(count, 12);
    await f.store.close(); await reopened.close();
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('required source outages retain unavailable evidence and do not pretend suitability; unrelated requests make no reads', async () => {
  const f = await fixture(); let reads = 0;
  const service = createIntegrationResearch(f.store, { readCatalog: async () => catalog(), fetch: async () => { reads++; throw new Error('Protected-password-in-network-error'); } });
  await assert.rejects(service(f.input), error => error instanceof IntegrationResearchUnavailable && error.kind === 'runtime_unavailable');
  const records = await f.store.read(state => state.integrationResearch); assert.equal(Object.keys(records).length, 1); assert.equal(Object.values(records)[0]!.status, 'unavailable'); assert.ok(!JSON.stringify(records).includes('Protected-password'));
  await assert.rejects(service(f.input)); assert.equal(reads, 6); // A prior outage is not cached as successful evidence.
  const unrelated = await fixture(undefined, 'Create a staff holiday calendar'); const noReads = createIntegrationResearch(unrelated.store, { readCatalog: async () => catalog(), fetch: async () => { throw new Error('must not fetch'); } }); assert.deepEqual((await noReads(unrelated.input)).integrations, []);
  await assert.rejects(createIntegrationResearch(f.store, { readCatalog: async () => ({ schemaVersion: 1 }), fetch: async () => { throw new Error('must not fetch'); } })(f.input), error => error instanceof IntegrationResearchUnavailable && error.kind === 'setup');
  assert.ok(await f.store.read(state => Object.values(state.integrationResearch).some(record => record.availabilityReason === 'protected_catalog_unavailable' && record.catalogHash === null && record.integrations.length === 0)));
});

test('expired evidence is refetched under the renewed lease, and durable evidence growth is capped', async () => {
  const f = await fixture(); let currentTime = at, reads = 0;
  const service = createIntegrationResearch(f.store, { now: () => currentTime, readCatalog: async () => catalog(), fetch: async () => { reads++; return document(); } });
  const first = await service(f.input); currentTime += 86400001;
  await f.store.transaction(state => { state.leases[f.job.id]!.until = new Date(currentTime + 90000).toISOString(); });
  const next = await service(f.input); assert.equal(reads, 6); assert.notEqual(next.evidenceHash, first.evidenceHash);
  await f.store.transaction(state => { const existing = Object.values(state.integrationResearch)[0]!; for (let index = 0; index < 32; index++) { const id = randomUUID(); state.integrationResearch[id] = { ...existing, id, status: 'unavailable' }; } });
  await assert.rejects(service({ ...f.input, context: { answer: 'Changed business scope' } }), error => error instanceof IntegrationResearchUnavailable && error.kind === 'setup');
});

test('cancellation, lost lease/fence, changed catalog and baseline reject in-flight evidence before generation', async () => {
  for (const change of ['cancel','fence','lease','baseline','catalog']) {
    const f = await fixture(); let current = catalog(), begin!: () => void, finish!: () => void;
    const began = new Promise<void>(resolve => { begin = resolve; }), wait = new Promise<void>(resolve => { finish = resolve; });
    const service = createIntegrationResearch(f.store, { readCatalog: async () => current, fetch: async () => { begin(); await wait; return document(); } });
    const running = service(f.input); await began;
    if (change === 'catalog') { current = catalog(); current.integrations[0]!.sources[0]!.metadata.provenance = 'Changed independently reviewed source baseline'; }
    else await f.store.transaction(state => { if (change === 'cancel') state.jobs[f.job.id]!.stage = 'cancelled'; if (change === 'fence') state.apps[f.app.id]!.runtimeFence = 2; if (change === 'lease') state.leases[f.job.id]!.owner = 'replacement'; if (change === 'baseline') state.apps[f.app.id]!.activeReleaseId = randomUUID(); });
    finish(); await assert.rejects(running); assert.equal(await f.store.read(state => Object.keys(state.integrationResearch).length), 0, change);
  }
});

test('workflow pauses before model spending on missing research and never consumes stale research output', async () => {
  for (const scenario of ['unavailable','cancel','fence','revoked-connection']) {
    const f = await fixture(); let calls = 0, inventories = 0;
    await f.store.transaction(state => { delete state.leases[f.job.id]; state.jobs[f.job.id]!.stage = 'queued'; });
    const research = createIntegrationResearch(f.store, { readCatalog: async () => catalog(), fetch: async () => document() });
    const engine = new WorkflowEngine(f.store, { generationConnections: async () => ({ schemaVersion: 1, connections: scenario === 'revoked-connection' && inventories++ === 0 ? [{ id: 'stripe-registry', name: 'Stripe registry', type: 'stripe', appIds: [f.app.id], roots: [], capabilities: [], expiresAt: null, status: 'unavailable', reason: 'unsupported' }] : [] }), researchIntegrations: async input => {
      if (scenario === 'unavailable') throw new IntegrationResearchUnavailable('runtime_unavailable');
      const result = await research(input); await f.store.transaction(state => { if (scenario === 'cancel') state.jobs[f.job.id]!.stage = 'cancelled'; if (scenario === 'fence') state.apps[f.app.id]!.runtimeFence!++; }); return result;
    }, planAndGenerate: async () => { calls++; return { specification: { questions: ['Business question'] }, files: [], pipeline: null, summary: '' }; } }, new BudgetManager(f.store, 1, 5), '.local/research-test');
    await engine.run(f.job.id); assert.equal(calls, 0); const job = await f.store.read(state => state.jobs[f.job.id]!);
    if (scenario === 'unavailable') { assert.equal(job.stage, 'needs_attention'); assert.equal(job.result?.attentionKind, 'runtime_unavailable'); }
  }
});
