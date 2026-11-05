import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from '../src/server.ts';
import { configureDependencies } from '../src/dependencies.ts';
import { JsonStore } from '../src/store.ts';
import { BudgetManager } from '../src/budget.ts';
import type { Config } from '../src/config.ts';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';
import { ModelGateway, createGenerationService, type ModelCatalog } from '../../../packages/core/src/models.ts';
import { hashArtifact, redact } from '../../../packages/core/src/security.ts';

const databasePassword = 'DatabaseOpaque+/ value"\\123';
const config = (): Config => ({ authMode: 'development', host: '127.0.0.1', port: 3000, publicOrigin: 'http://127.0.0.1:3000', dataDir: 'unused', workspaceDir: 'unused', oidcClientId: 'public-client-id', oidcIssuer: 'https://identity.example.com/realm', secretKey: Buffer.alloc(32, 57), requestLimitUsd: 1, monthlyLimitUsd: 5, adminDist: 'absent-protected-metadata-dist',
  openaiApiKey: 'OpenOpaquePlatform123', anthropicApiKey: 'ClaudeOpaquePlatform123', brokerToken: 'BrokerOpaquePlatform123', reportToken: 'ReportOpaquePlatform123', metricsToken: 'MetricsOpaquePlatform123', oidcClientSecret: 'OidcOpaque"\\\nUnicode_ș_123',
  mysqlUrl: `mysql://databaseUser:${encodeURIComponent(databasePassword)}@db.example.com/platform`, rabbitUrl: 'amqps://brokerUser:RabbitOpaquePlatform123@mq.example.com/', redisUrl: 'rediss://cacheUser:RedisOpaquePlatform123@redis.example.com/' });
function values(c: Config): string[] { return [c.openaiApiKey!, c.anthropicApiKey!, c.brokerToken!, c.reportToken!, c.metricsToken!, c.oidcClientSecret!, databasePassword, encodeURIComponent(databasePassword), 'RabbitOpaquePlatform123', 'RedisOpaquePlatform123', c.secretKey.toString('base64')]; }
function variants(value: string): string[] { return [...new Set([value, JSON.stringify(value).slice(1, -1)])]; }
async function apiFixture(c = config()) {
  const store = new JsonStore(); await store.initialize(); const server = await createServer(c, store, {});
  const session = await server.inject({ method: 'GET', url: '/api/v1/session' }), cookie = session.cookies[0]!;
  const headers = { cookie: `${cookie.name}=${cookie.value}`, origin: c.publicOrigin, 'x-csrf-token': session.json().csrfToken as string };
  return { store, server, headers, close: async () => { await server.close(); await store.close(); } };
}
function catalog(provider: 'openai' | 'anthropic' = 'openai'): ModelCatalog { return { schemaVersion: 1, pricesVerifiedAt: new Date().toISOString(), sources: ['https://example.com/company-test-catalog'], models: [{ id: 'synthetic-qualified-model', provider, tier: 'strong', inputUsdPerMillion: .1, outputUsdPerMillion: .1, cachedInputUsdPerMillion: .01, cacheWriteUsdPerMillion: .1, effort: 'high', qualified: true, maxInputTokens: 90000, maxOutputTokens: 4096 }] }; }
const receipt = (provider: 'openai' | 'anthropic', text = 'Synthetic output') => Response.json(provider === 'openai' ? { service_tier: 'default', usage: { input_tokens: 1, output_tokens: 1 }, output: [{ type: 'message', content: [{ type: 'output_text', text }] }] } : { usage: { service_tier: 'standard', input_tokens: 1, output_tokens: 1 }, content: [{ type: 'text', text }] });

test('app name and description reject every configured protected value before persistent mutation', async () => {
  const c = config(), f = await apiFixture(c);
  try {
    for (const value of values(c)) for (const field of ['name', 'description'] as const) {
      const before = await f.store.read(state => state);
      const response = await f.server.inject({ method: 'POST', url: '/api/v1/apps', headers: f.headers, payload: { name: 'Documents', description: 'Folder and version management', [field]: `Documents ${value}` } });
      assert.equal(response.statusCode, 400, `Protected ${field} was admitted`); assert.match(response.json().error.message, /protected.*form/i);
      for (const spelling of variants(value)) assert.ok(!response.body.includes(spelling), 'Error echoed a protected value');
      assert.deepEqual(await f.store.read(state => state), before, 'Rejected metadata mutated persistent state');
    }
  } finally { await f.close(); }
});

test('legitimate app metadata and public configuration names remain unchanged', async () => {
  const f = await apiFixture(); const name = 'Service desk for databaseUser', description = 'Documents, public-client-id and secret architecture notes at https://identity.example.com/realm.';
  try {
    const response = await f.server.inject({ method: 'POST', url: '/api/v1/apps', headers: f.headers, payload: { name, description, kind: 'web' } });
    assert.equal(response.statusCode, 200, response.body); assert.equal(response.json().app.name, name); assert.equal(response.json().app.description, description);
    assert.equal(await f.store.read(state => state.apps[response.json().app.id]?.description), description);
  } finally { await f.close(); }
});

test('chat and resume share the protected OIDC URL-password and encryption-key admission list', async () => {
  const c = config(), f = await apiFixture(c);
  try {
    const created = await f.server.inject({ method: 'POST', url: '/api/v1/apps', headers: f.headers, payload: { name: 'Documents' } }); const app = created.json().app as AppRecord;
    const at = new Date().toISOString(), job: JobRecord = { id: randomUUID(), appId: app.id, request: 'Create document folders', stage: 'clarification', baseReleaseId: null, budgetUsd: 1, costUsd: 0, attempts: 0, createdAt: at, updatedAt: at };
    await f.store.transaction(state => { state.jobs[job.id] = job; });
    for (const value of [c.oidcClientSecret!, databasePassword, encodeURIComponent(databasePassword), c.secretKey.toString('base64')]) {
      for (const [url, payload] of [[`/api/v1/apps/${app.id}/jobs`, { request: `Create folders ${value}` }], [`/api/v1/jobs/${job.id}/resume`, { answer: `Use folders ${value}` }]] as const) {
        const before = await f.store.read(state => state), response = await f.server.inject({ method: 'POST', url, headers: f.headers, payload });
        assert.equal(response.statusCode, 400); assert.match(response.json().error.message, /protected.*form/i); assert.deepEqual(await f.store.read(state => state), before);
      }
    }
  } finally { await f.close(); }
});

test('quoted JSON credential assignments cannot enter durable chat or clarification replies', async () => {
  const f = await apiFixture();
  try {
    const created = await f.server.inject({ method: 'POST', url: '/api/v1/apps', headers: f.headers, payload: { name: 'Documents' } });
    const app = created.json().app as AppRecord, at = new Date().toISOString();
    const job: JobRecord = { id: randomUUID(), appId: app.id, request: 'Create document folders', stage: 'clarification', baseReleaseId: null, budgetUsd: 1, costUsd: 0, attempts: 0, createdAt: at, updatedAt: at };
    await f.store.transaction(state => { state.jobs[job.id] = job; });
    for (const name of ['clientSecret', 'privateKey', 'accessToken', 'idToken', 'token', 'secret', 'credentials', 'authorization', 'cookie']) {
      const text = `Create folders using ${JSON.stringify({ [name]: 'opaque-business-credential' })}`;
      for (const [url, payload] of [[`/api/v1/apps/${app.id}/jobs`, { request: text }], [`/api/v1/jobs/${job.id}/resume`, { answer: text }]] as const) {
        const before = await f.store.read(state => state), response = await f.server.inject({ method: 'POST', url, headers: f.headers, payload });
        assert.equal(response.statusCode, 400);
        assert.match(response.json().error.message, /protected.*form/i);
        assert.ok(!response.body.includes('opaque-business-credential'));
        assert.deepEqual(await f.store.read(state => state), before);
      }
    }
  } finally { await f.close(); }
});

test('actual model adapters redact configured secrets in raw system and JSON legacy metadata for every stage', async () => {
  const c = config(), secrets = values(c); let dispatches = 0;
  for (const provider of ['openai', 'anthropic'] as const) {
    const gateway = new ModelGateway({ catalog: catalog(provider), apiKeys: { openai: 'OpenHeaderOpaque123', anthropic: 'ClaudeHeaderOpaque123' }, redactionSecrets: secrets, fetch: async (_url, init) => {
      dispatches++; const headers = new Headers(init?.headers), body = JSON.parse(String(init?.body));
      assert.equal(headers.get(provider === 'openai' ? 'authorization' : 'x-api-key'), provider === 'openai' ? 'Bearer OpenHeaderOpaque123' : 'ClaudeHeaderOpaque123');
      const text = provider === 'openai' ? body.instructions + body.input : body.system + body.messages[0].content;
      for (const value of secrets) for (const spelling of variants(value)) assert.ok(!text.includes(spelling), 'Configured secret survived actual model request assembly');
      assert.ok(text.includes('Document management')); assert.ok(text.includes('[REDACTED]')); return receipt(provider);
    } });
    for (const stage of ['economy', 'design', 'implementation', 'review'] as const) {
      await gateway.complete({ stage, jobId: 'synthetic-legacy-job', system: `Document management ${secrets.join(' | ')}`, prompt: JSON.stringify({ app: { name: secrets[0], description: secrets.join(' | ') }, previousSpecification: { note: c.oidcClientSecret }, files: [{ content: secrets.join(' | ') }] }), maxOutputTokens: 100 }, { reserve: async () => 'synthetic-reservation', settle: async () => {} });
    }
  }
  assert.equal(dispatches, 8, 'All provider/stage checks use injected in-process responses');
});

test('configured dependencies redact legacy app metadata at real gateway dispatch and share research context redaction', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-protected-metadata-')), c = config(), secrets = values(c), store = new JsonStore(); await store.initialize();
  const envNames = ['MODEL_CATALOG_FILE', 'OPENAI_API_KEY', 'OPENAI_API_KEY_FILE', 'ANTHROPIC_API_KEY', 'ANTHROPIC_API_KEY_FILE', 'INTEGRATION_CATALOG_FILE'];
  const prior = new Map(envNames.map(name => [name, process.env[name]])), priorFetch = globalThis.fetch; let dispatches = 0;
  try {
    const modelFile = join(root, 'catalog.json'), researchFile = join(root, 'research.json'); await writeFile(modelFile, JSON.stringify(catalog()));
    const at = new Date().toISOString(), metadata = { publisher: 'Publisher', provenance: 'Official documentation', license: 'Publisher documentation terms apply', maintenance: 'Company source reviewed; SDK qualification pending', reviewedBy: 'Company', reviewedAt: at, reviewStatus: 'reviewed', qualification: 'pending_dependency_and_protocol_checks' };
    await writeFile(researchFile, JSON.stringify({ schemaVersion: 1, integrations: [{ id: 'stripe', aliases: ['unusedadapteralias'], sources: [{ url: 'https://docs.stripe.com/api', purpose: 'documentation', sdkCandidate: null, metadata }] }] }));
    process.env.MODEL_CATALOG_FILE = modelFile; process.env.INTEGRATION_CATALOG_FILE = researchFile; process.env.OPENAI_API_KEY = 'EnvironmentHeaderOpaque123'; delete process.env.OPENAI_API_KEY_FILE; delete process.env.ANTHROPIC_API_KEY; delete process.env.ANTHROPIC_API_KEY_FILE;
    globalThis.fetch = async (_url, init) => {
      dispatches++; assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer EnvironmentHeaderOpaque123');
      const body = JSON.parse(String(init?.body)); for (const value of secrets) for (const spelling of variants(value)) assert.ok(!String(body.input).includes(spelling), 'Legacy metadata leaked through configured dependency factory');
      assert.ok(String(body.input).includes('Document management')); return receipt('openai', JSON.stringify({ title: 'Document management', summary: 'Synthetic requirements', acceptanceCriteria: ['Folders preserve documents'], questions: ['Which folders?'] }));
    };
    const app: AppRecord = { id: randomUUID(), slug: 'legacy-documents', name: c.brokerToken!, description: `Document management ${secrets.join(' | ')}`, kind: 'web', status: 'building', activeReleaseId: null, url: null, previewUrl: null, runtimeFence: 1, createdAt: at, updatedAt: at };
    const job: JobRecord = { id: randomUUID(), appId: app.id, request: `Document management ${secrets.join(' | ')}`, stage: 'specification', baseReleaseId: null, costUsd: 0, budgetUsd: 1, attempts: 0, runtimeFence: 1, createdAt: at, updatedAt: at };
    await store.transaction(state => { state.apps[app.id] = app; state.jobs[job.id] = job; state.leases[job.id] = { owner: 'synthetic-worker', until: new Date(Date.now() + 90000).toISOString() }; });
    const deps = await configureDependencies(c, store), context = await deps.researchIntegrations!({ app, job, context: {}, worker: { owner: 'synthetic-worker', runtimeFence: 1 } });
    const expected = hashArtifact(redact({ appId: app.id, jobId: job.id, baseReleaseId: null, request: job.request, previousSpecification: null, answer: null, connectionInventory: null }, secrets));
    assert.equal(context?.contextHash, expected, 'Actual configured research service did not receive the full protected list'); assert.deepEqual(context?.integrations, [], 'No official network source is requested');
    const output = await deps.planAndGenerate!({ app, job, context: { integrationResearch: context }, budgetRemainingUsd: 1 }, new BudgetManager(store, 1, 5).hooks(job.id, { owner: 'synthetic-worker', runtimeFence: 1 }));
    assert.deepEqual(output.specification.questions, ['Which folders?']); assert.equal(dispatches, 1); assert.equal(await store.read(state => Object.values(state.modelCalls)[0]?.status), 'completed');
    assert.equal(await store.read(state => state.apps[app.id]?.description), app.description, 'Legacy business metadata was changed instead of protecting dispatch');
  } finally {
    globalThis.fetch = priorFetch; for (const name of envNames) { const value = prior.get(name); if (value === undefined) delete process.env[name]; else process.env[name] = value; }
    await store.close(); await rm(root, { recursive: true, force: true });
  }
});

test('nested serialized and malformed credential values cannot mutate chat or clarification state', async () => {
  const f = await apiFixture();
  try {
    const created = await f.server.inject({ method: 'POST', url: '/api/v1/apps', headers: f.headers, payload: { name: 'Documents' } });
    const app = created.json().app as AppRecord, at = new Date().toISOString();
    const job: JobRecord = { id: randomUUID(), appId: app.id, request: 'Create document folders', stage: 'clarification', baseReleaseId: null, budgetUsd: 1, costUsd: 0, attempts: 0, createdAt: at, updatedAt: at };
    await f.store.transaction(state => { state.jobs[job.id] = job; });
    const texts = [JSON.stringify({ clientSecret: ['opaque-first', 'opaque-tail'] }, null, 2), JSON.stringify({ credentials: { first: 'opaque-first', nested: ['opaque-tail'] } }), 'privateKey="opaque-first\nopaque-tail"', 'clientSecret=["opaque-first", "opaque-tail"', 'clientSecret=' + '['.repeat(33) + '"opaque-tail"' + ']'.repeat(33), 'Cookie: sid=opaque-first; session=opaque-tail', 'Set-Cookie: sid=opaque-first; session=opaque-tail; HttpOnly'];
    let serialized = JSON.stringify({ accessToken: { nested: ['opaque-first', 'opaque-tail'] }, operation: 'Document management' });
    for (let layer = 0; layer < 10; layer++) { texts.push(serialized); serialized = JSON.stringify(serialized); }
    for (const text of texts) for (const [url, payload] of [[`/api/v1/apps/${app.id}/jobs`, { request: `Create folders using ${text}` }], [`/api/v1/jobs/${job.id}/resume`, { answer: `Use ${text}` }]] as const) {
      const before = await f.store.read(state => state), response = await f.server.inject({ method: 'POST', url, headers: f.headers, payload });
      assert.equal(response.statusCode, 400, 'Serialized or malformed credentials were admitted');
      assert.match(response.json().error.message, /protected.*form/i);
      assert.ok(!response.body.includes('opaque'));
      assert.deepEqual(await f.store.read(state => state), before);
    }
  } finally { await f.close(); }
});

test('benign pretty and serialized business JSON remains accepted byte for byte', async () => {
  const f = await apiFixture();
  try {
    let description = '{\n  "operation": "Document management",\n  "secretRef": "vault-reference",\n  "publicKey": "public-material"\n}';
    for (let layer = 0; layer < 5; layer++) {
      const response = await f.server.inject({ method: 'POST', url: '/api/v1/apps', headers: f.headers, payload: { name: `Documents ${layer}`, description } });
      assert.equal(response.statusCode, 200, response.body);
      assert.equal(response.json().app.description, description);
      description = JSON.stringify(description);
    }
  } finally { await f.close(); }
});

test('real generation and gateway requests contain no serialized legacy or diagnostic credential tails', async () => {
  const protectedParts = ['diagnostic-first-opaque', 'diagnostic-last-opaque', 'legacy-first-opaque', 'legacy-last-opaque', 'multiline-first-opaque', 'multiline-last-opaque'];
  const detail = `HTTP 401 ${JSON.stringify({ clientSecret: protectedParts.slice(0, 2), operation: 'Document management' })}\nprivateKey="${protectedParts[4]}\n${protectedParts[5]}"`;
  // This is the original engine's feedback projection, before the actual
  // generation service and provider request serialization add further layers.
  const feedback = { checks: [{ name: 'unit', passed: false, detail }], secretRef: 'public-reference' };
  const answer = `Untrusted verification feedback: ${JSON.stringify(redact(feedback))}`;
  const legacy = JSON.stringify(JSON.stringify({ credentials: { first: protectedParts[2], nested: [protectedParts[3]] }, purpose: 'Document management' }));
  let dispatches = 0;
  for (const provider of ['openai', 'anthropic'] as const) {
    const gateway = new ModelGateway({ catalog: catalog(provider), apiKeys: { [provider]: 'SyntheticProviderHeader123' }, fetch: async (_url, init) => {
      dispatches++; const body = JSON.parse(String(init?.body));
      const context = provider === 'openai' ? body.instructions + body.input : body.system + body.messages[0].content;
      for (const secret of protectedParts) assert.ok(!context.includes(secret), `Credential tail reached ${provider}`);
      assert.ok(context.includes('Document management')); assert.ok(context.includes('HTTP 401')); assert.ok(context.includes('public-reference'));
      return receipt(provider, JSON.stringify({ title: 'Documents', summary: 'Synthetic requirements', acceptanceCriteria: ['Preserve folders'], questions: ['Which folders?'] }));
    } });
    const at = new Date().toISOString(), app: AppRecord = { id: randomUUID(), slug: 'legacy-documents', name: 'Documents', description: legacy, kind: 'web', status: 'building', activeReleaseId: null, url: null, previewUrl: null, createdAt: at, updatedAt: at };
    const job: JobRecord = { id: randomUUID(), appId: app.id, request: `Document management ${legacy}`, stage: 'specification', baseReleaseId: null, budgetUsd: 1, costUsd: 0, attempts: 0, createdAt: at, updatedAt: at };
    const result = await createGenerationService({ gateway })({ app, job, context: { answer }, budgetRemainingUsd: 1 }, { reserve: async () => 'synthetic-reservation', settle: async () => {} });
    assert.deepEqual(result.specification.questions, ['Which folders?']);
  }
  assert.equal(dispatches, 2, 'Only the explicit in-process provider mocks execute');
});
