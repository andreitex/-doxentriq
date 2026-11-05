import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from '../src/server.ts';
import { JsonStore } from '../src/store.ts';
import type { Config } from '../src/config.ts';
import type { StripeWebhookPolicy, StripeWebhookApproval } from '../src/stripe-webhooks.ts';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import { beginExternalEffect, recordStripeWebhook } from '../src/external-effects.ts';

const secret = 'whsec_SYNTHETIC_only_123456789', rotation = 'whsec_SYNTHETIC_rotation_987654321';
const scope = { account: null, live: false, eventTypes: ['payment_intent.succeeded'] };
type Review = { approval: StripeWebhookApproval; policy: StripeWebhookPolicy; activeApprovalId: string | null };
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-stripe-ingress-')), file = join(root, 'state.json'), store = new JsonStore(file); await store.initialize();
  const appId = randomUUID(), connectionId = randomUUID(), session = 's'.repeat(43), time = new Date().toISOString();
  const config: Config = { authMode: 'oidc', host: '127.0.0.1', port: 3000, publicOrigin: 'https://admin.example.test', appsOrigin: 'https://apps.example.test', ownerSubject: 'owner', secretKey: Buffer.alloc(32, 7), dataDir: root, workspaceDir: join(root, 'workspaces'), adminDist: join(root, 'no-build'), oidcClientId: 'test', requestLimitUsd: 1, monthlyLimitUsd: 5 };
  await store.transaction(state => {
    state.apps[appId] = { id: appId, name: 'Synthetic', slug: 'synthetic', kind: 'web', description: '', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt: time, updatedAt: time };
    state.connections[connectionId] = { id: connectionId, type: 'stripe', name: 'Stripe', status: 'configured', endpoints: ['https://api.stripe.com'], roots: [], capabilities: ['webhooks.receive'], appIds: [appId], secretRef: null, expiresAt: null, dossier: { documentation: [], provenance: 'synthetic', license: 'synthetic', reviewStatus: 'pending' }, createdAt: time };
    state.sessions[session] = { id: session, principal: { id: 'owner', name: 'Owner', localOwner: true, mfa: true, roles: ['platform-owner'] }, csrfToken: 'csrf', expiresAt: new Date(Date.now() + 3600000).toISOString(), accessExpiresAt: new Date(Date.now() + 3600000).toISOString() };
  });
  const server = await createServer(config, store), headers = { cookie: `__Host-autosoft-session=${session}`, origin: config.publicOrigin, 'x-csrf-token': 'csrf' };
  const post = (url: string, payload: unknown) => server.inject({ method: 'POST', url, headers, payload: payload as object });
  async function prepare() { const response = await post(`/api/v1/connections/${connectionId}/stripe/webhook-reviews`, { appId, scope, signingSecrets: [secret, rotation] }); assert.equal(response.statusCode, 200, response.body); return response.json() as Review; }
  const approve = (review: Review) => post(`/api/v1/stripe/webhook-reviews/${review.approval.id}/approve`, { artifactHash: review.approval.artifactHash });
  async function activate() { const review = await prepare(), response = await approve(review); assert.equal(response.statusCode, 200, response.body); return review; }
  const raw = (change = {}) => Buffer.from(JSON.stringify({ id: 'evt_synthetic', object: 'event', type: 'payment_intent.succeeded', livemode: false, created: Math.floor(Date.now() / 1000) - 1, data: { object: { id: 'pi_synthetic', customer_document: 'SYNTHETIC_PRIVATE_DOCUMENT' } }, ...change }));
  const signature = (value: Buffer, key = secret, timestamp = Math.floor(Date.now() / 1000)) => `t=${timestamp},v1=${createHmac('sha256', key).update(timestamp + '.').update(value).digest('hex')}`;
  const deliver = (review: Review, value = raw(), changes: Record<string, string | string[]> = {}, url = new URL(review.policy.url).pathname) => server.inject({ method: 'POST', url, headers: { host: 'admin.example.test', 'content-type': 'application/json', 'stripe-signature': signature(value), ...changes }, payload: value });
  const events = () => store.read(state => Object.values(state.externalEvents));
  return { root, file, store, server, config, appId, connectionId, session, headers, post, prepare, approve, activate, raw, signature, deliver, events, close: async () => { await server.close(); await store.close(); await rm(root, { recursive: true, force: true }); } };
}

test('protected exact owner review activates raw-byte metadata ingress without leaking credentials or dispatching effects', async () => {
  const f = await fixture(); try {
    const review = await f.prepare(); assert.equal(review.approval.artifactHash, hashArtifact({ schemaVersion: 1, action: 'activate', policy: review.policy, activeApprovalId: null }));
    assert.equal(review.activeApprovalId, null); assert.equal(Date.parse(review.approval.expiresAt) - Date.parse(review.approval.createdAt), 300000);
    assert.doesNotMatch(JSON.stringify(review), /whsec_|signingSecrets|secretRef/); assert.equal((await f.deliver(review)).statusCode, 404);
    assert.equal((await f.approve(review)).statusCode, 200); const body = f.raw(); assert.equal((await f.deliver(review, body)).statusCode, 200);
    const saved = await f.events(); assert.equal(saved.length, 1); assert.equal(saved[0]!.appId, f.appId); assert.equal(saved[0]!.bodySha256, createHash('sha256').update(body).digest('hex'));
    const persisted = await readFile(f.file, 'utf8'); assert.ok(!persisted.includes(secret)); assert.ok(!persisted.includes(rotation)); assert.ok(!persisted.includes('SYNTHETIC_PRIVATE_DOCUMENT'));
    assert.deepEqual(await f.store.read(state => state.externalEffects), {}); assert.equal((await f.approve(review)).statusCode, 409);
    const list = await f.server.inject({ method: 'GET', url: `/api/v1/connections/${f.connectionId}/stripe/webhooks?appId=${f.appId}`, headers: f.headers }); assert.equal(list.statusCode, 200); assert.equal(list.json().endpoints[0].activeApprovalId, review.approval.id); assert.doesNotMatch(list.body, /whsec_|signingSecrets|secretRef/);
  } finally { await f.close(); }
});

test('concurrent duplicates commit one metadata record and conflicting signed bytes do not acknowledge', async () => {
  const f = await fixture(); try { const review = await f.activate(), body = f.raw(), results = await Promise.all(Array.from({ length: 16 }, () => f.deliver(review, body))); assert.ok(results.every(item => item.statusCode === 200)); assert.equal((await f.events()).length, 1); const conflict = await f.deliver(review, f.raw({ data: { object: { id: 'pi_changed' } } })); assert.equal(conflict.statusCode, 503); assert.equal((await f.events())[0]!.objectId, 'pi_synthetic'); } finally { await f.close(); }
});

test('owner MFA, CSRF and approved HTTPS configuration are required for protected setup', async () => {
  const f = await fixture(); try {
    for (const principal of [{ id: 'sso', name: 'SSO', localOwner: false, mfa: true, roles: ['platform-admin'] }, { id: 'owner', name: 'Owner', localOwner: true, mfa: false, roles: ['platform-owner'] }]) { await f.store.transaction(state => { state.sessions[f.session]!.principal = principal; }); assert.equal((await f.post(`/api/v1/connections/${f.connectionId}/stripe/webhook-reviews`, { appId: f.appId, scope, signingSecrets: [secret] })).statusCode, 403); }
    assert.equal((await f.store.read(state => Object.keys(state.stripeWebhookEndpoints))).length, 0);
  } finally { await f.close(); }
  const g = await fixture(); try { g.config.publicOrigin = 'http://admin.example.test'; const result = await g.server.inject({ method: 'POST', url: `/api/v1/connections/${g.connectionId}/stripe/webhook-reviews`, headers: { ...g.headers, origin: g.config.publicOrigin }, payload: { appId: g.appId, scope, signingSecrets: [secret] } }); assert.equal(result.statusCode, 503); assert.equal((await g.store.read(state => Object.keys(state.stripeWebhookEndpoints))).length, 0); } finally { await g.close(); }
});

test('stale reviews and changes to registry, event scope or encrypted secret cannot activate ingress', async () => {
  for (const mode of ['expiry', 'registry', 'scope', 'secret'] as const) { const f = await fixture(); try {
    const review = await f.prepare(); await f.store.transaction(state => { const endpoint = state.stripeWebhookEndpoints[review.policy.endpointId]!; if (mode === 'expiry') { const item = state.stripeWebhookApprovals[review.approval.id]!; item.createdAt = new Date(Date.now() - 300001).toISOString(); item.expiresAt = new Date(Date.parse(item.createdAt) + 300000).toISOString(); } if (mode === 'registry') state.connections[f.connectionId]!.appIds = []; if (mode === 'scope') endpoint.policy.scope.live = true; if (mode === 'secret') state.secrets[endpoint.secretRef] = 'SYNTHETIC-CORRUPT-ENVELOPE'; }); const result = await f.approve(review); assert.notEqual(result.statusCode, 200, mode); assert.equal((await f.deliver(review)).statusCode, 404); assert.equal((await f.events()).length, 0);
  } finally { await f.close(); } }
});

test('metadata-only connection registration grants no ingress and signed foreign accounts, mode and event types reject', async () => {
  const f = await fixture(); try {
    assert.equal((await f.server.inject({ method: 'POST', url: `/webhooks/stripe/${randomUUID()}`, headers: { host: 'admin.example.test', 'content-type': 'application/json', 'stripe-signature': f.signature(f.raw()) }, payload: f.raw() })).statusCode, 404);
    const review = await f.activate(); for (const change of [{ account: 'acct_foreign' }, { livemode: true }, { type: 'invoice.paid' }, { context: 'organization' }]) assert.equal((await f.deliver(review, f.raw(change))).statusCode, 400);
    assert.equal((await f.events()).length, 0);
  } finally { await f.close(); }
});

test('raw bytes, size, host, query, encoding, media type and ambiguous signature headers are checked', async () => {
  const f = await fixture(); try { const review = await f.activate(), body = f.raw();
    const changed = Buffer.from(JSON.stringify(JSON.parse(body.toString()), null, 2)); assert.equal((await f.deliver(review, changed, { 'stripe-signature': f.signature(body) })).statusCode, 400);
    const badHeaders: Record<string, string | string[]>[] = [{ host: 'attacker.example', 'x-forwarded-host': 'admin.example.test' }, { 'content-encoding': 'gzip' }, { 'content-type': 'text/plain' }, { 'stripe-signature': [f.signature(body), f.signature(body)] }, { origin: f.config.publicOrigin }, { cookie: 'untrusted' }];
    for (const headers of badHeaders) assert.equal((await f.deliver(review, body, headers)).statusCode, 400);
    assert.equal((await f.deliver(review, body, {}, new URL(review.policy.url).pathname + '?endpoint=other')).statusCode, 400);
    const over = Buffer.alloc(1024 * 1024 + 1); assert.equal((await f.deliver(review, over)).statusCode, 413); assert.equal((await f.events()).length, 0);
  } finally { await f.close(); }
});

test('withdrawal uses exact active approval and works after registry expiry; old endpoint cannot be reactivated', async () => {
  const f = await fixture(); try { const review = await f.activate(); await f.store.transaction(state => { state.connections[f.connectionId]!.status = 'disabled'; state.apps[f.appId]!.status = 'archived'; });
    const response = await f.post(`/api/v1/stripe/webhooks/${review.policy.endpointId}/withdrawal-review`, {}); assert.equal(response.statusCode, 200); const withdrawal = response.json() as Review; assert.equal(withdrawal.activeApprovalId, review.approval.id); assert.equal(withdrawal.approval.artifactHash, hashArtifact({ schemaVersion: 1, action: 'withdraw', policy: withdrawal.policy, activeApprovalId: withdrawal.activeApprovalId }));
    assert.equal((await f.approve(withdrawal)).json().status, 'withdrawn'); assert.equal((await f.deliver(review)).statusCode, 404); assert.equal((await f.approve(review)).statusCode, 409); assert.equal((await f.approve(withdrawal)).statusCode, 409);
  } finally { await f.close(); }
});

test('withdrawal and registry or encrypted-envelope drift after signature verification block the transaction commit', async () => {
  for (const mode of ['withdrawn', 'registry', 'envelope', 'scope', 'app', 'approval'] as const) { const f = await fixture(); try {
    const review = await f.activate(), original = f.store.transaction.bind(f.store); let intercepted = false;
    f.store.transaction = async action => { if (!intercepted) { intercepted = true; await original(state => { const endpoint = state.stripeWebhookEndpoints[review.policy.endpointId]!; if (mode === 'withdrawn') endpoint.status = 'withdrawn'; if (mode === 'registry') state.connections[f.connectionId]!.capabilities = []; if (mode === 'envelope') state.secrets[endpoint.secretRef] += 'CHANGED'; if (mode === 'scope') endpoint.policy.scope.live = true; if (mode === 'app') state.apps[f.appId]!.status = 'archived'; if (mode === 'approval') state.stripeWebhookApprovals[review.approval.id]!.approvedBy = 'foreign'; }); } return original(action); };
    const result = await f.deliver(review); assert.notEqual(result.statusCode, 200, mode); assert.ok(intercepted); assert.equal((await f.events()).length, 0);
  } finally { await f.close(); } }
});

test('failed inbox persistence never acknowledges and arbitrary failure text is omitted', async () => {
  const f = await fixture(); try { const review = await f.activate(); f.store.transaction = async () => { throw new Error(`${secret} SYNTHETIC_PRIVATE_DOCUMENT`); }; const result = await f.deliver(review); assert.equal(result.statusCode, 503); assert.equal(result.body, JSON.stringify({ error: 'Stripe delivery was not recorded.' })); assert.equal((await f.events()).length, 0); } finally { await f.close(); }
});

test('retained approved endpoint and inbox dedup survive a development-store restart without implying crash durability', async () => {
  const f = await fixture(); try { const review = await f.activate(), body = f.raw(); assert.equal((await f.deliver(review, body)).statusCode, 200); const restarted = new JsonStore(f.file); await restarted.initialize(); const server = await createServer(f.config, restarted); try { const result = await server.inject({ method: 'POST', url: new URL(review.policy.url).pathname, headers: { host: 'admin.example.test', 'content-type': 'application/json', 'stripe-signature': f.signature(body, rotation) }, payload: body }); assert.equal(result.statusCode, 200); assert.equal(await restarted.read(state => Object.keys(state.externalEvents).length), 1); } finally { await server.close(); await restarted.close(); } } finally { await f.close(); }
});

test('signing-only enrollment accepts a registry needing API credentials without granting default inbox or external-effect authority', async () => {
  const f = await fixture(); try {
    await f.store.transaction(state => { state.connections[f.connectionId]!.status = 'needs_credentials'; state.connections[f.connectionId]!.capabilities.push('payments.create'); });
    const review = await f.activate(), body = f.raw();
    await assert.rejects(recordStripeWebhook(f.store, { appId: f.appId, connectionId: f.connectionId, raw: body, signature: f.signature(body), activeSecrets: [secret], scope }), /unavailable/);
    await assert.rejects(beginExternalEffect(f.store, { appId: f.appId, connectionId: f.connectionId, operationId: randomUUID(), capability: 'payments.create', requestSha256: 'a'.repeat(64) }), /unavailable/);
    assert.equal((await f.deliver(review, body)).statusCode, 200); assert.equal((await f.events()).length, 1);
    assert.equal(await f.store.read(state => state.connections[f.connectionId]!.status), 'needs_credentials'); assert.deepEqual(await f.store.read(state => state.externalEffects), {});
  } finally { await f.close(); }
});

test('disabled, expired, foreign-app registries and malformed secret forms cannot create endpoint reviews', async () => {
  for (const mode of ['disabled', 'expired', 'foreign', 'type', 'capability'] as const) { const f = await fixture(); try {
    await f.store.transaction(state => { const item = state.connections[f.connectionId]!; if (mode === 'disabled') item.status = 'disabled'; if (mode === 'expired') item.expiresAt = new Date(Date.now() - 1).toISOString(); if (mode === 'foreign') item.appIds = [randomUUID()]; if (mode === 'type') item.type = 'rest'; if (mode === 'capability') item.capabilities = []; });
    assert.equal((await f.post(`/api/v1/connections/${f.connectionId}/stripe/webhook-reviews`, { appId: f.appId, scope, signingSecrets: [secret] })).statusCode, 409); assert.equal(await f.store.read(state => Object.keys(state.stripeWebhookEndpoints).length), 0);
  } finally { await f.close(); } }
  const f = await fixture(); try {
    for (const signingSecrets of [[], [secret, secret], ['not-a-secret'], [secret, rotation, 'whsec_SYNTHETIC_third_123456789']]) assert.equal((await f.post(`/api/v1/connections/${f.connectionId}/stripe/webhook-reviews`, { appId: f.appId, scope, signingSecrets })).statusCode, 400);
    assert.equal(await f.store.read(state => Object.keys(state.stripeWebhookEndpoints).length), 0);
  } finally { await f.close(); }
});

test('an installed SPA never acknowledges unregistered, trailing or encoded webhook paths', async () => {
  const f = await fixture(); try {
    await mkdir(f.config.adminDist); await writeFile(join(f.config.adminDist, 'index.html'), '<html>SYNTHETIC-SPA</html>');
    const server = await createServer(f.config, f.store); try {
      const good = await f.activate(), endpoint = new URL(good.policy.url).pathname;
      for (const url of ['/webhooks', '/webhooks/unknown', endpoint + '/', endpoint.replace('/stripe/', '/%73tripe/'), endpoint + '%2F']) {
        const result = await server.inject({ method: 'POST', url, headers: { host: 'admin.example.test', 'content-type': 'application/json', 'stripe-signature': f.signature(f.raw()) }, payload: f.raw() });
        assert.ok(result.statusCode >= 400, `${url}: ${result.statusCode}`); assert.ok(!result.body.includes('SYNTHETIC-SPA'));
      }
      assert.equal((await server.inject({ method: 'GET', url: endpoint, headers: { host: 'admin.example.test' } })).statusCode, 404);
      const raw = f.raw(); assert.equal((await server.inject({ method: 'POST', url: endpoint, headers: { host: 'admin.example.test', 'content-type': 'application/json', 'stripe-signature': f.signature(raw) }, payload: raw })).statusCode, 200); assert.equal((await f.events()).length, 1);
    } finally { await server.close(); }
  } finally { await f.close(); }
});

test('a retained endpoint alias, mismatched approval row and malformed or future approval timestamps cannot receive delivery', async () => {
  for (const mode of ['alias', 'approval-id', 'malformed-time', 'future-time'] as const) { const f = await fixture(); try {
    const review = await f.activate(), alias = randomUUID(); await f.store.transaction(state => {
      const endpoint = state.stripeWebhookEndpoints[review.policy.endpointId]!, approval = state.stripeWebhookApprovals[review.approval.id]!;
      if (mode === 'alias') state.stripeWebhookEndpoints[alias] = structuredClone(endpoint);
      if (mode === 'approval-id') approval.id = randomUUID();
      if (mode === 'malformed-time') { approval.approvedAt = approval.consumedAt = endpoint.activatedAt = 'malformed'; }
      if (mode === 'future-time') { const now = Date.now() + 10000; approval.createdAt = new Date(now).toISOString(); approval.expiresAt = new Date(now + 300000).toISOString(); approval.approvedAt = approval.consumedAt = endpoint.activatedAt = new Date(now).toISOString(); }
    });
    const result = await f.deliver(review, f.raw(), {}, mode === 'alias' ? `/webhooks/stripe/${alias}` : new URL(review.policy.url).pathname);
    assert.notEqual(result.statusCode, 200, mode); assert.equal((await f.events()).length, 0);
  } finally { await f.close(); } }
});

test('a consumed valid owner approval remains active after its original review window expires', async () => {
  const f = await fixture(); try { const review = await f.activate(); await f.store.transaction(state => {
    const approval = state.stripeWebhookApprovals[review.approval.id]!, endpoint = state.stripeWebhookEndpoints[review.policy.endpointId]!, earlier = Date.now() - 600000;
    approval.createdAt = new Date(earlier).toISOString(); approval.expiresAt = new Date(earlier + 300000).toISOString(); approval.approvedAt = approval.consumedAt = endpoint.activatedAt = new Date(earlier + 1000).toISOString();
  }); assert.equal((await f.deliver(review)).statusCode, 200); assert.equal((await f.events()).length, 1); } finally { await f.close(); }
});

test('bounded scoped history pages retain inspection and withdrawal after more than 256 endpoints', async () => {
  const f = await fixture(); try {
    const active = await f.activate(), foreignId = randomUUID();
    await f.store.transaction(state => {
      const source = state.stripeWebhookEndpoints[active.policy.endpointId]!;
      for (let index = 0; index < 259; index++) {
        const id = randomUUID(), item = structuredClone(source);
        item.policy.endpointId = id; item.policy.url = `https://admin.example.test/webhooks/stripe/${id}`; item.secretRef = `stripe-webhook:${id}`;
        item.status = 'pending'; item.approvalId = null; item.activatedAt = item.withdrawnAt = null; item.createdAt = new Date(Date.UTC(2000, 0, 1) + Math.floor(index / 2) * 1000).toISOString();
        state.stripeWebhookEndpoints[id] = item;
      }
      const foreign = structuredClone(source); foreign.policy.endpointId = foreignId; foreign.policy.appId = randomUUID(); foreign.policy.url = `https://admin.example.test/webhooks/stripe/${foreignId}`; foreign.secretRef = `stripe-webhook:${foreignId}`;
      state.stripeWebhookEndpoints[foreignId] = foreign;
    });
    const path = `/api/v1/connections/${f.connectionId}/stripe/webhooks?appId=${f.appId}`, ids: string[] = [], counts: number[] = []; let cursor: string | null = null;
    do {
      const response: import('fastify').LightMyRequestResponse = await f.server.inject({ method: 'GET', url: path + (cursor ? `&cursor=${cursor}` : ''), headers: f.headers });
      assert.equal(response.statusCode, 200, response.body); const page: { endpoints: { policy: StripeWebhookPolicy }[]; nextCursor: string | null } = response.json(); assert.deepEqual(Object.keys(page).sort(), ['endpoints', 'nextCursor']); assert.ok(page.endpoints.length <= 100); assert.doesNotMatch(response.body, /whsec_|signingSecrets|secretRef/);
      counts.push(page.endpoints.length); ids.push(...page.endpoints.map((item: { policy: StripeWebhookPolicy }) => item.policy.endpointId)); cursor = page.nextCursor;
      if (cursor !== null) assert.equal(cursor, page.endpoints.at(-1)!.policy.endpointId);
    } while (cursor);
    assert.deepEqual(counts, [100, 100, 60]); assert.equal(new Set(ids).size, 260); assert.equal(ids.at(-1), active.policy.endpointId); assert.ok(!ids.includes(foreignId));
    const order = await f.store.read(state => ids.map(id => ({ id, time: Date.parse(state.stripeWebhookEndpoints[id]!.createdAt) })));
    for (let index = 1; index < order.length; index++) assert.ok(order[index - 1]!.time < order[index]!.time || order[index - 1]!.time === order[index]!.time && order[index - 1]!.id < order[index]!.id);
    for (const query of [`&cursor=${foreignId}`, `&cursor=${randomUUID()}`]) assert.equal((await f.server.inject({ method: 'GET', url: path + query, headers: f.headers })).statusCode, 404);
    for (const query of ['&cursor=not-a-uuid', '&limit=1000', `&cursor=${ids[0]}&cursor=${ids[1]}`]) assert.equal((await f.server.inject({ method: 'GET', url: path + query, headers: f.headers })).statusCode, 400);
    const withdrawal = await f.post(`/api/v1/stripe/webhooks/${ids.at(-1)}/withdrawal-review`, {}); assert.equal(withdrawal.statusCode, 200); assert.equal((await f.approve(withdrawal.json())).statusCode, 200);
    assert.equal(await f.store.read(state => state.stripeWebhookEndpoints[active.policy.endpointId]!.status), 'withdrawn');
  } finally { await f.close(); }
});

test('approved historical HTTPS scope can be inspected and withdrawn after origin rotation but cannot activate or deliver at the replacement origin', async () => {
  const f = await fixture(); try {
    const active = await f.activate(), pending = await f.prepare(), config = { ...f.config, publicOrigin: 'https://replacement.example.test' }, server = await createServer(config, f.store), headers = { ...f.headers, origin: config.publicOrigin };
    try {
      const list = await server.inject({ method: 'GET', url: `/api/v1/connections/${f.connectionId}/stripe/webhooks?appId=${f.appId}`, headers }); assert.equal(list.statusCode, 200); assert.ok(list.json().endpoints.some((item: { policy: StripeWebhookPolicy }) => item.policy.url === active.policy.url));
      const approvePending = await server.inject({ method: 'POST', url: `/api/v1/stripe/webhook-reviews/${pending.approval.id}/approve`, headers, payload: { artifactHash: pending.approval.artifactHash } }); assert.equal(approvePending.statusCode, 409);
      const raw = f.raw(); for (const host of ['admin.example.test', 'replacement.example.test']) assert.notEqual((await server.inject({ method: 'POST', url: new URL(active.policy.url).pathname, headers: { host, 'content-type': 'application/json', 'stripe-signature': f.signature(raw) }, payload: raw })).statusCode, 200);
      const withdrawal = await server.inject({ method: 'POST', url: `/api/v1/stripe/webhooks/${active.policy.endpointId}/withdrawal-review`, headers, payload: {} }); assert.equal(withdrawal.statusCode, 200); const review = withdrawal.json() as Review; assert.equal(review.policy.url, active.policy.url); assert.equal(review.activeApprovalId, active.approval.id);
      const approved = await server.inject({ method: 'POST', url: `/api/v1/stripe/webhook-reviews/${review.approval.id}/approve`, headers, payload: { artifactHash: review.approval.artifactHash } }); assert.equal(approved.statusCode, 200); assert.equal(approved.json().status, 'withdrawn'); assert.equal((await f.events()).length, 0);
    } finally { await server.close(); }
  } finally { await f.close(); }
});

test('retained withdrawal rejects noncanonical HTTPS URLs and corrupted consumed approval metadata', async () => {
  for (const mode of ['plaintext', 'userinfo', 'query', 'foreign-path', 'approval-id'] as const) { const f = await fixture(); try {
    const active = await f.activate(); await f.store.transaction(state => {
      const endpoint = state.stripeWebhookEndpoints[active.policy.endpointId]!, approval = state.stripeWebhookApprovals[active.approval.id]!;
      if (mode === 'plaintext') endpoint.policy.url = endpoint.policy.url.replace('https:', 'http:');
      if (mode === 'userinfo') endpoint.policy.url = endpoint.policy.url.replace('https://', 'https://user@');
      if (mode === 'query') endpoint.policy.url += '?changed=true';
      if (mode === 'foreign-path') endpoint.policy.url = `https://admin.example.test/webhooks/stripe/${randomUUID()}`;
      if (mode === 'approval-id') approval.id = randomUUID();
      approval.artifactHash = hashArtifact({ schemaVersion: 1, action: 'activate', policy: endpoint.policy, activeApprovalId: null });
    });
    const response = await f.post(`/api/v1/stripe/webhooks/${active.policy.endpointId}/withdrawal-review`, {}); assert.equal(response.statusCode, 409, mode); assert.equal(await f.store.read(state => state.stripeWebhookEndpoints[active.policy.endpointId]!.status), 'active');
  } finally { await f.close(); } }
});
