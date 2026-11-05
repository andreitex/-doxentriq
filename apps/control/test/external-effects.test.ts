import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { JsonStore } from '../src/store.ts';
import { beginExternalEffect, settleExternalEffect, recordStripeWebhook } from '../src/external-effects.ts';

async function fixture(file?: string) {
  const store = new JsonStore(file); await store.initialize(); const appId = randomUUID(), connectionId = randomUUID(), time = new Date().toISOString();
  await store.transaction(state => {
    state.apps[appId] = { id: appId, slug: 'example', name: 'Example', kind: 'web', description: '', status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt: time, updatedAt: time };
    state.connections[connectionId] = { id: connectionId, name: 'Stripe', type: 'stripe', endpoints: ['https://api.stripe.com'], roots: [], capabilities: ['payments.create', 'webhooks.receive'], appIds: [appId], secretRef: null, expiresAt: null, status: 'configured', dossier: { documentation: [], provenance: 'synthetic', license: 'synthetic', reviewStatus: 'pending' }, createdAt: time };
  });
  const input = { appId, connectionId, operationId: randomUUID(), capability: 'payments.create', requestSha256: 'a'.repeat(64) };
  const secret = 'whsec_synthetic_only_123456789';
  const webhook = (change = {}) => {
    const timestamp = Math.floor(Date.now() / 1000), raw = Buffer.from(JSON.stringify({ id: 'evt_example', object: 'event', type: 'payment_intent.succeeded', livemode: false, created: timestamp - 10, data: { object: { id: 'pi_example', customer_document: 'PRIVATE-BUSINESS-RECORD' } }, ...change }));
    return { appId, connectionId, raw, signature: `t=${timestamp},v1=${createHmac('sha256', secret).update(timestamp + '.').update(raw).digest('hex')}`, activeSecrets: [secret], scope: { account: null, live: false, eventTypes: ['payment_intent.succeeded'] } };
  };
  return { store, appId, connectionId, input, webhook };
}
test('concurrent duplicate delivery gives one persisted dispatch permit', async () => {
  const f = await fixture(), results = await Promise.all(Array.from({ length: 20 }, () => beginExternalEffect(f.store, f.input)));
  assert.equal(results.filter(item => item.dispatch).length, 1); assert.equal(new Set(results.map(item => item.record.dispatchToken)).size, 1);
  assert.equal((await f.store.read(state => Object.values(state.externalEffects))).length, 1);
});
test('dispatch fence survives a development-store restart and is never reclaimed after unknown outcome', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'autosoft-effect-'));
  try {
    const file = join(directory, 'state.json'), f = await fixture(file), first = await beginExternalEffect(f.store, f.input);
    await f.store.close(); const restarted = new JsonStore(file); await restarted.initialize();
    assert.equal((await beginExternalEffect(restarted, f.input)).dispatch, false);
    await settleExternalEffect(restarted, { id: first.record.id, dispatchToken: first.record.dispatchToken, outcome: 'unknown', receiptSha256: null });
    const retained = await beginExternalEffect(restarted, f.input); assert.equal(retained.dispatch, false); assert.equal(retained.record.state, 'unknown');
    await assert.rejects(settleExternalEffect(restarted, { id: first.record.id, dispatchToken: first.record.dispatchToken, outcome: 'succeeded', receiptSha256: 'b'.repeat(64) }));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test('changed request/capability cannot reuse an operation identity and stale results cannot settle it', async () => {
  const f = await fixture(), first = await beginExternalEffect(f.store, f.input);
  await assert.rejects(beginExternalEffect(f.store, { ...f.input, requestSha256: 'b'.repeat(64) }));
  await f.store.transaction(state => state.connections[f.connectionId]!.capabilities.push('payments.refund'));
  await assert.rejects(beginExternalEffect(f.store, { ...f.input, capability: 'payments.refund' }));
  await assert.rejects(settleExternalEffect(f.store, { id: first.record.id, dispatchToken: randomUUID(), outcome: 'succeeded', receiptSha256: 'b'.repeat(64) }));
  await assert.rejects(settleExternalEffect(f.store, { id: first.record.id, dispatchToken: first.record.dispatchToken, outcome: 'rejected', receiptSha256: null }));
  const result = await settleExternalEffect(f.store, { id: first.record.id, dispatchToken: first.record.dispatchToken, outcome: 'succeeded', receiptSha256: 'b'.repeat(64) }); assert.equal(result.state, 'succeeded');
  assert.equal((await beginExternalEffect(f.store, f.input)).dispatch, false);
  await assert.rejects(settleExternalEffect(f.store, { id: first.record.id, dispatchToken: first.record.dispatchToken, outcome: 'unknown', receiptSha256: null }));
});
test('failed state persistence cannot grant a dispatch permit', async () => {
  const f = await fixture();
  const failed = { ...f.store, mode: 'development' as const, close: async () => {}, read: f.store.read.bind(f.store), transaction: async () => { throw new Error('synthetic commit failure'); } };
  await assert.rejects(beginExternalEffect(failed, f.input));
  assert.equal((await f.store.read(state => Object.values(state.externalEffects))).length, 0);
});
test('connection expiry, disabled access, archived app and cross-app scope block a dispatch fence', async () => {
  for (const mode of ['expired', 'disabled', 'archived', 'cross-app', 'capability'] as const) {
    const f = await fixture(); await f.store.transaction(state => {
      if (mode === 'expired') state.connections[f.connectionId]!.expiresAt = new Date(Date.now() - 1).toISOString();
      if (mode === 'disabled') state.connections[f.connectionId]!.status = 'disabled';
      if (mode === 'archived') state.apps[f.appId]!.status = 'archived';
      if (mode === 'cross-app') state.connections[f.connectionId]!.appIds = [];
      if (mode === 'capability') state.connections[f.connectionId]!.capabilities = [];
    });
    await assert.rejects(beginExternalEffect(f.store, f.input)); assert.equal((await f.store.read(state => Object.values(state.externalEffects))).length, 0);
  }
});
test('Stripe metadata is committed once under concurrent duplicate webhooks and private content is omitted', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'autosoft-webhook-'));
  try {
    const file = join(directory, 'state.json'), f = await fixture(file), input = f.webhook();
    const results = await Promise.all(Array.from({ length: 12 }, () => recordStripeWebhook(f.store, input)));
    assert.equal(results.filter(result => !result.duplicate).length, 1); assert.equal((await f.store.read(state => Object.values(state.externalEvents))).length, 1);
    const persisted = await readFile(file, 'utf8'); assert.ok(!persisted.includes('PRIVATE-BUSINESS-RECORD')); assert.ok(!persisted.includes(input.activeSecrets[0]!));
    const restart = new JsonStore(file); await restart.initialize(); assert.equal((await recordStripeWebhook(restart, input)).duplicate, true);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test('invalid webhook, mismatched scope, conflicting event content and wrong connection cannot reach the inbox', async () => {
  const f = await fixture(), input = f.webhook(); await assert.rejects(recordStripeWebhook(f.store, { ...input, signature: 'invalid' }));
  assert.equal((await f.store.read(state => Object.values(state.externalEvents))).length, 0);
  await recordStripeWebhook(f.store, input); await assert.rejects(recordStripeWebhook(f.store, f.webhook({ data: { object: { id: 'pi_conflicting' } } })));
  await assert.rejects(recordStripeWebhook(f.store, { ...input, scope: { ...input.scope, live: true } }));
  await f.store.transaction(state => { state.connections[f.connectionId]!.type = 'rest'; }); await assert.rejects(recordStripeWebhook(f.store, input));
  assert.equal((await f.store.read(state => Object.values(state.externalEvents))).length, 1);
});
test('connection authorization is checked at commit after queue delay, not at webhook arrival', async () => {
  const f = await fixture();
  await f.store.transaction(state => { state.connections[f.connectionId]!.expiresAt = new Date(Date.now() + 50).toISOString(); });
  const delayed = { mode: 'development' as const, close: f.store.close.bind(f.store), read: f.store.read.bind(f.store), transaction: async <T>(action: Parameters<JsonStore['transaction']>[0]) => { await new Promise(resolve => setTimeout(resolve, 80)); return f.store.transaction(action) as Promise<T>; } };
  await assert.rejects(recordStripeWebhook(delayed, f.webhook()));
  assert.equal((await f.store.read(state => Object.values(state.externalEvents))).length, 0);
});
test('validated dispatch and settlement values are detached from caller mutations while queued', async () => {
  const f = await fixture(), expected = structuredClone(f.input), pending = beginExternalEffect(f.store, f.input);
  f.input.appId = randomUUID(); f.input.requestSha256 = 'invalid'; f.input.capability = 'not.allowed';
  const first = await pending; assert.equal(first.record.appId, expected.appId); assert.equal(first.record.requestSha256, expected.requestSha256); assert.equal(first.record.capability, expected.capability);
  const settlement = { id: first.record.id, dispatchToken: first.record.dispatchToken, outcome: 'unknown' as 'unknown' | 'succeeded', receiptSha256: null };
  const finished = settleExternalEffect(f.store, settlement); settlement.id = '0'.repeat(64); settlement.outcome = 'succeeded';
  assert.equal((await finished).state, 'unknown'); assert.equal((await beginExternalEffect(f.store, expected)).dispatch, false);
});
test('verified webhook identity and metadata are detached from caller changes while queued', async () => {
  const f = await fixture(), input = f.webhook(), pending = recordStripeWebhook(f.store, input);
  input.appId = randomUUID(); input.connectionId = randomUUID(); input.raw.fill(0); input.scope.live = true;
  const result = await pending; assert.equal(result.event.appId, f.appId); assert.equal(result.event.connectionId, f.connectionId); assert.equal(result.event.objectId, 'pi_example'); assert.equal(result.event.live, false);
});
