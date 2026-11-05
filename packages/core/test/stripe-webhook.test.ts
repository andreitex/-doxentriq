import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createHash } from 'node:crypto';
import { verifyStripeWebhook } from '../src/stripe-webhook.ts';
const secret = 'whsec_synthetic_only_123456789', other = 'whsec_synthetic_rotation_987654321', now = 1791734400;
const scope = { account: null, live: false, eventTypes: ['payment_intent.succeeded'] };
const body = (change = {}) => Buffer.from(JSON.stringify({ id: 'evt_example', object: 'event', type: 'payment_intent.succeeded', livemode: false, created: now - 20, data: { object: { id: 'pi_example', secret_business_value: 'private' } }, ...change }));
const sign = (raw: Buffer, timestamp = now, key = secret) => `t=${timestamp},v1=${createHmac('sha256', key).update(timestamp + '.').update(raw).digest('hex')}`;

test('Stripe signature authenticates exact raw bytes and returns metadata without business content', () => {
  const raw = body(), event = verifyStripeWebhook(raw, sign(raw), [secret], scope, now);
  assert.equal(event.eventId, 'evt_example'); assert.equal(event.objectId, 'pi_example'); assert.equal(event.bodySha256, createHash('sha256').update(raw).digest('hex'));
  assert.ok(!JSON.stringify(event).includes('private'));
  const reformatted = Buffer.from(JSON.stringify(JSON.parse(raw.toString()), null, 2));
  assert.throws(() => verifyStripeWebhook(reformatted, sign(raw), [secret], scope, now));
});
test('Stripe active-secret rotation accepts only v1 and rejects mismatched signatures', () => {
  const raw = body(); assert.equal(verifyStripeWebhook(raw, sign(raw, now, other), [secret, other], scope, now).eventId, 'evt_example');
  const signature = sign(raw).replace('v1=', 'v0='); assert.throws(() => verifyStripeWebhook(raw, signature, [secret], scope, now));
  assert.throws(() => verifyStripeWebhook(raw, sign(raw, now, other), [secret], scope, now));
  assert.equal(verifyStripeWebhook(raw, sign(raw) + ',v1=' + '0'.repeat(64), [secret], scope, now).eventId, 'evt_example');
});
test('Stripe timestamp tolerance rejects expired and future replays and ambiguous timestamps', () => {
  const raw = body();
  for (const timestamp of [now - 301, now + 301]) assert.throws(() => verifyStripeWebhook(raw, sign(raw, timestamp), [secret], scope, now));
  for (const timestamp of [now - 300, now + 300]) assert.equal(verifyStripeWebhook(raw, sign(raw, timestamp), [secret], scope, now).eventId, 'evt_example');
  for (const signature of [sign(raw) + `,t=${now}`, sign(raw).replace(`t=${now}`, `t=0${now}`), sign(raw) + '\n']) assert.throws(() => verifyStripeWebhook(raw, signature, [secret], scope, now));
});
test('Stripe account, live mode, event allowlist and event format are separate scoped checks', () => {
  for (const change of [{ account: 'acct_foreign' }, { livemode: true }, { type: 'payment_intent.payment_failed' }, { context: 'organization' }, { object: 'v2.core.event' }, { id: '../evt' }, { data: { object: { id: '../pi' } } }]) {
    const raw = body(change); assert.throws(() => verifyStripeWebhook(raw, sign(raw), [secret], scope, now));
  }
  const raw = body({ account: 'acct_allowed' }); assert.equal(verifyStripeWebhook(raw, sign(raw), [secret], { ...scope, account: 'acct_allowed' }, now).account, 'acct_allowed');
});
test('Stripe bounded inputs and malformed UTF-8 or JSON fail without exposing private input', () => {
  for (const raw of [Buffer.alloc(0), Buffer.alloc(1024 * 1024 + 1), Buffer.from([0xff]), Buffer.from('private invalid JSON')]) {
    assert.throws(() => verifyStripeWebhook(raw, sign(raw), [secret], scope, now), error => error instanceof Error && error.message === 'Stripe webhook verification or configured event scope failed.');
  }
  const raw = body();
  for (const signature of ['x'.repeat(4097), sign(raw).replace(/v1=.*/, 'v1=invalid'), sign(raw) + ',bad', sign(raw) + ',v1=' + '0'.repeat(64).toUpperCase().replace('0', 'A')]) assert.throws(() => verifyStripeWebhook(raw, signature, [secret], scope, now));
});
test('Stripe unsafe configuration cannot silently disable verification or replay limits', () => {
  const raw = body();
  for (const secrets of [[], [secret, secret], [secret, other, 'whsec_synthetic_third_123456789'], ['private']]) assert.throws(() => verifyStripeWebhook(raw, sign(raw), secrets, scope, now));
  for (const badNow of [-1, NaN, Infinity, now + 0.5]) assert.throws(() => verifyStripeWebhook(raw, sign(raw), [secret], scope, badNow));
  assert.throws(() => verifyStripeWebhook(raw, sign(raw), [secret], { ...scope, eventTypes: [] }, now));
  assert.throws(() => verifyStripeWebhook(raw, sign(raw), [secret], { ...scope, eventTypes: [...scope.eventTypes, ...scope.eventTypes] }, now));
});
