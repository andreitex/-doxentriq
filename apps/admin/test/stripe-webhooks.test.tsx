import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import type { AppRecord, ConnectionRecord } from '../src/types';
import Connections, { stripeWebhookRegistration } from '../src/views/Connections';
import StripeWebhooks, { appendStripeEndpointPage, eligibleStripeApp, prepareStripeReview, readStripeEndpointPage, stripeArtifactHash, stripeFenceResolved, stripeSetupBody, StripeSubmissionUncertain, submitStripeReview, validateStripeEndpoints, validateStripeReview, type StripeEndpoint, type StripeReview, type StripeSetup } from '../src/components/StripeWebhooks';

const at = Date.parse('2030-01-01T12:00:00.000Z'), origin = 'https://admin.example.test';
const app: AppRecord = { id: randomUUID(), name: 'Finance', slug: 'finance', description: '', kind: 'web', status: 'published', activeReleaseId: null, url: null, previewUrl: null, createdAt: new Date(at).toISOString(), updatedAt: new Date(at).toISOString() };
const connection: ConnectionRecord = { id: randomUUID(), type: 'stripe', name: 'Stripe finance', status: 'needs_credentials', endpoints: [], roots: [], capabilities: ['webhooks.receive'], appIds: [app.id], secretRef: null, expiresAt: null, dossier: { documentation: [], provenance: 'Company registration', license: '', reviewStatus: 'pending' }, createdAt: new Date(at).toISOString() };
const input: StripeSetup = { appId: app.id, account: 'acct_fixture', live: false, events: 'invoice.paid\ncustomer.updated', signingSecret: 'whsec_1234567890abcdefghijkl', previousSigningSecret: '' };
function review(action: 'activate' | 'withdraw' = 'activate', bound = connection): { review: StripeReview; endpoint: StripeEndpoint } {
  const policy = { schemaVersion: 1 as const, provider: 'stripe' as const, payloadFormat: 'api_v1_snapshot' as const, endpointId: randomUUID(), appId: app.id, connectionId: connection.id, url: '', registryHash: hashArtifact(bound), credentialBinding: 'a'.repeat(64), credentialEnvelopeHash: 'b'.repeat(64), scope: { account: input.account, live: false, eventTypes: ['invoice.paid', 'customer.updated'] } }; policy.url = `${origin}/webhooks/stripe/${policy.endpointId}`;
  const activeApprovalId = action === 'withdraw' ? randomUUID() : null;
  const approval = { id: randomUUID(), endpointId: policy.endpointId, appId: app.id, connectionId: connection.id, action, artifactHash: hashArtifact({ schemaVersion: 1, action, policy, activeApprovalId }), createdAt: new Date(at).toISOString(), expiresAt: new Date(at + 300000).toISOString(), approvedAt: null, approvedBy: null, consumedAt: null };
  return { review: { policy, approval, activeApprovalId, ...(action === 'activate' ? { status: 'pending' as const } : {}) }, endpoint: { policy, status: action === 'withdraw' ? 'active' : 'pending', activeApprovalId, activatedAt: action === 'withdraw' ? new Date(at - 500000).toISOString() : null, withdrawnAt: null } };
}
const clone = <T,>(value: T): T => structuredClone(value);
function accepted(value: StripeReview, endpoint?: StripeEndpoint) { const approvedAt = new Date(at + 1000).toISOString(); return { policy: value.policy, status: value.approval.action === 'activate' ? 'active' : 'withdrawn', activeApprovalId: value.approval.action === 'activate' ? value.approval.id : endpoint!.activeApprovalId, approval: { ...value.approval, approvedAt, consumedAt: approvedAt, approvedBy: 'permanent-owner' } }; }

test('signing-only eligible scope needs no generic API credential, and rejects missing or stale app rights', () => {
  assert.equal(eligibleStripeApp(connection, app, at), true);
  for (const changed of [{ ...connection, status: 'disabled' as const }, { ...connection, capabilities: ['payments.write'] }, { ...connection, appIds: [] }, { ...connection, expiresAt: new Date(at).toISOString() }, { ...connection, type: 'rest' as const }]) assert.equal(eligibleStripeApp(changed, app, at), false);
  assert.equal(eligibleStripeApp(connection, { ...app, status: 'archived' }, at), false); assert.equal(eligibleStripeApp(connection, undefined, at), false);
  assert.throws(() => stripeSetupBody(input, connection, app, false, at), /owner/);
});
test('setup contains exact account, mode and one or two distinct password secrets with no endpoint URL override', () => {
  const body = stripeSetupBody({ ...input, previousSigningSecret: 'whsec_abcdefghijkl1234567890', live: true }, connection, app, true, at);
  assert.deepEqual(Object.keys(body).sort(), ['appId', 'scope', 'signingSecrets']); assert.equal(body.signingSecrets.length, 2); assert.deepEqual(body.scope, { account: 'acct_fixture', live: true, eventTypes: ['invoice.paid', 'customer.updated'] });
  assert.equal(stripeSetupBody({ ...input, account: '' }, connection, app, true, at).scope.account, null);
  for (const changed of [{ ...input, signingSecret: 'sk_provider_secret' }, { ...input, previousSigningSecret: input.signingSecret }, { ...input, account: 'foreign_account' }, { ...input, events: '*' }, { ...input, events: 'invoice.paid,invoice.paid' }, { ...input, events: '' }, { ...input, events: Array.from({ length: 65 }, (_, n) => `invoice.event_${n}`).join(',') }]) assert.throws(() => stripeSetupBody(changed, connection, app, true, at));
});
test('canonical artifact hashing matches backend and review verification binds registry, exact URL, event scope and action', async () => {
  const value = review().review; assert.equal(await stripeArtifactHash(connection), hashArtifact(connection));
  assert.deepEqual(await validateStripeReview(value, connection, app.id, origin, 'activate', at), value);
  const mutants: StripeReview[] = [];
  for (const key of ['registryHash', 'credentialBinding', 'credentialEnvelopeHash'] as const) { const changed = clone(value); changed.policy[key] = 'c'.repeat(64); mutants.push(changed); }
  const foreign = clone(value); foreign.policy.url = `https://other.example.test/webhooks/stripe/${value.policy.endpointId}`; mutants.push(foreign);
  const query = clone(value); query.policy.url += '?unsafe=1'; mutants.push(query);
  const thin = clone(value); (thin.policy as { payloadFormat: string }).payloadFormat = 'api_v2_thin'; mutants.push(thin);
  const wrongApp = clone(value); wrongApp.policy.appId = randomUUID(); mutants.push(wrongApp);
  for (const changed of mutants) await assert.rejects(validateStripeReview(changed, connection, app.id, origin, 'activate', at));
  await assert.rejects(validateStripeReview(value, connection, app.id, 'http://admin.example.test', 'activate', at));
  await assert.rejects(validateStripeReview(value, connection, app.id, origin, 'activate', at, undefined, { ...value.policy.scope, live: true }));
});
test('only an exact unconsumed five-minute review is eligible, including created-at and strict null fields', async () => {
  const value = review().review;
  for (const update of [{ createdAt: new Date(at + 1).toISOString() }, { expiresAt: new Date(at + 300001).toISOString() }, { approvedAt: new Date(at).toISOString() }, { approvedBy: 'owner' }, { consumedAt: new Date(at).toISOString() }, { action: 'withdraw' }, { artifactHash: 'd'.repeat(64) }]) { const changed = clone(value); Object.assign(changed.approval, update); await assert.rejects(validateStripeReview(changed, connection, app.id, origin, 'activate', at)); }
  await assert.rejects(validateStripeReview(value, connection, app.id, origin, 'activate', at + 300000));
  await assert.rejects(validateStripeReview({ ...value, signingSecrets: [input.signingSecret] }, connection, app.id, origin, 'activate', at));
});
test('exact retained withdrawal remains reviewable after registry, app scope and credential status change', async () => {
  const value = review('withdraw'), disabled = { ...connection, status: 'disabled' as const, appIds: [], capabilities: [], expiresAt: new Date(at - 1).toISOString() };
  assert.equal(eligibleStripeApp(disabled, { ...app, status: 'archived' }, at), false);
  assert.deepEqual(await validateStripeReview(value.review, disabled, app.id, origin, 'withdraw', at, value.endpoint), value.review);
  await assert.rejects(validateStripeReview({ ...value.review, activeApprovalId: randomUUID() }, disabled, app.id, origin, 'withdraw', at, value.endpoint));
  await assert.rejects(validateStripeReview(value.review, disabled, app.id, origin, 'withdraw', at, { ...value.endpoint, status: 'withdrawn' }));
  const changed = clone(value.endpoint); changed.policy.scope.live = true; await assert.rejects(validateStripeReview(value.review, disabled, app.id, origin, 'withdraw', at, changed));
});
test('retained endpoint inspection accepts historical registry but rejects foreign, secret-bearing or inconsistent state', () => {
  const value = review('withdraw').endpoint, changedRegistry = { ...connection, name: 'New registry snapshot' };
  assert.deepEqual(validateStripeEndpoints({ endpoints: [value], nextCursor: null }, changedRegistry.id, app.id, origin), { endpoints: [value], nextCursor: null });
  for (const changed of [{ ...value, activeApprovalId: null }, { ...value, withdrawnAt: new Date(at).toISOString() }, { ...value, activatedAt: null }, { ...value, secretRef: 'private-ref' }, { ...value, policy: { ...value.policy, appId: randomUUID() } }]) assert.throws(() => validateStripeEndpoints({ endpoints: [changed], nextCursor: null }, connection.id, app.id, origin));
  assert.throws(() => validateStripeEndpoints({ endpoints: [value, value], nextCursor: null }, connection.id, app.id, origin));
  assert.throws(() => validateStripeEndpoints({ endpoints: null, nextCursor: null }, connection.id, app.id, origin));
});
test('HTTPS origin validation refuses secret dispatch on HTTP, credentials, path or noncanonical origins and clears secrets', async () => {
  for (const unsafe of ['http://admin.example.test', 'https://user:password@admin.example.test', `${origin}/`, `${origin}/private`, `${origin}?secret=value`, `${origin}#fragment`, 'https://admin.example.test:443', 'https://ADMIN.example.test']) {
    let calls = 0, cleared = 0, secret = input.signingSecret;
    await assert.rejects(prepareStripeReview(input, connection, app, true, unsafe, () => { secret = ''; cleared++; }, async () => { calls++; return review().review; }, () => at));
    assert.equal(calls, 0); assert.equal(cleared, 1); assert.equal(secret, '');
  }
});
test('historical HTTPS endpoint remains withdrawable after admin origin migration while activation stays current', async () => {
  const current = 'https://new-admin.example.test', value = review('withdraw');
  assert.deepEqual(validateStripeEndpoints({ endpoints: [value.endpoint], nextCursor: null }, connection.id, app.id, current).endpoints, [value.endpoint]);
  assert.deepEqual(await validateStripeReview(value.review, connection, app.id, current, 'withdraw', at, value.endpoint), value.review);
  const stopped = await submitStripeReview(value.review, connection, app.id, current, true, value.endpoint, async () => accepted(value.review, value.endpoint), () => at + 1000);
  assert.equal(stopped.status, 'withdrawn'); assert.equal(stopped.policy.url, value.endpoint.policy.url);
  await assert.rejects(validateStripeReview(review().review, connection, app.id, current, 'activate', at));
  for (const url of [`http://old.example.test/webhooks/stripe/${value.endpoint.policy.endpointId}`, `https://user:password@old.example.test/webhooks/stripe/${value.endpoint.policy.endpointId}`, `${value.endpoint.policy.url}?unsafe=1`, `${value.endpoint.policy.url}#fragment`, `${value.endpoint.policy.url}/`, value.endpoint.policy.url.replace('/webhooks/', '/%77ebhooks/')]) assert.throws(() => validateStripeEndpoints({ endpoints: [{ ...value.endpoint, policy: { ...value.endpoint.policy, url } }], nextCursor: null }, connection.id, app.id, current));
});
test('bounded endpoint pages keep more than 256 historical endpoints usable and deny inconsistent cursor or overlap', async () => {
  const rows = Array.from({ length: 259 }, () => review('withdraw').endpoint); let collected: StripeEndpoint[] = [], cursor: string | null = null;
  for (let offset = 0; offset < rows.length; offset += 100) {
    const endpoints = rows.slice(offset, offset + 100), nextCursor = offset + 100 < rows.length ? endpoints.at(-1)!.policy.endpointId : null;
    const page = await readStripeEndpointPage(connection.id, app.id, origin, cursor, async path => { assert.equal(path.includes('&cursor='), cursor !== null); if (cursor) assert.ok(path.endsWith(`&cursor=${cursor}`)); return { endpoints, nextCursor }; });
    collected = appendStripeEndpointPage(collected, page, cursor); cursor = page.nextCursor;
  }
  assert.equal(collected.length, 259); assert.equal(collected.at(-1)!.status, 'active'); assert.equal(cursor, null);
  assert.throws(() => validateStripeEndpoints({ endpoints: rows.slice(0, 101), nextCursor: null }, connection.id, app.id, origin));
  assert.throws(() => validateStripeEndpoints({ endpoints: rows.slice(0, 100), nextCursor: randomUUID() }, connection.id, app.id, origin));
  assert.throws(() => validateStripeEndpoints({ endpoints: rows.slice(0, 1), nextCursor: rows[0]!.policy.endpointId }, connection.id, app.id, origin));
  assert.throws(() => appendStripeEndpointPage(collected, { endpoints: [rows[0]!], nextCursor: null }, collected.at(-1)!.policy.endpointId));
  assert.throws(() => appendStripeEndpointPage(collected, { endpoints: [review('withdraw').endpoint], nextCursor: null }, randomUUID()));
  const afterApproval = review('withdraw').endpoint;
  assert.deepEqual(appendStripeEndpointPage([afterApproval], { endpoints: rows.slice(0, 100), nextCursor: rows[99]!.policy.endpointId }, null), rows.slice(0, 100));
});
test('old app or owner session responses cannot return usable inspection or prepared review evidence', async () => {
  let current = true, resolve!: (value: unknown) => void, cleared = 0;
  const call = () => new Promise<unknown>(done => { resolve = done; });
  const inspecting = readStripeEndpointPage(connection.id, app.id, origin, null, call, () => current);
  current = false; resolve({ endpoints: [review('withdraw').endpoint], nextCursor: null }); await assert.rejects(inspecting);
  current = true;
  const preparing = prepareStripeReview(input, connection, app, true, origin, () => { cleared++; }, call, () => at, () => current);
  current = false; resolve(review().review); await assert.rejects(preparing); assert.equal(cleared, 1);
});
test('webhook registration fixes exact metadata scope without hidden API credentials, endpoints or outbound capabilities', () => {
  const requested = { name: ' Webhook metadata ', appIds: [app.id], credentials: { token: 'SECRET' }, endpoints: ['https://provider.example.test'], roots: ['/secret'], capabilities: ['payments.write'] };
  let calls = 0;
  const register = (selected: typeof requested, owner: boolean, apps: AppRecord[]) => { const body = stripeWebhookRegistration(selected, apps, owner); calls++; return body; };
  const body = register(requested, true, [app]);
  assert.deepEqual(body, { name: 'Webhook metadata', type: 'stripe', endpoints: [], roots: [], capabilities: ['webhooks.receive'], appIds: [app.id] });
  assert.doesNotMatch(JSON.stringify(body), /SECRET|provider\.example|payments\.write|credentials/); assert.equal(calls, 1);
  const denied: [typeof requested, boolean, AppRecord[]][] = [[requested, false, [app]], [requested, true, [{ ...app, status: 'archived' }]], [{ ...requested, appIds: [] }, true, [app]], [{ ...requested, appIds: [randomUUID()] }, true, [app]], [{ ...requested, appIds: [app.id, app.id] }, true, [app]]];
  for (const [selected, owner, apps] of denied) assert.throws(() => register(selected, owner, apps));
  assert.equal(calls, 1);
});
test('secret fields are cleared in finally for success, transport failure, malformed response and owner denial', async () => {
  for (const mode of ['success', 'transport', 'malformed', 'owner'] as const) {
    let cleared = 0, calls = 0; const value = review().review;
    const result = prepareStripeReview(input, connection, app, mode !== 'owner', origin, () => { cleared++; }, async (path, options) => { calls++; assert.match(path, /webhook-reviews$/); assert.deepEqual(options?.body, stripeSetupBody(input, connection, app, true, at)); if (mode === 'transport') throw new Error(input.signingSecret); return mode === 'malformed' ? { signingSecrets: [input.signingSecret] } : value; }, () => at);
    if (mode === 'success') await result; else await assert.rejects(result);
    assert.equal(cleared, 1); assert.equal(calls, mode === 'owner' ? 0 : 1);
  }
});
test('invalid review and missing owner/MFA refuse approval before any API request', async () => {
  let calls = 0; const value = review().review, call = async () => { calls++; return {}; };
  await assert.rejects(submitStripeReview(value, connection, app.id, origin, false, undefined, call, () => at));
  await assert.rejects(submitStripeReview(value, connection, app.id, origin, true, undefined, call, () => at + 300000));
  assert.equal(calls, 0);
});
test('owner or app epoch change during asynchronous review validation cancels unsent approval', async () => {
  const value = review().review; let current = true, calls = 0;
  await assert.rejects(submitStripeReview(value, connection, app.id, origin, true, undefined, async () => { calls++; return accepted(value); }, () => { current = false; return at; }, () => current));
  assert.equal(calls, 0);
  current = true;
  const result = await submitStripeReview(value, connection, app.id, origin, true, undefined, async () => { calls++; return accepted(value); }, () => at + 1000, () => current);
  assert.equal(calls, 1); assert.equal(result.status, 'active');
});
test('lost activation response is uncertain and the same approval cannot be automatically replayed', async () => {
  const value = review().review; let calls = 0; const call = async () => { calls++; throw new Error(input.signingSecret); };
  await assert.rejects(submitStripeReview(value, connection, app.id, origin, true, undefined, call, () => at), StripeSubmissionUncertain);
  await assert.rejects(submitStripeReview(value, connection, app.id, origin, true, undefined, call, () => at), StripeSubmissionUncertain);
  assert.equal(calls, 1);
});
test('activation confirmation must match consumed receipt and exact active approval, never merely an HTTP success', async () => {
  const value = review().review; let calls = 0;
  const endpoint = await submitStripeReview(value, connection, app.id, origin, true, undefined, async (path, options) => { calls++; assert.equal(path, `/stripe/webhook-reviews/${value.approval.id}/approve`); assert.deepEqual(options, { method: 'POST', body: { artifactHash: value.approval.artifactHash } }); return accepted(value); }, () => at + 1000);
  assert.equal(calls, 1); assert.equal(endpoint.status, 'active'); assert.equal(endpoint.activeApprovalId, value.approval.id);
  for (const field of ['activeApprovalId', 'status', 'consumedAt', 'policy'] as const) {
    const separate = review().review, returned = accepted(separate);
    if (field === 'activeApprovalId') returned.activeApprovalId = randomUUID(); else if (field === 'status') returned.status = 'pending'; else if (field === 'consumedAt') returned.approval.consumedAt = null as unknown as string; else returned.policy = { ...returned.policy, scope: { ...returned.policy.scope, live: true } };
    await assert.rejects(submitStripeReview(separate, connection, app.id, origin, true, undefined, async () => returned, () => at + 1000), StripeSubmissionUncertain);
  }
});
test('withdrawal dispatch stops only the reviewed historical endpoint and requires exact consumed response', async () => {
  const value = review('withdraw'), changed = { ...connection, status: 'disabled' as const, appIds: [] }; let calls = 0;
  const endpoint = await submitStripeReview(value.review, changed, app.id, origin, true, value.endpoint, async (_path, options) => { calls++; assert.deepEqual(options?.body, { artifactHash: value.review.approval.artifactHash }); return accepted(value.review, value.endpoint); }, () => at + 1000);
  assert.equal(calls, 1); assert.equal(endpoint.status, 'withdrawn'); assert.equal(endpoint.activeApprovalId, value.endpoint.activeApprovalId); assert.equal(endpoint.policy.endpointId, value.endpoint.policy.endpointId);
});
test('uncertain action resolves only by retained status confirmation or expiry with successful explicit inspection', () => {
  const value = review('withdraw'), fence = { endpointId: value.endpoint.policy.endpointId, action: 'withdraw' as const, expiresAt: new Date(at + 300000).toISOString() };
  assert.equal(stripeFenceResolved(fence, [value.endpoint], at), false);
  assert.equal(stripeFenceResolved(fence, [{ ...value.endpoint, status: 'withdrawn', withdrawnAt: new Date(at).toISOString() }], at), true);
  assert.equal(stripeFenceResolved(fence, [], at + 300000), true);
});
test('owner/MFA UI gates all secret and approval controls; signing fields remain password-only', () => {
  const blocked = renderToStaticMarkup(createElement(StripeWebhooks, { connection, apps: [app], selectedApp: app, canProvision: false }));
  assert.match(blocked, /permanent local owner with MFA/); assert.doesNotMatch(blocked, /type="password"|Review exact webhook scope|Inspect retained endpoints/);
  const allowed = renderToStaticMarkup(createElement(StripeWebhooks, { connection, apps: [app], selectedApp: app, canProvision: true }));
  assert.equal((allowed.match(/type="password"/g) ?? []).length, 2); assert.equal((allowed.match(/autoComplete="new-password"/g) ?? []).length, 2);
  assert.match(allowed, /API v2 thin events are unsupported/); assert.match(allowed, /separate installation check/); assert.match(allowed, /does not send payments or email/);
  assert.doesNotMatch(allowed, new RegExp(input.signingSecret)); assert.match(allowed, /disabled=""[^>]*>Review exact webhook scope/);
});
test('Connections exposes protected Stripe controls and retained selected archived apps even outside current registry', () => {
  const archived = { ...app, status: 'archived' as const }, old = { ...connection, appIds: [], status: 'disabled' as const };
  const html = renderToStaticMarkup(createElement(Connections, { apps: [], selectedApp: archived, connections: [old], loading: false, onRetry() {}, canProvision: true }));
  assert.match(html, /Stripe webhook endpoints/); assert.match(html, /Finance · setup unavailable/); assert.match(html, /Retained endpoints can still be inspected and withdrawn/);
});
