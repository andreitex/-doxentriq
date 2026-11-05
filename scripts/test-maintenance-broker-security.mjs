import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { TrustedBrokerHttp } from '../packages/core/src/trusted-broker-http.ts';
import { requestDailySecurity, FAILURE, REQUEST_LIMIT, REPORT_LIMIT, TIMEOUT_MS } from './maintenance-broker-security.mjs';

const token = 'synthetic-protected-broker-token';
const request = { appId: 'app-one', releaseId: 'release-one', commit: 'a'.repeat(40), images: { web: 'example/app@sha256:' + 'b'.repeat(64) } };
const report = { subject: 'app', appId: request.appId, releaseId: request.releaseId, status: 'passed', coverage: [{ name: 'exact-source', status: 'passed' }] };
function fixed(error) {
  assert.ok(error instanceof Error); assert.equal(error.message, FAILURE.trimEnd());
  assert.equal(Object.hasOwn(error, 'cause'), false); assert.equal(Object.hasOwn(error, 'input'), false);
  assert.equal(Object.hasOwn(error, 'confirmedRejected'), false); return true;
}
async function denied(fetchImpl) {
  let calls = 0;
  await assert.rejects(requestDailySecurity(TrustedBrokerHttp, request, token, async (...args) => { calls++; return fetchImpl(...args); }), fixed);
  assert.equal(calls, 1);
}

test('actual shared transport sends one fixed TLS request with exact scope and deadline', async () => {
  let calls = 0;
  const start = Date.now();
  const text = await requestDailySecurity(TrustedBrokerHttp, request, token, async (url, init) => {
    calls++; assert.equal(String(url), 'https://broker:8090/v1/security');
    assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'error');
    assert.deepEqual(init.headers, { 'content-type': 'application/json', authorization: `Bearer ${token}` });
    assert.deepEqual(JSON.parse(init.body), request); assert.equal(init.signal.aborted, false);
    return Response.json(report);
  });
  assert.equal(calls, 1); assert.deepEqual(JSON.parse(text), report);
  assert.equal(TIMEOUT_MS, 300000); assert.ok(Date.now() - start < TIMEOUT_MS);
});

test('ordinary success admits genuine reports above the old core 64KiB default up to 4MiB', async () => {
  const large = { ...report, detail: 'x'.repeat(2 << 20) };
  assert.deepEqual(JSON.parse(await requestDailySecurity(TrustedBrokerHttp, request, token, async () => Response.json(large))), large);
  assert.equal(REPORT_LIMIT, 4 << 20);
});

test('infinite streamed success is cancelled at its first excess chunk without retry', async () => {
  let pulls = 0, cancelled = false;
  const stream = new ReadableStream({ pull(controller) { pulls++; controller.enqueue(new Uint8Array(REPORT_LIMIT + 1)); }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
  await denied(async () => new Response(stream)); assert.equal(pulls, 1); assert.equal(cancelled, true);
});

test('negative responses retain the shared 64KiB refusal bound and expose no body', async () => {
  let cancelled = false;
  const stream = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(65537)); }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
  await denied(async () => new Response(stream, { status: 409 })); assert.equal(cancelled, true);
  await denied(async () => Response.json({ rejectedBeforeExecution: true, message: token + ' private-value' }, { status: 409 }));
});

test('missing, malformed, excessive and mismatched content lengths reject', async () => {
  for (const length of ['-1', '01', '1e6', String(REPORT_LIMIT + 1), '3'])
    await denied(async () => new Response('{}', { headers: { 'content-length': length } }));
  await denied(async () => new Response(null));
});

test('fatal UTF8, malformed JSON and non-object receipts cannot become a report', async () => {
  for (const value of [new Uint8Array([255]), '{', 'null', '[]', 'true', '"private-value"'])
    await denied(async () => new Response(value));
});

test('HTTP200 is required even when another status supplies a plausible object', async () => {
  for (const status of [201, 202, 204, 301, 307, 401, 500])
    await denied(async () => status === 204 ? new Response(null, { status }) : Response.json(report, { status }));
});

test('redirected or foreign final authority never receives report authority', async () => {
  for (const mode of ['redirected', 'foreign']) {
    const value = Response.json(report);
    Object.defineProperty(value, mode === 'redirected' ? 'redirected' : 'url', { value: mode === 'redirected' ? true : 'https://foreign.example/private' });
    await denied(async () => value);
  }
});

test('network and stream failures discard forged rejection and hostile raw error data', async () => {
  await denied(async () => { throw Object.assign(new Error(token), { confirmedRejected: true, input: token, cause: token }); });
  await denied(async () => new Response(new ReadableStream({ start(controller) { controller.error(new Error(token)); } })));
});

test('oversized request or malformed protected token is rejected before dispatch', async () => {
  let calls = 0; const fetchImpl = async () => { calls++; return Response.json(report); };
  for (const value of [null, [], { field: 'x'.repeat(REQUEST_LIMIT) }])
    await assert.rejects(requestDailySecurity(TrustedBrokerHttp, value, token, fetchImpl), fixed);
  for (const value of ['', 'x'.repeat(4097), 'secret\nvalue', 'secret value'])
    await assert.rejects(requestDailySecurity(TrustedBrokerHttp, request, value, fetchImpl), fixed);
  assert.equal(calls, 0);
});

test('native entrypoint has the fixed installed transport/secret path and fixed failure output', () => {
  const source = readFileSync(new URL('./maintenance-broker-security.mjs', import.meta.url), 'utf8');
  assert.match(source, /await import\('\/app\/packages\/core\/src\/trusted-broker-http\.ts'\)/);
  assert.match(source, /const file = '\/run\/secrets\/broker-token'/);
  assert.match(source, /process\.stderr\.write\(FAILURE\)/);
  assert.doesNotMatch(source, /process\.env|console\.|response\.text\(|\.message\b|\.confirmedRejected\b/);
});
