import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { callback, login } from '../web/auth.js';
import { createApplication } from '../src/http.mjs';
import { HttpError } from '../src/domain.mjs';

const config = { clientId: 'app-synthetic', authorizationEndpoint: 'https://identity.example/realms/app/protocol/openid-connect/auth', tokenEndpoint: 'https://identity.example/realms/app/protocol/openid-connect/token' };
function browser(t, pathname = '/') {
  const stored = new Map(), navigations = [], cleaned = [], origin = 'https://documents.example';
  const values = { location: { origin, pathname, search: '', assign: value => navigations.push(new URL(value)) }, sessionStorage: { getItem: name => stored.get(name) ?? null, setItem: (name, value) => stored.set(name, value), removeItem: name => stored.delete(name) }, history: { replaceState: (_state, _title, path) => cleaned.push(path) } };
  for (const [name, value] of Object.entries(values)) { const previous = Object.getOwnPropertyDescriptor(globalThis, name); Object.defineProperty(globalThis, name, { value, configurable: true }); t.after(() => { if (previous) Object.defineProperty(globalThis, name, previous); else delete globalThis[name]; }); }
  return { ...values, stored, navigations, cleaned };
}

test('browser sign-in uses the registered callback and keeps local password login available', async t => {
  const page = browser(t, '/documents'); await login(config);
  const target = page.navigations[0], attempt = JSON.parse(page.stored.get('autosoft-dms-pkce'));
  assert.equal(target.searchParams.get('redirect_uri'), 'https://documents.example/auth/callback');
  assert.equal(target.searchParams.get('code_challenge_method'), 'S256');
  assert.match(target.searchParams.get('code_challenge'), /^[A-Za-z0-9_-]{43}$/);
  assert.equal(target.searchParams.get('state'), attempt.state);
  assert.equal(target.searchParams.has('kc_idp_hint'), false);
  assert.equal(target.searchParams.get('response_type'), 'code');
});

test('registered callback redeems the original PKCE attempt and clears its URL and state', async t => {
  const page = browser(t); await login(config); const attempt = JSON.parse(page.stored.get('autosoft-dms-pkce'));
  page.location.pathname = '/auth/callback'; page.location.search = new URLSearchParams({ code: 'synthetic-code', state: attempt.state }).toString();
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async (url, options) => { calls++; assert.equal(url, config.tokenEndpoint); assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit'); assert.equal(options.body.get('redirect_uri'), 'https://documents.example/auth/callback'); assert.equal(options.body.get('code_verifier'), attempt.verifier); return Response.json({ access_token: 'synthetic-access-token' }); });
  assert.equal(await callback(config), 'synthetic-access-token'); assert.equal(calls, 1); assert.deepEqual(page.cleaned, ['/']); assert.equal(page.stored.size, 0);
});

for (const mode of ['wrong-state', 'expired', 'foreign-origin', 'wrong-path']) test(`callback rejects ${mode} without sending a token request`, async t => {
  const page = browser(t); await login(config); const attempt = JSON.parse(page.stored.get('autosoft-dms-pkce'));
  if (mode === 'expired') attempt.createdAt = Date.now() - 600001;
  if (mode === 'foreign-origin') attempt.redirectUri = 'https://foreign.example/auth/callback';
  page.stored.set('autosoft-dms-pkce', JSON.stringify(attempt)); page.location.pathname = mode === 'wrong-path' ? '/' : '/auth/callback'; page.location.search = new URLSearchParams({ code: 'synthetic-code', state: mode === 'wrong-state' ? 'foreign-state' : attempt.state }).toString();
  let calls = 0; t.mock.method(globalThis, 'fetch', async () => { calls++; throw Error('Unexpected request'); });
  await assert.rejects(callback(config), /does not match/); assert.equal(calls, 0); assert.equal(page.stored.size, 0); assert.deepEqual(page.cleaned, ['/']);
});

test('only the registered callback serves the SPA without exposing authenticated APIs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dms-login-'));
  const server = createApplication({ publicConfig: { issuer: 'https://identity.example/realms/app' }, origin: 'https://documents.example', staticRoot: root, allowInsecureHttp: true, verify: async () => { throw new HttpError(401, 'Sign in required'); } });
  try {
    await writeFile(join(root, 'index.html'), '<!doctype html><title>Synthetic DMS login</title>');
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); const base = `http://127.0.0.1:${server.address().port}`;
    for (const path of ['/', '/auth/callback?code=synthetic&state=synthetic']) { const result = await fetch(base + path); assert.equal(result.status, 200); assert.match(result.headers.get('content-type'), /text\/html/); assert.match(await result.text(), /Synthetic DMS login/); }
    assert.equal((await fetch(base + '/auth/other')).status, 404);
    assert.equal((await fetch(base + '/auth/callback', { method: 'POST' })).status, 404);
    assert.equal((await fetch(base + '/api/documents')).status, 401);
  } finally { await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); }
});
