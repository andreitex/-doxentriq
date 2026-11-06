import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PassThrough, Readable } from 'node:stream';
import { IdentityProvisioningError, readConfiguration, runProvisioning } from './keycloak-provision.mjs';

const config = { bootstrapPassword: 'synthetic-bootstrap-value', provisionerSecret: 'synthetic-provisioner-value' };
const ownerSubject = '11111111-1111-4111-8111-111111111111';
const helper = fileURLToPath(new URL('./keycloak-provision.mjs', import.meta.url));
const json = value => new Response(JSON.stringify(value), { status: 200 });

function fixture({ create = false, failure } = {}) {
  const requests = [], output = [];
  let exists = !create;
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    assert.equal(new URL(url).origin, 'https://keycloak:8443');
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    assert.equal(options.signal.aborted, false);
    if (failure) return failure(url, options);
    const path = new URL(url).pathname, method = options.method ?? 'GET';
    if (path.endsWith('/token')) return json({ access_token: 'synthetic-token-value' });
    if (path === '/admin/realms/master/clients') {
      if (method === 'POST') { exists = true; return new Response(null, { status: 201 }); }
      return json(exists ? [{ id: 'provisioner' }] : []);
    }
    if (path.endsWith('/service-account-user')) return json({ id: 'service-user' });
    if (path.endsWith('/roles/create-realm')) return json({ id: 'create-role', name: 'create-realm' });
    if (path.endsWith('/role-mappings/realm')) return new Response(null, { status: 204 });
    assert.fail('Unexpected fixture request');
  };
  return { requests, output, options: { fetchImpl, output: value => output.push(value) } };
}

test('fresh provisioner accepts empty 201 without content-length and protects every request', async () => {
  const f = fixture({ create: true });
  await runProvisioning(config, f.options);
  assert.equal(f.requests.filter(r => r.url.endsWith('/clients') && r.options.method === 'POST').length, 1);
  assert.equal(f.requests.length, 8);
  assert.deepEqual(f.output, ['Scoped app realm provisioner configured.']);
  assert.ok(!JSON.stringify(f.output).includes(config.provisionerSecret));
});

test('existing provisioner is reused without client creation or credential replacement', async () => {
  const f = fixture();
  await runProvisioning(config, f.options);
  assert.equal(f.requests.length, 6);
  assert.equal(f.requests.filter(r => r.url.endsWith('/clients') && r.options.method === 'POST').length, 0);
});

test('uncertain client creation stops once and does not repeat or report success', async () => {
  const f = fixture({ create: true });
  const original = f.options.fetchImpl;
  f.options.fetchImpl = async (url, options) => {
    if (url.endsWith('/clients') && options.method === 'POST') {
      f.requests.push({ url, options });
      throw new Error('upstream diagnostic contains synthetic-private-content');
    }
    return original(url, options);
  };
  await assert.rejects(runProvisioning(config, f.options), error => error instanceof IdentityProvisioningError && /inspect its current state/.test(error.message) && !error.message.includes('synthetic-private-content'));
  assert.equal(f.requests.length, 3);
  assert.equal(f.output.length, 0);
});

test('redirects and HTTP failures stop before further calls and do not print their body', async () => {
  for (const status of [302, 401, 429, 500, 503]) {
    const f = fixture({ failure: () => new Response('synthetic-private-content', { status }) });
    await assert.rejects(runProvisioning(config, f.options), error => error.message === `Identity provisioning failed HTTP ${status}`);
    assert.equal(f.requests.length, 1);
    assert.equal(f.output.length, 0);
  }
});

test('malformed JSON is redacted and empty 200 is refused', async () => {
  for (const body of ['', 'synthetic-private-content', '{"secret":"synthetic-private-content"']) {
    const f = fixture({ failure: () => new Response(body, { status: 200 }) });
    await assert.rejects(runProvisioning(config, f.options), error => error instanceof IdentityProvisioningError && !error.message.includes('synthetic-private-content'));
    assert.equal(f.requests.length, 1);
  }
});

test('advertised and streamed responses are size-bounded and unread bodies are cancelled', async () => {
  for (const advertised of [true, false]) {
    let cancelled = false;
    const body = new ReadableStream({
      pull(controller) { controller.enqueue(new Uint8Array(65536)); },
      cancel() { cancelled = true; }
    });
    const f = fixture({ failure: () => new Response(body, { status: 200, headers: advertised ? { 'content-length': '1048577' } : {} }) });
    await assert.rejects(runProvisioning(config, f.options), /permitted size/);
    assert.equal(cancelled, true);
    assert.equal(f.requests.length, 1);
  }
});

test('an already elapsed operation makes no network request', async () => {
  const f = fixture();
  await assert.rejects(runProvisioning(config, { ...f.options, operationSignal: AbortSignal.abort() }), /inspect its current state/);
  assert.equal(f.requests.length, 0);
});

test('operation deadline stops a stalled request or body without automatic retry', async () => {
  // Keep one ref'ed timer while AbortSignal.timeout uses an unref'ed timer.
  const keepalive = setTimeout(() => {}, 2000);
  try {
    for (const stalledBody of [false, true]) {
      let cancelled = false;
      const f = fixture({ failure: () => stalledBody
        ? new Response(new ReadableStream({ cancel() { cancelled = true; } }))
        : new Promise(() => {}) });
      const start = performance.now();
      await assert.rejects(runProvisioning(config, { ...f.options, operationSignal: AbortSignal.timeout(25) }), /inspect its current state/);
      assert.ok(performance.now() - start < 1500);
      assert.equal(f.requests.length, 1);
      if (stalledBody) assert.equal(cancelled, true);
    }
  } finally { clearTimeout(keepalive); }
});

test('invalid protected input and unknown actions fail before contacting identity', async () => {
  for (const input of [null, [], {}, { ...config, action: 'delete-owner' }, { ...config, directoryReaderSecret: '' }, { action: 'recover-owner', bootstrapPassword: config.bootstrapPassword, ownerSubject, ownerPassword: 'synthetic-recovery-value' }]) {
    const f = fixture();
    await assert.rejects(runProvisioning(input, f.options), IdentityProvisioningError);
    assert.equal(f.requests.length, 0);
  }
});

test('password-only recovery retains owner checks, required actions and logout', async () => {
  const requests = [], output = [], user = { id: ownerSubject, username: 'owner', requiredActions: ['CONFIGURE_TOTP'] };
  const fetchImpl = async (url, options) => {
    assert.equal(options.redirect, 'error');
    const path = new URL(url).pathname, method = options.method ?? 'GET';
    requests.push({ path, method });
    if (path.endsWith('/token')) return json({ access_token: 'synthetic-token' });
    if (path.endsWith('/federated-identity')) return json([]);
    if (path.endsWith('/roles/platform-owner/users')) return json([user]);
    if (path.endsWith('/credentials')) return json([{ id: 'otp', type: 'otp' }]);
    if (path.endsWith('/reset-password') || path.endsWith('/logout')) return new Response(null, { status: 204 });
    if (path.endsWith('/users/' + ownerSubject)) {
      if (method === 'PUT') { Object.assign(user, JSON.parse(options.body)); return new Response(null, { status: 204 }); }
      return json(user);
    }
    assert.fail('Unexpected recovery request');
  };
  await runProvisioning({ action: 'recover-owner', bootstrapPassword: config.bootstrapPassword, ownerPassword: 'synthetic-recovery-value', ownerSubject, resetTotp: false }, { fetchImpl, output: value => output.push(value) });
  assert.equal(requests.filter(r => r.method === 'DELETE').length, 0);
  assert.ok(requests.some(r => r.path.endsWith('/logout') && r.method === 'POST'));
  assert.deepEqual(user.requiredActions, ['CONFIGURE_TOTP', 'UPDATE_PASSWORD']);
  assert.equal(JSON.parse(output[0]).passwordReset, true);
  assert.ok(!output[0].includes('synthetic-recovery-value'));
});

test('real CLI rejects malformed or oversized stdin without exposing supplied values', () => {
  for (const input of ['{"bootstrapPassword":"synthetic-private-content"', 'synthetic-private-content'.repeat(4000)]) {
    const result = spawnSync(process.execPath, [helper], { input, encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.ok(!result.stderr.includes('synthetic-private-content'));
    assert.ok(!result.stderr.includes('SyntaxError'));
  }
});

test('protected stdin uses the operation deadline and closes a stalled input', async () => {
  const stream = new PassThrough(), keepalive = setTimeout(() => {}, 2000);
  stream.write('{"bootstrapPassword":"synthetic-private-content"');
  try {
    await assert.rejects(readConfiguration(stream, AbortSignal.timeout(25)), error => error instanceof IdentityProvisioningError && !error.message.includes('synthetic-private-content'));
    assert.equal(stream.destroyed, true);
  } finally { clearTimeout(keepalive); stream.destroy(); }
});

test('valid protected stdin is parsed without retaining the stream', async () => {
  const stream = Readable.from([Buffer.from(JSON.stringify(config))]);
  assert.deepEqual(await readConfiguration(stream), config);
  assert.equal(stream.destroyed, true);
});
