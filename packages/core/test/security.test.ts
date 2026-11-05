import test from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../src/security.ts';
import { readFile } from 'node:fs/promises';

test('structured provider credentials use camelCase, underscore and hyphen spellings', () => {
  const fields = ['accessToken', 'refreshToken', 'idToken', 'clientSecret', 'privateKey', 'secretKey', 'signingSecret', 'signingSecrets', 'setCookie', 'access_token', 'client-secret'];
  const input = Object.fromEntries(fields.map(name => [name, ['opaque-protected-value']]));
  const actual = redact({ nested: [input], accessTokenLifespanSeconds: 60, tokenCount: 123, secretRef: 'vault-reference', publicKey: 'public-key' });
  for (const name of fields) assert.equal(actual.nested[0]![name], '[REDACTED]');
  assert.equal(actual.accessTokenLifespanSeconds, 60);
  assert.equal(actual.tokenCount, 123);
  assert.equal(actual.secretRef, 'vault-reference');
  assert.equal(actual.publicKey, 'public-key');
  assert.deepEqual(input.accessToken, ['opaque-protected-value']);
});

test('quoted diagnostic JSON credentials including escaped quotes are removed', () => {
  const credentials = { clientSecret: 'opaque-"quoted"-secret', privateKey: 'opaque-key-value', refresh_token: 'opaque-refresh', idToken: 'opaque-identity', secretKey: 'opaque-encryption', signingSecret: 'opaque-signing', token: 'opaque-token', secret: 'opaque-secret', credentials: 'opaque-credentials', authorization: 'Basic opaque-basic', cookie: 'sid=opaque-cookie', setCookie: 'sid=opaque-cookie; HttpOnly', appName: 'Documents' };
  const serialized = JSON.stringify(credentials);
  const actual = JSON.parse(redact(serialized)) as Record<string, string>;
  for (const name of Object.keys(credentials).filter(name => name !== 'appName')) assert.equal(actual[name], '[REDACTED]');
  assert.equal(actual.appName, 'Documents');
  assert.equal(credentials.clientSecret, 'opaque-"quoted"-secret');
});

test('unquoted Basic authorization removes the entire credential and keeps the following line', () => {
  const actual = redact('Authorization: Basic b3BhcXVlOmNyZWRlbnRpYWw=\nRequest failed with HTTP 401');
  assert.equal(actual, 'Authorization: "[REDACTED]"\nRequest failed with HTTP 401');
});

test('multiline private keys are removed from diagnostics while certificates and public keys remain', () => {
  for (const kind of ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'OPENSSH PRIVATE KEY']) {
    const secret = `-----BEGIN ${kind}-----\nopaque-key-line-one\nopaque-key-line-two\n-----END ${kind}-----`;
    const message = `Connection failed using ${secret}; inspect application configuration.`;
    assert.equal(redact(message), 'Connection failed using [REDACTED]; inspect application configuration.');
    assert.deepEqual(JSON.parse(redact(JSON.stringify({ privateKey: secret }))), { privateKey: '[REDACTED]' });
  }
  const publicMaterial = '-----BEGIN CERTIFICATE-----\npublic-certificate\n-----END CERTIFICATE----- -----BEGIN PUBLIC KEY-----\npublic-key\n-----END PUBLIC KEY-----';
  assert.equal(redact(publicMaterial), publicMaterial);
});

test('single-quoted and plain credential assignments preserve unrelated diagnostic text', () => {
  const message = "clientSecret='opaque \\'quoted\\' value' refreshToken=opaque-refresh idToken: opaque-identity privateKey=opaque-private foo=bar";
  const actual = redact(message);
  assert.ok(!actual.includes('opaque'));
  assert.ok(!actual.includes('quoted'));
  assert.ok(actual.includes('foo=bar'));
  assert.equal((actual.match(/\[REDACTED\]/g) ?? []).length, 4);
});

test('embedded credential arrays and objects remove the whole value and preserve adjacent business JSON', () => {
  for (const value of [['opaque-first', 'opaque-second'], { first: 'opaque-first', nested: ['opaque-second', { last: 'opaque-third' }] }]) {
    for (const spaces of [undefined, 2]) {
      const text = JSON.stringify({ clientSecret: value, appName: 'Documents', secretRef: 'vault-reference', publicKey: 'public-material' }, null, spaces);
      assert.deepEqual(JSON.parse(redact(text)), { clientSecret: '[REDACTED]', appName: 'Documents', secretRef: 'vault-reference', publicKey: 'public-material' });
      assert.ok(!redact(text).includes('opaque'));
    }
    assert.deepEqual(redact({ credentials: value, context: 'Documents' }), { credentials: '[REDACTED]', context: 'Documents' });
  }
});

test('multiline quoted and multiword bare assignments keep no credential tail', () => {
  for (const quote of ['"', "'"]) {
    const text = `clientSecret=${quote}opaque-first\nopaque-second${quote}\nRequest failed with HTTP 401`;
    assert.equal(redact(text), 'clientSecret="[REDACTED]"\nRequest failed with HTTP 401');
  }
  assert.equal(redact('clientSecret=opaque first second foo=bar\nHTTP 401'), 'clientSecret="[REDACTED]" foo=bar\nHTTP 401');
  assert.equal(redact('privateKey:\n  opaque-value\nHTTP 401'), 'privateKey:\n  "[REDACTED]"\nHTTP 401');
});

test('serialized diagnostic JSON is redacted through bounded nested string layers', () => {
  let text = JSON.stringify({ clientSecret: ['opaque-first', { nested: 'opaque-last' }], appName: 'Documents' });
  for (let layers = 0; layers < 11; layers++) {
    const actual = redact(`Diagnostic payload ${text}; retry later.`);
    assert.ok(!actual.includes('opaque-first'));
    assert.ok(!actual.includes('opaque-last'));
    assert.notEqual(actual, `Diagnostic payload ${text}; retry later.`);
    if (layers < 8) assert.ok(actual.includes('Documents'));
    text = JSON.stringify(text);
  }
  const envelope = JSON.stringify({ diagnostic: JSON.stringify({ accessToken: { first: 'opaque-first', second: 'opaque-last' }, operation: 'list documents' }), reason: 'HTTP 401' });
  const actual = JSON.parse(redact(envelope));
  assert.deepEqual(JSON.parse(actual.diagnostic), { accessToken: '[REDACTED]', operation: 'list documents' });
  assert.equal(actual.reason, 'HTTP 401');
});

test('malformed oversized and deeply balanced credential values fail closed', () => {
  for (const value of ['["opaque-first", "opaque-tail"', '{"first":"opaque-first", "nested":["opaque-tail"]', '"opaque-first\nopaque-tail', '[['.repeat(33) + '"opaque-tail"' + ']]'.repeat(33), '"' + 'x'.repeat(65537) + 'opaque-tail"']) {
    const original = `Diagnostic clientSecret=${value}`;
    const actual = redact(original);
    assert.notEqual(actual, original);
    assert.ok(!actual.includes('opaque'));
    assert.ok(!actual.includes('xxxxx'));
  }
  // Decoded recognized names also retain the fail-closed policy.
  assert.equal(redact('{"client\\u0053ecret":["opaque-tail"'), '[REDACTED]');
  const budget = ' '.repeat(2 * 1024 * 1024) + 'clientSecret=opaque-budget-tail';
  assert.equal(redact(budget), '[REDACTED]');
});

test('benign pretty JSON nested serialization and public references remain byte exact', () => {
  let text = '{\n  "appName": "Documents",\n  "secretRef": "vault-reference",\n  "publicKey": "public-material",\n  "tokenCount": 3\n}';
  for (let depth = 0; depth < 12; depth++) { assert.equal(redact(text), text); text = JSON.stringify(text); }
  for (const text of ['Public secret architecture notes', "Documents don't lose owners' files", 'clientSecretRef=vault-reference', 'accessTokenLifespanSeconds: 60', '{"note":"public\\u0020material"}']) assert.equal(redact(text), text);
});

test('inspection limits cannot hide later escaped credential names', () => {
  const escaped = '{"client\\u0053ecret":["opaque-tail"]}';
  for (const text of ['{"pad":"' + 'x'.repeat(65537) + '","client\\u0053ecret":["opaque-tail"]}', ' '.repeat(2 * 1024 * 1024) + escaped, 'ordinary="unterminated business description']) assert.equal(redact(text), '[REDACTED]');
  let text = escaped;
  for (let layer = 0; layer < 10; layer++) {
    assert.ok(!redact(text).includes('opaque-tail'), 'Serialized escaped credential key was not inspected');
    text = JSON.stringify(text);
  }
});

test('runtime authorization templates and Fetch credential policies preserve actual DMS source', async () => {
  const source=await readFile('templates/dms/web/main.jsx','utf8');
  assert.equal(redact(source),source);
  const envelope=JSON.stringify({previousFiles:[{path:'web/main.jsx',content:source}]});
  assert.equal(redact(envelope),envelope);
  assert.equal(redact(JSON.stringify(envelope)),JSON.stringify(envelope));
});

test('public runtime templates never preserve literal credentials or computed template secrets', () => {
  const ordinary='headers: { authorization: `Bearer ${identity.accessToken}`, credentials: \'omit\' }';
  assert.equal(redact(ordinary),ordinary);
  for(const value of ["authorization: 'Bearer opaque-private-token'",'authorization: `Bearer actual-private-token`',"authorization: `Bearer ${'opaque-private-token'}`",'authorization: `Bearer ${token}-opaque-private-token`','credentials: \'opaque-private-token\'','authorization = `Bearer ${token}`']){
    const actual=redact(value); assert.notEqual(actual,value); assert.ok(!actual.includes('opaque-private-token')); assert.ok(!actual.includes('actual-private-token'));
  }
  assert.deepEqual(redact({credentials:'omit',authorization:'Bearer opaque-private-token'}),{credentials:'[REDACTED]',authorization:'[REDACTED]'});
  assert.ok(!redact(ordinary,['identity.accessToken']).includes('identity.accessToken'));
});

test('credential templates consume complete suffixes nested expressions and malformed values', () => {
  for(const value of ['`Bearer ${token}-opaque-private-tail`','`prefix-${`nested-${value}-opaque-private-tail`}-suffix`','`prefix-${{value:"opaque-private-tail"}.value}-suffix`','`unterminated-${value}-opaque-private-tail']){
    const actual=redact('authorization: '+value+'\nHTTP 401');
    assert.ok(!actual.includes('opaque-private-tail'));
    assert.ok(actual.includes('[REDACTED]'));
  }
  for(const value of ['{token:`prefix}-opaque-private-tail`}', '[`prefix]-opaque-private-tail`]']){
    assert.ok(!redact('credentials: '+value+'\nHTTP 401').includes('opaque-private-tail'));
  }
});

test('bare Cookie and Set-Cookie headers remove every semicolon separated credential', () => {
  for (const header of ['Cookie: sid=opaque-first; session=opaque-tail', 'Set-Cookie: sid=opaque-first; session=opaque-tail; Path=/; HttpOnly', 'set_cookie="opaque-first"; session=opaque-tail']) {
    const actual = redact(header + '\nRequest failed with HTTP 401');
    assert.ok(!actual.includes('opaque'));
    assert.ok(actual.endsWith('\nRequest failed with HTTP 401'));
  }
  assert.deepEqual(JSON.parse(redact('{"cookie":null,"operation":"Document management"}')), { cookie: '[REDACTED]', operation: 'Document management' });
});
