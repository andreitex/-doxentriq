import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as httpServer } from 'node:http';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JsonStore } from '../src/store.ts';
import { createServer } from '../src/server.ts';
import type { Config } from '../src/config.ts';

test('OIDC validates PKCE, nonce, audience, roles and MFA and encrypts refresh tokens', async () => {
  const root = await mkdtemp(join(tmpdir(), 'autosoft-oidc-')); const store = new JsonStore(); const pair = await generateKeyPair('RS256'); const jwk = await exportJWK(pair.publicKey); jwk.kid = 'test-key'; jwk.alg = 'RS256';
  let issuer = ''; let nonce = ''; let pkce = ''; let tokenRequests = 0; let audience = 'autosoft-admin'; let subject = 'owner-id'; let roles = ['platform-owner']; let amr = ['pwd', 'otp']; let identityProvider: string | undefined;
  const provider = httpServer(async (request, response) => {
    response.setHeader('content-type', 'application/json');
    if (request.url === '/.well-known/openid-configuration') return response.end(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/keys` }));
    if (request.url === '/keys') return response.end(JSON.stringify({ keys: [jwk] }));
    if (request.url !== '/token') { response.statusCode = 404; return response.end('{}'); }
    let raw = ''; for await (const chunk of request) raw += String(chunk); const body = new URLSearchParams(raw); tokenRequests++;
    if (body.get('grant_type') === 'authorization_code') assert.equal(body.get('code_verifier'), pkce);
    const claims = { realm_access: { roles }, amr, name: 'Local owner', ...(identityProvider ? { identity_provider: identityProvider } : {}) };
    const access = await new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setIssuer(issuer).setAudience(audience).setSubject(subject).setIssuedAt().setExpirationTime(tokenRequests === 1 ? '10s' : '5m').sign(pair.privateKey);
    const id = await new SignJWT({ nonce, name: 'Local owner' }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setIssuer(issuer).setAudience('autosoft-admin').setSubject(subject).setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
    response.end(JSON.stringify({ access_token: access, id_token: id, refresh_token: `sensitive-refresh-${tokenRequests}` }));
  });
  await new Promise<void>(resolve => provider.listen(0, '127.0.0.1', resolve)); issuer = `http://127.0.0.1:${(provider.address() as { port: number }).port}`;
  const config: Config = { authMode: 'oidc', host: '127.0.0.1', port: 3000, publicOrigin: 'https://admin.test', dataDir: root, workspaceDir: join(root, 'workspaces'), oidcIssuer: issuer, oidcClientId: 'autosoft-admin', oidcClientSecret: 'test-client-secret', ownerSubject: 'owner-id', secretKey: Buffer.alloc(32, 42), requestLimitUsd: 1, monthlyLimitUsd: 5, adminDist: join(root, 'missing') };
  const server = await createServer(config, store);
  try {
    assert.equal((await server.inject({ method: 'GET', url: '/api/v1/session' })).statusCode, 401);
    const login = await server.inject({ method: 'GET', url: '/auth/login' }); assert.equal(login.statusCode, 302); const location = new URL(login.headers.location!); const state = location.searchParams.get('state')!; nonce = location.searchParams.get('nonce')!; pkce = await store.read(data => data.authStates[state]!.verifier);
    assert.equal(location.searchParams.get('code_challenge_method'), 'S256'); assert.notEqual(location.searchParams.get('code_challenge'), pkce);
    const cookie = login.cookies[0]!; const callback = await server.inject({ method: 'GET', url: `/auth/callback?state=${state}&code=test-code`, headers: { cookie: `${cookie.name}=${cookie.value}` } }); assert.equal(callback.statusCode, 302, callback.body);
    const sessionCookie = callback.cookies.find(item => item.name === '__Host-autosoft-session')!; const sessionHeaders = { cookie: `${sessionCookie.name}=${sessionCookie.value}` };
    const session = await server.inject({ method: 'GET', url: '/api/v1/session', headers: sessionHeaders }); assert.equal(session.statusCode, 200, session.body); assert.equal(session.json().principal.localOwner, true); assert.equal(tokenRequests, 2, 'Expired access token should refresh exactly once.');
    const sessionState = await store.read(data => Object.values(data.sessions)[0]!); assert.ok(sessionState.encryptedRefreshToken); assert.ok(!JSON.stringify(sessionState).includes('sensitive-refresh'));
    for (const alteration of [{ expiresAt: 'invalid-expiry' }, { accessExpiresAt: undefined }, { accessExpiresAt: 'invalid-token-expiry' }, { principal: { ...sessionState.principal, mfa: false } }, { principal: { ...sessionState.principal, localOwner: false, roles: [] } }]) {
      await store.transaction(data => { data.sessions[sessionState.id] = { ...sessionState, ...alteration }; }); const denied = await server.inject({ method: 'GET', url: '/api/v1/apps', headers: sessionHeaders }); assert.ok([401, 403].includes(denied.statusCode), denied.body); assert.equal(tokenRequests, 2, 'Live revocation and invalid timestamps must not call the provider.');
    }
    await store.transaction(data => { data.sessions[sessionState.id] = sessionState; });
    const replay = await server.inject({ method: 'GET', url: `/auth/callback?state=${state}&code=test-code`, headers: { cookie: `${cookie.name}=${cookie.value}` } }); assert.equal(replay.statusCode, 400);
    const newLogin = await server.inject({ method: 'GET', url: '/auth/login' }); const next = new URL(newLogin.headers.location!); const nextState = next.searchParams.get('state')!; nonce = next.searchParams.get('nonce')!; pkce = await store.read(data => data.authStates[nextState]!.verifier); audience = 'another-application';
    const nextCookie = newLogin.cookies[0]!; const wrongAudience = await server.inject({ method: 'GET', url: `/auth/callback?state=${nextState}&code=test-code`, headers: { cookie: `${nextCookie.name}=${nextCookie.value}` } }); assert.equal(wrongAudience.statusCode, 401);
    async function nextSignIn() {
      const login = await server.inject({ method: 'GET', url: '/auth/login' }); const target = new URL(login.headers.location!); const state = target.searchParams.get('state')!; nonce = target.searchParams.get('nonce')!; pkce = await store.read(data => data.authStates[state]!.verifier); const stateCookie = login.cookies[0]!;
      return server.inject({ method: 'GET', url: `/auth/callback?state=${state}&code=test-code`, headers: { cookie: `${stateCookie.name}=${stateCookie.value}` } });
    }
    audience = 'autosoft-admin'; subject = 'owner-id'; roles = ['platform-owner']; amr = ['pwd']; identityProvider = undefined;
    const enrolledSessions = await store.read(data => Object.keys(data.sessions).length);
    const enrollment = await nextSignIn();
    assert.equal(enrollment.statusCode, 302);
    assert.equal(enrollment.headers.location, '/?signin=mfa', 'Owner enrollment must explain a fresh MFA login without granting access.');
    assert.ok(!enrollment.cookies.some(cookie => cookie.name === '__Host-autosoft-session' && cookie.value), 'Enrollment must not issue an authenticated platform cookie.');
    assert.equal(await store.read(data => Object.keys(data.sessions).length), enrolledSessions);
    const freshLogin = await server.inject({ method: 'GET', url: '/auth/login?reauthenticate=1' });
    const freshTarget = new URL(freshLogin.headers.location!);
    assert.equal(freshTarget.searchParams.get('prompt'), 'login');
    assert.equal(freshTarget.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(await store.read(data => data.authStates[freshTarget.searchParams.get('state')!]?.nonce));
    audience = 'autosoft-admin'; subject = 'another-local-user'; roles = ['platform-admin']; assert.equal((await nextSignIn()).statusCode, 403, 'An additional local administrator must be denied.');
    identityProvider = 'google'; amr = ['pwd']; assert.equal((await nextSignIn()).statusCode, 403, 'An SSO administrator without MFA must be denied.');
    amr = ['pwd', 'otp']; assert.equal((await nextSignIn()).statusCode, 302, 'An authorized brokered administrator with MFA may sign in.');
  } finally { await server.close(); await new Promise<void>((resolve, reject) => provider.close(error => error ? reject(error) : resolve())); await rm(root, { force: true, recursive: true }); }
});
