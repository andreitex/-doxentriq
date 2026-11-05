import { readFile, lstat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { HttpError } from './domain.mjs';

export function createVerifier({ appId, issuer, audience, jwks }) {
  if (!appId || !issuer || !audience || !jwks) throw new Error('App identity, issuer, audience and local JWKS are mandatory.');
  const keys = createLocalJWKSet(jwks);
  return async (authorization, target = 'api') => {
    if (typeof authorization !== 'string' || !/^Bearer [^\s]+$/.test(authorization) || authorization.length > 16384) throw new HttpError(401, 'A valid app access token is required.');
    let payload;
    try { ({ payload } = await jwtVerify(authorization.slice(7), keys, { issuer, audience: target === 'mcp' ? `${appId}:mcp` : audience, algorithms: ['RS256', 'ES256'], requiredClaims: ['sub', 'exp', 'iat', 'app_id'], maxTokenAge: '15m', clockTolerance: 5 })); }
    catch { throw new HttpError(401, 'The app access token is invalid or expired.'); }
    if (payload.app_id !== appId) throw new HttpError(403, 'The token belongs to another application.');
    const roles = payload.resource_access?.[audience]?.roles;
    return { id: payload.sub, appId, roles: Array.isArray(roles) ? roles.filter(value => typeof value === 'string') : [], scopes: typeof payload.scope === 'string' ? payload.scope.split(' ') : [] };
  };
}
/** Optional company-controlled per-request group authorization. Tokens stay in
 * transit, membership permissions are never written into local users or JWTs. */
export function createDirectoryVerifier({ appId, audience, url, verify, fetchImpl = fetch }) {
  const endpoint = new URL(url);
  if (endpoint.protocol !== 'https:' || endpoint.hostname !== 'control' || endpoint.port !== '3000' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== `/api/public/v1/apps/${appId}/directory/authorize`) throw new Error('Directory authorization requires the exact trusted app-scoped control endpoint.');
  return async (authorization, target = 'api') => {
    const principal = await verify(authorization, target); let value;
    try {
      const response = await fetchImpl(endpoint.href, { method: 'POST', redirect: 'error', credentials: 'omit', headers: { 'content-type': 'application/json', authorization }, body: JSON.stringify({ target }), signal: AbortSignal.timeout(35000) });
      if (!response.ok) throw new Error();
      if (!response.body) throw new Error(); const reader = response.body.getReader(); const chunks = []; let size = 0;
      try { for (;;) { const { done, value: chunk } = await reader.read(); if (done) break; size += chunk.length; if (size > 16384) throw new Error(); chunks.push(chunk); } } finally { await reader.cancel().catch(() => {}); }
      value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      const checked = Date.parse(value.checkedAt), expires = Date.parse(value.validUntil), now = Date.now();
      if (value.appId !== appId || value.subject !== principal.id || value.audience !== (target === 'mcp' ? `${appId}:mcp` : audience) || !/^[a-f0-9]{64}$/.test(value.policyHash ?? '') || !Number.isFinite(checked) || checked > now + 10000 || now - checked > 60000 || !Number.isFinite(expires) || expires <= now || expires <= checked || expires - checked > 300000 || !Array.isArray(value.permissions) || value.permissions.length > 4 || new Set(value.permissions).size !== value.permissions.length || value.permissions.some(permission => !['dms.read', 'dms.search', 'dms.write', 'dms.admin'].includes(permission))) throw new Error();
    } catch { throw new HttpError(503, 'Directory authorization is unavailable, incomplete or stale. No app permission is accepted until the protected company service is restored.'); }
    return { ...principal, roles: [...new Set([...principal.roles, ...value.permissions])], directoryAuthorization: { policyHash: value.policyHash, validUntil: value.validUntil } };
  };
}
export async function loadAuth(environment) {
  if (!environment.OIDC_JWKS_FILE) throw new Error('An app-scoped OIDC_JWKS_FILE is required.');
  const issuer = new URL(environment.OIDC_ISSUER);
  if (issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.search || issuer.hash) throw new Error('A trusted HTTPS OIDC issuer is required.');
  const audience = environment.OIDC_AUDIENCE;
  const exactIssuer = issuer.href.replace(/\/$/, ''), appId = environment.APP_ID, resourceId = environment.OIDC_JWKS_RESOURCE_ID;
  if (!appId || !audience || !resourceId || ![appId, `${appId}_preview`].includes(resourceId)) throw new Error('Exact app identity, audience and JWKS resource scope are required.');
  let cachedHash, cachedVerifier;
  const refresh = async () => {
    try {
      const info = await lstat(environment.OIDC_JWKS_FILE);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 1024 * 1024) throw new Error('Invalid local key file.');
      const bundle = JSON.parse(await readFile(environment.OIDC_JWKS_FILE, 'utf8')), metadata = bundle.autosoft;
      const checked = Date.parse(metadata?.checkedAt), expires = Date.parse(metadata?.validUntil), now = Date.now();
      if (metadata?.schemaVersion !== 1 || metadata.appId !== appId || metadata.resourceId !== resourceId || metadata.issuer !== exactIssuer || !Number.isFinite(checked) || !Number.isFinite(expires) || checked > now + 60000 || expires <= now || expires <= checked || expires - checked > 3600000 || !/^[a-f0-9]{64}$/.test(metadata.keysHash ?? '') || !Array.isArray(bundle.keys) || !bundle.keys.length || bundle.keys.length > 32) throw new Error('Invalid issuer-bound key evidence.');
      const seen = new Set();
      for (const key of bundle.keys) {
        if (!key || typeof key !== 'object' || typeof key.kid !== 'string' || seen.has(key.kid) || key.use !== 'sig' || !['RS256', 'ES256'].includes(key.alg) || ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'jku', 'x5u'].some(name => Object.hasOwn(key, name))) throw new Error('Invalid public verification keys.');
        if (key.alg === 'RS256' && key.kty !== 'RSA' || key.alg === 'ES256' && (key.kty !== 'EC' || key.crv !== 'P-256')) throw new Error('Invalid key algorithm.'); seen.add(key.kid);
      }
      const normalized = bundle.keys.map(key => Object.fromEntries(Object.keys(key).sort().map(name => [name, key[name]])));
      const hash = createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
      if (hash !== metadata.keysHash) throw new Error('Key evidence changed.');
      if (cachedHash !== hash) { cachedVerifier = createVerifier({ appId, issuer: exactIssuer, audience, jwks: { keys: bundle.keys } }); cachedHash = hash; }
      return cachedVerifier;
    } catch { throw new HttpError(503, 'App sign-in is temporarily unavailable because trusted signing-key evidence is missing or stale. Contact the company operator.'); }
  };
  await refresh();
  const verify = async (...args) => (await refresh())(...args);
  return { verify: environment.DIRECTORY_AUTHORIZATION_URL ? createDirectoryVerifier({ appId, audience, url: environment.DIRECTORY_AUTHORIZATION_URL, verify }) : verify, publicConfig: { appId, issuer: exactIssuer, clientId: audience, authorizationEndpoint: exactIssuer + '/protocol/openid-connect/auth', tokenEndpoint: exactIssuer + '/protocol/openid-connect/token' } };
}
