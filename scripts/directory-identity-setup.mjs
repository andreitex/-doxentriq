// Separate company operation. Preview first, then apply the exact reviewed hash.
// It changes only the selected platform provider's claim/profile policy. Existing
// app realms, accounts, invitations and role grants are not modified.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

function canonical(value) { if (Array.isArray(value)) return value.map(canonical); if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])); return value; }
export function directorySetupHash(value) { return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex'); }
export function directoryMapperMatches(existing, desired) {
  return existing.identityProviderAlias === desired.identityProviderAlias && existing.identityProviderMapper === desired.identityProviderMapper && directorySetupHash(existing.config) === directorySetupHash(desired.config);
}
export function directorySetupPlan(provider, profile, existingMappers, scope) {
  if (!['microsoft', 'google'].includes(scope.provider) || provider.alias !== scope.provider || !provider.enabled || provider.providerId !== (scope.provider === 'google' ? 'google' : 'oidc')) throw new Error('Exact existing trusted provider is required');
  const google = scope.provider === 'google';
  if (google ? !/^C[A-Za-z0-9_-]{1,127}$/.test(scope.tenantId) || !/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(scope.workspaceDomain ?? '') || provider.config.hostedDomain !== scope.workspaceDomain : !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(scope.tenantId) || scope.workspaceDomain !== null) throw new Error('Exact immutable tenant/customer and hosted domain are required');
  const claims = google ? ['sub', 'hd'] : ['sub', 'oid', 'tid', 'iss'];
  const mappers = claims.map(claim => ({ name: `autosoft-directory-${scope.provider}-${claim}`, identityProviderAlias: scope.provider, identityProviderMapper: google ? 'google-user-attribute-mapper' : 'oidc-user-attribute-idp-mapper', config: google ? { jsonField: claim, userAttribute: `autosoft.directory.google.${claim}`, syncMode: 'FORCE' } : { claim, 'user.attribute': `autosoft.directory.microsoft.${claim}`, syncMode: 'FORCE' } }));
  for (const mapper of mappers) {
    const target = mapper.config.userAttribute ?? mapper.config['user.attribute'];
    const conflicts = existingMappers.filter(value => (value.config?.userAttribute ?? value.config?.['user.attribute']) === target);
    if (conflicts.length > 1 || conflicts.some(value => !directoryMapperMatches(value, mapper))) throw new Error('Reserved directory mapper already has a different policy; resolve it explicitly before setup');
  }
  const updatedProfile = structuredClone(profile); updatedProfile.unmanagedAttributePolicy = 'DISABLED'; updatedProfile.attributes ??= [];
  for (const claim of claims) {
    const name = `autosoft.directory.${scope.provider}.${claim}`, matches = updatedProfile.attributes.filter(value => value.name === name);
    if (matches.length > 1) throw new Error('Protected profile attribute is duplicated');
    if (matches.length) matches[0].permissions = { view: ['admin'], edit: ['admin'] };
    else updatedProfile.attributes.push({ name, displayName: name, multivalued: false, permissions: { view: ['admin'], edit: ['admin'] } });
  }
  const config = { ...provider.config, validateSignature: 'true', syncMode: 'FORCE' };
  if (!google) {
    const base = `https://login.microsoftonline.com/${scope.tenantId}`;
    for (const [key, value] of Object.entries({ issuer: `${base}/v2.0`, authorizationUrl: `${base}/oauth2/v2.0/authorize`, tokenUrl: `${base}/oauth2/v2.0/token`, jwksUrl: `${base}/discovery/v2.0/keys` })) if (config[key] !== value) throw new Error('Existing Microsoft endpoint or issuer differs from the reviewed tenant');
    if (config.userInfoUrl && config.userInfoUrl !== 'https://graph.microsoft.com/oidc/userinfo') throw new Error('Microsoft user-info endpoint is not trusted'); config.useJwksUrl = 'true';
  }
  // Secret values are deliberately excluded from the review hash/output.
  const publicKeys = ['clientId', 'issuer', 'authorizationUrl', 'tokenUrl', 'jwksUrl', 'useJwksUrl', 'validateSignature', 'syncMode', 'hostedDomain', 'userInfoUrl'];
  const publicProjection = value => Object.fromEntries(publicKeys.filter(key => Object.hasOwn(value, key)).map(key => [key, value[key]]));
  const publicConfig = publicProjection(config);
  const change = { schemaVersion: 1, provider: scope.provider, tenantId: scope.tenantId, workspaceDomain: scope.workspaceDomain, baseHash: directorySetupHash({ provider: { alias: provider.alias, enabled: provider.enabled, providerId: provider.providerId, config: publicProjection(provider.config) }, profile, existingMappers }), config: publicConfig, profile: updatedProfile, mappers };
  return { artifactHash: directorySetupHash(change), change, provider: { ...provider, config }, profile: updatedProfile, mappers };
}
async function main() {
  const text = readFileSync(0, 'utf8'); if (Buffer.byteLength(text) > 65536) throw new Error('Bounded protected setup input required'); const input = JSON.parse(text), base = 'https://keycloak:8443';
  async function call(path, token, options = {}) { const response = await fetch(base + path, { ...options, redirect: 'error', signal: AbortSignal.timeout(15000), headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...options.headers } }); if (!response.ok) throw new Error(`Protected identity setup unavailable HTTP ${response.status}`); return response.status === 204 || response.headers.get('content-length') === '0' ? null : response.json(); }
  const token = (await call('/realms/master/protocol/openid-connect/token', undefined, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'bootstrap-admin', password: input.bootstrapPassword }) })).access_token;
  const prefix = `/admin/realms/platform/identity-provider/instances/${encodeURIComponent(input.provider)}`;
  const provider = await call(prefix, token), profile = await call('/admin/realms/platform/users/profile', token), mappers = await call(prefix + '/mappers', token), plan = directorySetupPlan(provider, profile, mappers, input);
  if (input.apply !== true) { console.log(JSON.stringify({ artifactHash: plan.artifactHash, change: plan.change, impact: ['Only company platform identity attributes/provider claim policy are changed; no user role or app realm is changed.', 'Disable unmanaged profile attributes and protect immutable directory attributes from user edits.', 'Signature validation and forced claim refresh are mandatory. Existing users need a fresh upstream sign-in before any directory authorization.', 'Directory API consent, protected credential setup and exact app activation remain separate operations. Live Microsoft/Google proof is required before customer qualification.'] })); return; }
  if (input.expectedHash !== plan.artifactHash) throw new Error('Exact reviewed setup hash differs; preview again');
  await call('/admin/realms/platform/users/profile', token, { method: 'PUT', body: JSON.stringify(plan.profile) });
  await call(prefix, token, { method: 'PUT', body: JSON.stringify(plan.provider) });
  for (const mapper of plan.mappers) if (!mappers.some(value => directoryMapperMatches(value, mapper))) await call(prefix + '/mappers', token, { method: 'POST', body: JSON.stringify(mapper) });
  const afterProvider = await call(prefix, token), afterProfile = await call('/admin/realms/platform/users/profile', token), afterMappers = await call(prefix + '/mappers', token);
  const after = directorySetupPlan(afterProvider, afterProfile, afterMappers, input);
  if (directorySetupHash(after.change.config) !== directorySetupHash(plan.change.config) || directorySetupHash(after.profile) !== directorySetupHash(plan.profile) || plan.mappers.some(mapper => !afterMappers.some(value => directoryMapperMatches(value, mapper)))) throw new Error('Identity setup confirmation differs; group authorization remains unavailable until company inspection');
  console.log(JSON.stringify({ configured: true, provider: input.provider, tenantId: input.tenantId, reviewedArtifactHash: plan.artifactHash, freshUpstreamLoginRequired: true, groupRolesGranted: false, liveProviderQualified: false }));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(() => { console.error('Protected directory identity setup failed. Inspect trusted company configuration; no directory role grants were made.'); process.exitCode = 1; });
