import test from 'node:test';
import assert from 'node:assert/strict';
import { directoryMapperMatches, directorySetupPlan } from './directory-identity-setup.mjs';
const tenant = '11111111-1111-4111-8111-111111111111', prefix = `https://login.microsoftonline.com/${tenant}`;
const provider = { alias: 'microsoft', providerId: 'oidc', enabled: true, config: { clientId: 'fixture', clientSecret: 'synthetic-secret-must-never-appear', syncMode: 'IMPORT', issuer: `${prefix}/v2.0`, authorizationUrl: `${prefix}/oauth2/v2.0/authorize`, tokenUrl: `${prefix}/oauth2/v2.0/token`, jwksUrl: `${prefix}/discovery/v2.0/keys` } };
test('company directory setup review binds exact public policy and protects immutable signed claims without exposing secrets', () => {
  const scope = { provider: 'microsoft', tenantId: tenant, workspaceDomain: null }, profile = { attributes: [{ name: 'username', permissions: { view: ['admin', 'user'], edit: ['admin', 'user'] } }] };
  const result = directorySetupPlan(provider, profile, [], scope);
  assert.equal(result.profile.unmanagedAttributePolicy, 'DISABLED'); assert.equal(result.mappers.length, 4); assert.equal(result.provider.config.validateSignature, 'true'); assert.equal(result.provider.config.syncMode, 'FORCE');
  assert.ok(!JSON.stringify(result.change).includes(provider.config.clientSecret)); assert.equal(result.provider.config.clientSecret, provider.config.clientSecret); assert.ok(result.profile.attributes.filter(attribute => attribute.name.startsWith('autosoft.directory.')).every(attribute => attribute.permissions.edit.join() === 'admin'));
  assert.equal(profile.attributes.length, 1); assert.equal(provider.config.syncMode, 'IMPORT'); assert.equal(directorySetupPlan({ ...provider, config: { ...provider.config, clientId: 'other' } }, profile, [], scope).artifactHash === result.artifactHash, false);
  assert.throws(() => directorySetupPlan(provider, profile, [{ ...result.mappers[0], config: { ...result.mappers[0].config, syncMode: 'IMPORT' } }], scope));
  assert.throws(() => directorySetupPlan({ ...provider, config: { ...provider.config, issuer: 'https://evil.example' } }, profile, [], scope));
});
test('Google setup uses the native Google profile mapper and exact customer/domain, never an incompatible OIDC mapper', () => {
  const result = directorySetupPlan({ alias: 'google', providerId: 'google', enabled: true, config: { hostedDomain: 'example.com', clientId: 'fixture', clientSecret: 'synthetic-google-secret' } }, { attributes: [] }, [], { provider: 'google', tenantId: 'C0123fixture', workspaceDomain: 'example.com' });
  assert.ok(result.mappers.every(mapper => mapper.identityProviderMapper === 'google-user-attribute-mapper')); assert.deepEqual(result.mappers.map(mapper => mapper.config.jsonField).sort(), ['hd', 'sub']); assert.ok(!JSON.stringify(result.change).includes('synthetic-google-secret'));
  assert.throws(() => directorySetupPlan({ alias: 'google', providerId: 'google', enabled: true, config: { hostedDomain: '*', clientId: 'fixture' } }, { attributes: [] }, [], { provider: 'google', tenantId: 'C0123fixture', workspaceDomain: 'example.com' }));
});
test('a correctly protected mapper with a different display name is reused, while alias and duplicate targets remain rejected', () => {
  const scope = { provider: 'microsoft', tenantId: tenant, workspaceDomain: null }, profile = { attributes: [] };
  const initial = directorySetupPlan(provider, profile, [], scope);
  const existing = initial.mappers.map(mapper => ({ ...mapper, name: `company-${mapper.name}`, id: 'existing-id' }));
  const repeated = directorySetupPlan(provider, profile, existing, scope);
  assert.ok(repeated.mappers.every(mapper => existing.some(value => directoryMapperMatches(value, mapper))));
  assert.equal(directoryMapperMatches({ ...existing[0], identityProviderAlias: 'other' }, initial.mappers[0]), false);
  assert.throws(() => directorySetupPlan(provider, profile, [...existing, { ...existing[0], name: 'duplicate' }], scope));
});
