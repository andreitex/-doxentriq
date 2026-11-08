// Trusted installation code, executed in the company platform image with internal TLS.
import { pathToFileURL } from 'node:url';

const BASE = 'https://keycloak:8443';
const MAX_INPUT = 64 * 1024;
const MAX_RESPONSE = 1024 * 1024;
const REQUEST_MS = 15000;
const OPERATION_MS = 120000;

export class IdentityProvisioningError extends Error {}

function credential(value) {
  return typeof value === 'string' && value.length >= 12 && value.length <= 4096 && !value.includes('\0');
}

function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config) || !credential(config.bootstrapPassword)) throw new IdentityProvisioningError('Protected identity configuration is invalid');
  if (config.action === 'recover-owner') {
    if (!credential(config.ownerPassword) || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(config.ownerSubject) || typeof config.resetTotp !== 'boolean') throw new IdentityProvisioningError('Protected owner recovery configuration is invalid');
  } else if (config.action !== undefined || !credential(config.provisionerSecret) || (config.directoryReaderSecret !== undefined && (!credential(config.directoryReaderSecret) || config.directoryReaderSecret.length < 32))) {
    throw new IdentityProvisioningError('Protected identity provisioning configuration is invalid');
  }
}

function beforeDeadline(promise, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => reject(new IdentityProvisioningError('Identity request did not complete; inspect its current state before retrying'));
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

// One operation deadline covers fetch and response consumption. No request,
// including a mutation whose result is uncertain, is automatically retried here.
function transport(fetchImpl, operationSignal) {
  return async function call(path, options = {}, token) {
    const readiness = path === 'https://keycloak:9000/health/ready' && Object.keys(options).length === 0 && token === undefined;
    if (typeof path !== 'string' || !readiness && !path.startsWith('/admin/realms/') && !path.startsWith('/realms/') || path.includes('#') || path.includes('\\') || /[\r\n\0]/.test(path)) throw new IdentityProvisioningError('Invalid identity endpoint');
    const { expectedStatus, ...request } = options;
    const signal = AbortSignal.any([operationSignal, AbortSignal.timeout(REQUEST_MS)]);
    let result, reader;
    try {
      signal.throwIfAborted();
      result = await beforeDeadline(fetchImpl(readiness ? path : BASE + path, { ...request, redirect: 'error', signal, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...request.headers } }), signal);
      if (!result.ok || expectedStatus !== undefined && result.status !== expectedStatus) throw new IdentityProvisioningError(`Identity provisioning failed HTTP ${result.status}`);
      const length = result.headers.get('content-length');
      if (length !== null && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > MAX_RESPONSE)) throw new IdentityProvisioningError('Identity response exceeds the permitted size');
      const chunks = [];
      let bytes = 0;
      if (result.body) {
        reader = result.body.getReader();
        while (true) {
          signal.throwIfAborted();
          const { value, done } = await beforeDeadline(reader.read(), signal);
          if (done) break;
          bytes += value.byteLength;
          if (bytes > MAX_RESPONSE) throw new IdentityProvisioningError('Identity response exceeds the permitted size');
          chunks.push(Buffer.from(value));
        }
      }
      signal.throwIfAborted();
      if (bytes === 0 && (result.status === 201 || result.status === 204)) return null;
      if (bytes === 0 || result.status === 204) throw new IdentityProvisioningError('Identity response has an unexpected body');
      // JSON parser diagnostics may include credentials from an upstream body.
      // Convert them to a fixed diagnostic before crossing the CLI boundary.
      try { return JSON.parse(Buffer.concat(chunks, bytes).toString('utf8')); }
      catch { throw new IdentityProvisioningError('Identity response is not valid JSON'); }
    } catch (error) {
      if (error instanceof IdentityProvisioningError) throw error;
      throw new IdentityProvisioningError('Identity request did not complete; inspect its current state before retrying');
    } finally {
      // Cancel unread/error bodies without waiting indefinitely on cleanup.
      if (reader) { void reader.cancel().catch(() => {}); reader.releaseLock(); }
      else if (result?.body) void result.body.cancel().catch(() => {});
    }
  };
}

export async function runProvisioning(config, { fetchImpl = fetch, output = console.log, operationSignal = AbortSignal.timeout(OPERATION_MS) } = {}) {
  validateConfig(config);
  const call = transport(fetchImpl, operationSignal);
const token = (await call('/realms/master/protocol/openid-connect/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'bootstrap-admin', password: config.bootstrapPassword }) })).access_token;
if (config.action === 'recover-owner') {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(config.ownerSubject)) throw new IdentityProvisioningError('Invalid configured owner UUID');
  const owner = await call(`/admin/realms/platform/users/${encodeURIComponent(config.ownerSubject)}`, {}, token);
  if (owner.id !== config.ownerSubject || owner.username !== 'owner' || owner.federationLink) throw new IdentityProvisioningError('Protected local owner identity mismatch');
  const identities = await call(`/admin/realms/platform/users/${owner.id}/federated-identity`, {}, token);
  const owners = await call('/admin/realms/platform/roles/platform-owner/users?first=0&max=2', {}, token);
  if (identities.length || owners.length !== 1 || owners[0].id !== owner.id) throw new IdentityProvisioningError('Permanent local owner uniqueness check failed');
  const credentials = await call(`/admin/realms/platform/users/${owner.id}/credentials`, {}, token);
  const otp = credentials.filter(credential => credential.type === 'otp');
  const recovery = credentials.filter(credential => credential.type === 'recovery-authn-codes');
  let configureRecovery = false;
  if (config.resetTotp === true) {
    // /authentication/flows lists only top-level flows. Inspect the actual
    // browser's nested execution tree rather than treating that as absence.
    const flows = await call('/admin/realms/platform/authentication/flows/platform-browser/executions', {}, token);
    const configured = flows.filter(flow => flow.displayName === 'platform-owner-second-factor' && flow.authenticationFlow === true && flow.level === 1 && flow.requirement === 'CONDITIONAL');
    if (configured.length > 1 || (!configured.length && recovery.length)) throw new IdentityProvisioningError('Existing owner recovery policy needs company repair before reset');
    if (configured.length) {
      const realm = await call('/admin/realms/platform', {}, token);
      const providers = await call('/admin/realms/platform/authentication/required-actions', {}, token);
      const actions = await call('/admin/realms/platform/authentication/flows/platform-owner-second-factor/executions', {}, token);
      const forms = await call('/admin/realms/platform/authentication/flows/platform-forms/executions', {}, token);
      const factor = actions.filter(action => action.providerId === 'auth-recovery-authn-code-form' && action.requirement === 'ALTERNATIVE');
      const password = forms.filter(action => action.providerId === 'auth-username-password-form' && action.requirement === 'REQUIRED');
      if (realm.browserFlow !== 'platform-browser' || factor.length !== 1 || password.length !== 1 || !actions.some(action => action.providerId === 'conditional-user-configured' && action.requirement === 'REQUIRED') || !actions.some(action => action.providerId === 'auth-otp-form' && action.requirement === 'ALTERNATIVE') || !providers.some(provider => provider.alias === 'CONFIGURE_RECOVERY_AUTHN_CODES' && provider.enabled === true)) throw new IdentityProvisioningError('Qualified owner recovery policy differs; reset refused');
      for (const [execution, reference, alias] of [[factor[0], 'mfa', 'verified-owner-recovery'], [password[0], 'pwd', 'verified-password']]) {
        if (!execution.authenticationConfig) throw new IdentityProvisioningError('Owner MFA reference configuration is missing');
        const referenceConfig = await call(`/admin/realms/platform/authentication/config/${encodeURIComponent(execution.authenticationConfig)}`, {}, token);
        // Keycloak 26.8 masks universal AMR properties as unknown metadata.
        // A mask is not a value attestation: retain exact company aliases and
        // execution shape, and keep token/MFA acceptance independently strict.
        // This operation never changes authenticator references or grants.
        if (referenceConfig.alias !== alias || ![reference, '**********'].includes(referenceConfig.config?.['default.reference.value']) || !['1800', '**********'].includes(referenceConfig.config?.['default.reference.maxAge'])) throw new IdentityProvisioningError('Owner MFA reference policy differs; reset refused');
      }
      configureRecovery = true;
    }
  }
  const requiredActions = [...new Set([...(owner.requiredActions ?? []), 'UPDATE_PASSWORD', ...(config.resetTotp === true ? ['CONFIGURE_TOTP'] : []), ...(configureRecovery ? ['CONFIGURE_RECOVERY_AUTHN_CODES'] : [])])];
  await call(`/admin/realms/platform/users/${owner.id}`, { method: 'PUT', body: JSON.stringify({ ...owner, requiredActions }) }, token);
  if (config.resetTotp === true) {
    for (const credential of [...otp, ...recovery]) await call(`/admin/realms/platform/users/${owner.id}/credentials/${encodeURIComponent(credential.id)}`, { method: 'DELETE' }, token);
  }
  await call(`/admin/realms/platform/users/${owner.id}/reset-password`, { method: 'PUT', body: JSON.stringify({ type: 'password', value: config.ownerPassword, temporary: true }) }, token);
  await call(`/admin/realms/platform/users/${owner.id}/logout`, { method: 'POST' }, token);
  const after = await call(`/admin/realms/platform/users/${owner.id}/credentials`, {}, token);
  if (config.resetTotp === true && after.some(credential => credential.type === 'otp')) throw new IdentityProvisioningError('Owner TOTP removal verification failed');
  if (config.resetTotp === true && after.some(credential => credential.type === 'recovery-authn-codes')) throw new IdentityProvisioningError('Owner recovery-code removal verification failed');
  const confirmed = await call(`/admin/realms/platform/users/${owner.id}`, {}, token);
  if (!requiredActions.every(action => confirmed.requiredActions?.includes(action))) throw new IdentityProvisioningError('Owner re-enrollment verification failed');
  output(JSON.stringify({ ownerSubject: owner.id, passwordReset: true, totpReset: config.resetTotp === true, removedTotpCredentials: config.resetTotp === true ? otp.length : 0, removedRecoveryCredentials: config.resetTotp === true ? recovery.length : 0, recoveryEnrollmentRequired: configureRecovery, sessionsInvalidated: true, requiredActions }));
  return;
}
const clients = await call('/admin/realms/master/clients?clientId=autosoft-provisioner', {}, token);
let client = clients[0];
if (!client) {
  await call('/admin/realms/master/clients', { method: 'POST', body: JSON.stringify({ clientId: 'autosoft-provisioner', enabled: true, protocol: 'openid-connect', publicClient: false, secret: config.provisionerSecret, standardFlowEnabled: false, directAccessGrantsEnabled: false, serviceAccountsEnabled: true, fullScopeAllowed: true }), expectedStatus: 201 }, token);
  client = (await call('/admin/realms/master/clients?clientId=autosoft-provisioner', {}, token))[0];
}
const account = await call(`/admin/realms/master/clients/${client.id}/service-account-user`, {}, token);
const role = await call('/admin/realms/master/roles/create-realm', {}, token);
await call(`/admin/realms/master/users/${account.id}/role-mappings/realm`, { method: 'POST', body: JSON.stringify([role]) }, token);
// Verify the permanent client can obtain a token. Do not leave an untested provisioning credential.
await call('/realms/master/protocol/openid-connect/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'autosoft-provisioner', client_secret: config.provisionerSecret }) });
if (config.directoryReaderSecret) {
  const readerName = 'platform-directory-reader', realm = '/admin/realms/platform';
  if (typeof config.directoryReaderSecret !== 'string' || config.directoryReaderSecret.length < 32) throw new IdentityProvisioningError('Protected directory reader credential is invalid');
  const found = await call(`${realm}/clients?clientId=${readerName}`, {}, token);
  if (found.length > 1) throw new IdentityProvisioningError('Directory reader identity is ambiguous');
  const desired = { clientId: readerName, enabled: true, protocol: 'openid-connect', publicClient: false, secret: config.directoryReaderSecret, standardFlowEnabled: false, directAccessGrantsEnabled: false, implicitFlowEnabled: false, serviceAccountsEnabled: true, fullScopeAllowed: false, attributes: { 'autosoft.directory-reader': '1' } };
  if (!found.length) await call(`${realm}/clients`, { method: 'POST', body: JSON.stringify(desired) }, token);
  const readers = await call(`${realm}/clients?clientId=${readerName}`, {}, token);
  if (readers.length !== 1) throw new IdentityProvisioningError('Exact protected directory reader unavailable');
  const reader = await call(`${realm}/clients/${readers[0].id}`, {}, token);
  if (reader.clientId !== readerName || reader.attributes?.['autosoft.directory-reader'] !== '1' || !reader.enabled || reader.publicClient || !reader.serviceAccountsEnabled || reader.standardFlowEnabled || reader.directAccessGrantsEnabled || reader.implicitFlowEnabled || reader.fullScopeAllowed) throw new IdentityProvisioningError('Existing directory reader policy differs; company review required');
  const account = await call(`${realm}/clients/${reader.id}/service-account-user`, {}, token);
  const managers = await call(`${realm}/clients?clientId=realm-management`, {}, token);
  if (managers.length !== 1) throw new IdentityProvisioningError('Exact platform management client unavailable');
  const managementId = managers[0].id, names = ['view-users', 'view-realm', 'view-identity-providers'];
  const existing = await call(`${realm}/users/${account.id}/role-mappings`, {}, token);
  if (existing.realmMappings?.some(role => ['platform-owner', 'platform-admin', 'platform-builder', 'platform-viewer'].includes(role.name)) || Object.values(existing.clientMappings ?? {}).some(mapping => mapping.id === managementId && mapping.mappings.some(role => !names.includes(role.name)))) throw new IdentityProvisioningError('Directory reader has unexpected privileges; provisioning refused');
  const roles = await Promise.all(names.map(name => call(`${realm}/clients/${managementId}/roles/${name}`, {}, token)));
  const scopes = await call(`${realm}/clients/${reader.id}/scope-mappings/clients/${managementId}`, {}, token);
  if (scopes.some(role => !names.includes(role.name))) throw new IdentityProvisioningError('Directory reader token scope has unexpected privileges; provisioning refused');
  await call(`${realm}/clients/${reader.id}/scope-mappings/clients/${managementId}`, { method: 'POST', body: JSON.stringify(roles) }, token);
  await call(`${realm}/users/${account.id}/role-mappings/clients/${managementId}`, { method: 'POST', body: JSON.stringify(roles) }, token);
  const confirmed = await call(`${realm}/users/${account.id}/role-mappings/clients/${managementId}`, {}, token);
  if (confirmed.length !== names.length || !names.every(name => confirmed.some(role => role.name === name && role.clientRole && role.containerId === managementId))) throw new IdentityProvisioningError('Directory reader read-only role verification failed');
  // Token verification proves the stable protected credential without replacing
  // an existing client's secret, roles outside this reader, or user accounts.
  const readonlyToken = (await call('/realms/platform/protocol/openid-connect/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'client_credentials', client_id: readerName, client_secret: config.directoryReaderSecret }) })).access_token;
  await call(`${realm}/users/profile`, {}, readonlyToken);
  await call(`${realm}/identity-provider/instances`, {}, readonlyToken);
}
output('Scoped app realm provisioner configured.');

}

export async function readConfiguration(input = process.stdin, signal = AbortSignal.timeout(OPERATION_MS)) {
  const chunks = [], iterator = input[Symbol.asyncIterator]();
  let size = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const { value, done } = await beforeDeadline(iterator.next(), signal);
      if (done) break;
      size += value.byteLength;
      if (size > MAX_INPUT) throw new IdentityProvisioningError('Protected identity input exceeds the permitted size');
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    if (error instanceof IdentityProvisioningError) throw error;
    throw new IdentityProvisioningError('Protected identity input did not complete');
  } finally { input.destroy(); }
  try { return JSON.parse(Buffer.concat(chunks, size).toString('utf8')); }
  catch { throw new IdentityProvisioningError('Protected identity input is not valid JSON'); }
}

// This mode is for a fresh, not-yet-public installation. It performs no realm,
// user, client, credential, role or flow writes. OAuth token acquisition remains
// POST and can create authentication/audit events at the identity service.
export async function verifyInitialIdentity(config, { fetchImpl = fetch, output = console.log, operationSignal = AbortSignal.timeout(OPERATION_MS) } = {}) {
  const refuse = () => { throw new IdentityProvisioningError('Initial identity policy verification failed; public startup remains refused'); };
  const need = value => { if (!value) refuse(); };
  const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
  const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value);
  need(config?.action === 'verify-initial' && credential(config.bootstrapPassword) && credential(config.provisionerSecret)
    && credential(config.directoryReaderSecret) && uuid(config.ownerSubject));
  let origin;
  try { origin = new URL(config.adminOrigin); } catch { refuse(); }
  need(origin.protocol === 'https:' && origin.origin === config.adminOrigin && !origin.username && !origin.password
    && Array.isArray(config.ssoAliases) && new Set(config.ssoAliases).size === config.ssoAliases.length
    && config.ssoAliases.every(alias => ['google', 'microsoft'].includes(alias)));
  const call = transport(fetchImpl, operationSignal);
  const token = (await call('/realms/master/protocol/openid-connect/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'bootstrap-admin', password: config.bootstrapPassword }) })).access_token;
  need(typeof token === 'string' && token.length > 0 && token.length <= 65536);
  const get = path => call('/admin/realms/' + path, {}, token);
  const only = rows => { need(Array.isArray(rows) && rows.length === 1 && uuid(rows[0].id)); return rows[0]; };
  const realm = await get('platform');
  const expected = { realm: 'platform', enabled: true, sslRequired: 'all', registrationAllowed: false,
    resetPasswordAllowed: false, loginWithEmailAllowed: true, duplicateEmailsAllowed: false,
    bruteForceProtected: true, failureFactor: 5, accessTokenLifespan: 300, ssoSessionIdleTimeout: 1800,
    ssoSessionMaxLifespan: 28800, passwordPolicy: 'length(16) and digits(1) and lowerCase(1) and upperCase(1) and specialChars(1)',
    otpPolicyType: 'totp', otpPolicyAlgorithm: 'HmacSHA1', otpPolicyDigits: 6, otpPolicyPeriod: 30,
    otpPolicyLookAheadWindow: 1, browserFlow: 'platform-browser' };
  need(Object.entries(expected).every(([key, value]) => realm[key] === value));
  const owners = await get('platform/roles/platform-owner/users?first=0&max=2');
  need(only(owners).id === config.ownerSubject);
  const owner = await get('platform/users/' + config.ownerSubject);
  need(owner.id === config.ownerSubject && owner.username === 'owner' && owner.enabled === true && !owner.federationLink);
  need(same([...(owner.requiredActions ?? [])].sort(), ['CONFIGURE_RECOVERY_AUTHN_CODES', 'CONFIGURE_TOTP', 'UPDATE_PASSWORD']));
  need(same(await get('platform/users/' + config.ownerSubject + '/federated-identity'), []));
  const credentials = await get('platform/users/' + config.ownerSubject + '/credentials');
  need(Array.isArray(credentials) && credentials.length === 1 && credentials[0].type === 'password');
  const admins = await get('platform/roles/platform-admin/users?first=0&max=2');
  need(only(admins).id === config.ownerSubject);
  const ownerRoles = await get('platform/users/' + config.ownerSubject + '/role-mappings/realm/composite');
  need(Array.isArray(ownerRoles) && same(ownerRoles.filter(r => r.name?.startsWith('platform-')).map(r => r.name).sort(), ['platform-admin', 'platform-owner']));
  const required = await get('platform/authentication/required-actions');
  for (const alias of ['UPDATE_PASSWORD', 'CONFIGURE_TOTP', 'CONFIGURE_RECOVERY_AUTHN_CODES']) {
    const matches = required.filter(row => row.alias === alias);
    need(matches.length === 1 && matches[0].providerId === alias && matches[0].enabled === true);
  }
  const reference = async (row, alias, value) => {
    need(typeof row.authenticationConfig === 'string' && uuid(row.authenticationConfig));
    const cfg = await get('platform/authentication/config/' + row.authenticationConfig);
    // A masked value is not proof. This fresh stage stays unqualified when the
    // server cannot expose exact authenticated readback of these references.
    need(cfg.alias === alias && cfg.config?.['default.reference.value'] === value
      && cfg.config?.['default.reference.maxAge'] === '1800');
  };
  const flows = [
    ['platform-browser', [['identity-provider-redirector', 'ALTERNATIVE'], ['flow:platform-forms', 'ALTERNATIVE']]],
    ['platform-forms', [['auth-username-password-form', 'REQUIRED', 'verified-password', 'pwd'], ['flow:platform-owner-second-factor', 'CONDITIONAL']]],
    ['platform-owner-second-factor', [['conditional-user-configured', 'REQUIRED'], ['auth-otp-form', 'ALTERNATIVE', 'verified-otp', 'otp'], ['auth-recovery-authn-code-form', 'ALTERNATIVE', 'verified-owner-recovery', 'mfa']]],
    ['platform-sso-otp', [['auth-otp-form', 'REQUIRED', 'verified-otp', 'otp']]],
  ];
  for (const [alias, wanted] of flows) {
    const tree = await get('platform/authentication/flows/' + alias + '/executions');
    need(Array.isArray(tree) && tree.every(row => Number.isInteger(row.level) && row.level >= 0));
    const direct = tree.filter(row => row.level === 0).sort((a, b) => a.index - b.index);
    need(direct.length === wanted.length && direct.every(row => Number.isInteger(row.index)));
    need(new Set(direct.map(row => row.index)).size === direct.length);
    for (let i = 0; i < wanted.length; i++) {
      const row = direct[i], [name, requirement, referenceAlias, value] = wanted[i];
      need(row.requirement === requirement && (name.startsWith('flow:')
        ? row.authenticationFlow === true && row.displayName === name.slice(5)
        : row.authenticationFlow !== true && row.providerId === name));
      if (referenceAlias) await reference(row, referenceAlias, value);
    }
  }
  const providers = await get('platform/identity-provider/instances');
  need(Array.isArray(providers) && same(providers.map(p => p.alias).sort(), [...config.ssoAliases].sort()));
  need(providers.every(p => p.enabled === true && p.trustEmail === false && p.postBrokerLoginFlowAlias === 'platform-sso-otp'
    && p.firstBrokerLoginFlowAlias === 'first broker login' && p.providerId === (p.alias === 'google' ? 'google' : 'oidc')));
  const client = async (name, realmName = 'platform') => {
    const row = only(await get(realmName + '/clients?clientId=' + encodeURIComponent(name)));
    const value = await get(realmName + '/clients/' + row.id);
    need(value.id === row.id && value.clientId === name && value.enabled === true && value.protocol === 'openid-connect');
    return value;
  };
  const admin = await client('autosoft-admin');
  need(admin.publicClient === false && admin.standardFlowEnabled === true && admin.directAccessGrantsEnabled === false
    && admin.implicitFlowEnabled === false && admin.serviceAccountsEnabled === false
    && same(admin.redirectUris, [config.adminOrigin + '/auth/callback']) && same(admin.webOrigins, [config.adminOrigin])
    && admin.attributes?.['pkce.code.challenge.method'] === 'S256');
  const mappers = [
    ['verified-authentication-method', 'oidc-amr-mapper', { 'id.token.claim': 'true', 'access.token.claim': 'true' }],
    ['admin-audience', 'oidc-audience-mapper', { 'included.client.audience': 'autosoft-admin', 'access.token.claim': 'true', 'id.token.claim': 'false' }],
    ['verified-identity-provider', 'oidc-usersessionmodel-note-mapper', { 'user.session.note': 'identity_provider', 'claim.name': 'identity_provider', 'jsonType.label': 'String', 'access.token.claim': 'true', 'id.token.claim': 'true' }],
  ];
  need(Array.isArray(admin.protocolMappers) && admin.protocolMappers.length === mappers.length);
  for (const [name, mapper, fields] of mappers) {
    const rows = admin.protocolMappers.filter(row => row.name === name);
    need(rows.length === 1 && rows[0].protocol === 'openid-connect' && rows[0].protocolMapper === mapper
      && Object.entries(fields).every(([key, value]) => rows[0].config?.[key] === value));
  }
  const provisioner = await client('autosoft-provisioner', 'master');
  need(provisioner.publicClient === false && provisioner.standardFlowEnabled === false && provisioner.directAccessGrantsEnabled === false
    && provisioner.implicitFlowEnabled === false && provisioner.serviceAccountsEnabled === true && provisioner.fullScopeAllowed === true);
  const account = await get('master/clients/' + provisioner.id + '/service-account-user'); need(uuid(account.id));
  const grants = await get('master/users/' + account.id + '/role-mappings/realm/composite');
  const allowed = new Set(['create-realm', 'default-roles-master', 'offline_access', 'uma_authorization']);
  need(Array.isArray(grants) && grants.some(role => role.name === 'create-realm') && grants.every(role => allowed.has(role.name)));
  const allGrants = await get('master/users/' + account.id + '/role-mappings');
  need(Object.values(allGrants.clientMappings ?? {}).every(mapping => mapping.mappings?.length === 0));
  const reader = await client('platform-directory-reader');
  need(reader.attributes?.['autosoft.directory-reader'] === '1' && reader.publicClient === false && reader.standardFlowEnabled === false
    && reader.directAccessGrantsEnabled === false && reader.implicitFlowEnabled === false && reader.serviceAccountsEnabled === true && reader.fullScopeAllowed === false);
  const readerAccount = await get('platform/clients/' + reader.id + '/service-account-user'); need(uuid(readerAccount.id));
  const management = await client('realm-management');
  const roles = ['view-identity-providers', 'view-realm', 'view-users'];
  const exactRoles = rows => Array.isArray(rows) && same(rows.map(r => r.name).sort(), roles)
    && rows.every(r => r.clientRole === true && r.containerId === management.id);
  need(exactRoles(await get('platform/users/' + readerAccount.id + '/role-mappings/clients/' + management.id)));
  need(exactRoles(await get('platform/clients/' + reader.id + '/scope-mappings/clients/' + management.id)));
  const mappings = await get('platform/users/' + readerAccount.id + '/role-mappings');
  need(!(mappings.realmMappings ?? []).some(r => r.name?.startsWith('platform-'))
    && Object.values(mappings.clientMappings ?? {}).every(mapping => mapping.id === management.id && exactRoles(mapping.mappings)));
  // Fresh installation supports no pre-existing groups or other users. This
  // refuses inherited group grants rather than confusing direct-role member
  // listings with complete effective membership. The composite endpoint below
  // also expands indirect realm-role assignments for every allowed user.
  need(same(await get('platform/groups?first=0&max=1'), []));
  const local = await client('platform-provisioner');
  need(local.publicClient === false && local.standardFlowEnabled === false && local.directAccessGrantsEnabled === false && local.serviceAccountsEnabled === true);
  const localAccount = await get('platform/clients/' + local.id + '/service-account-user'); need(uuid(localAccount.id));
  const expectedUsers = new Map([[config.ownerSubject, 'owner'], [readerAccount.id, 'service-account-platform-directory-reader'], [localAccount.id, 'service-account-platform-provisioner']]);
  need(expectedUsers.size === 3);
  // Keycloak26.8.1's unfiltered listing excludes service accounts. Its explicit
  // enabled filter includes them; query BOTH values so disabled identities do
  // not disappear from qualification. No disabled account is expected fresh.
  const users = await get('platform/users?enabled=true&first=0&max=4');
  need(same(await get('platform/users?enabled=false&first=0&max=1'), []));
  need(Array.isArray(users) && users.length === 3 && new Set(users.map(user => user.id)).size === 3);
  for (const user of users) {
    need(expectedUsers.get(user.id) === user.username && user.enabled === true && !user.federationLink);
    need(same(await get('platform/users/' + user.id + '/groups?first=0&max=1'), []));
    const effective = await get('platform/users/' + user.id + '/role-mappings/realm/composite');
    need(Array.isArray(effective));
    const protectedRoles = effective.filter(role => ['platform-owner', 'platform-admin'].includes(role.name)).map(role => role.name).sort();
    need(same(protectedRoles, user.id === config.ownerSubject ? ['platform-admin', 'platform-owner'] : []));
  }
  const inventories = new Map();
  for (const realmName of ['master', 'platform']) {
    const listed = await get(realmName + '/clients?first=0&max=33');
    need(Array.isArray(listed) && listed.length > 0 && listed.length <= 32
      && listed.every(c => uuid(c.id) && typeof c.clientId === 'string')
      && new Set(listed.map(c => c.id)).size === listed.length && new Set(listed.map(c => c.clientId)).size === listed.length);
    inventories.set(realmName, listed);
  }
  const readerClosure = ['query-groups', 'query-users', ...roles].sort();
  for (const [realmName, subject, administrativeId, desired] of [
    ['master', account.id, null, []],
    ['platform', readerAccount.id, management.id, readerClosure],
    ['platform', localAccount.id, management.id, ['manage-clients']],
  ]) {
    const listed = inventories.get(realmName);
    if (administrativeId) need(listed.some(client => client.id === administrativeId && client.clientId === 'realm-management'));
    for (const item of listed) {
      const effective = await get(realmName + '/users/' + subject + '/role-mappings/clients/' + item.id + '/composite');
      need(Array.isArray(effective) && effective.every(role => role.clientRole === true && role.containerId === item.id));
      const names = effective.map(role => role.name).sort(); need(new Set(names).size === names.length);
      // Ordinary service-account defaults can include these own-account roles.
      // They never authorize realm/client/user administration.
      if (item.clientId === 'account') need(names.every(name => ['manage-account', 'manage-account-links', 'view-profile'].includes(name)));
      else need(same(names, item.id === administrativeId ? desired : []));
    }
  }
  for (const [realmName, clientId, secret] of [['master', 'autosoft-provisioner', config.provisionerSecret], ['platform', 'platform-directory-reader', config.directoryReaderSecret]]) {
    const issued = await call('/realms/' + realmName + '/protocol/openid-connect/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: secret }) });
    need(typeof issued?.access_token === 'string' && issued.access_token.length > 0);
  }
  output(JSON.stringify({ scope: 'INITIAL_IDENTITY_POLICY_READBACK', ownerSubject: config.ownerSubject,
    configuredPolicyVerified: true, browserMfaQualified: false, publicStartupAllowed: false }));
}

export async function requireIdentityReadiness({ fetchImpl = fetch, operationSignal = AbortSignal.timeout(OPERATION_MS) } = {}) {
  const health = await transport(fetchImpl, operationSignal)('https://keycloak:9000/health/ready');
  if (health?.status !== 'UP' || !Array.isArray(health.checks) || !health.checks.every(check => check.status === 'UP')) {
    throw new IdentityProvisioningError('Private identity readiness is unconfirmed; no provisioning mutation was attempted');
  }
}

export async function runNativeIdentity(config, options = {}) {
  if (config?.action !== 'verify-initial') validateConfig(config);
  await requireIdentityReadiness(options);
  return (config?.action === 'verify-initial' ? verifyInitialIdentity : runProvisioning)(config, options);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const operationSignal = AbortSignal.timeout(OPERATION_MS);
  try { await runNativeIdentity(await readConfiguration(process.stdin, operationSignal), { operationSignal }); }
  catch (error) {
    console.error(error instanceof IdentityProvisioningError ? error.message : 'Identity setup did not complete; inspect its current state before retrying');
    process.exitCode = 1;
  }
}
