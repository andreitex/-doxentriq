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
    if (typeof path !== 'string' || !path.startsWith('/admin/realms/') && !path.startsWith('/realms/') || path.includes('#') || path.includes('\\') || /[\r\n\0]/.test(path)) throw new IdentityProvisioningError('Invalid identity endpoint');
    const { expectedStatus, ...request } = options;
    const signal = AbortSignal.any([operationSignal, AbortSignal.timeout(REQUEST_MS)]);
    let result, reader;
    try {
      signal.throwIfAborted();
      result = await beforeDeadline(fetchImpl(BASE + path, { ...request, redirect: 'error', signal, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...request.headers } }), signal);
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const operationSignal = AbortSignal.timeout(OPERATION_MS);
  try { await runProvisioning(await readConfiguration(process.stdin, operationSignal), { operationSignal }); }
  catch (error) {
    console.error(error instanceof IdentityProvisioningError ? error.message : 'Identity setup did not complete; inspect its current state before retrying');
    process.exitCode = 1;
  }
}
