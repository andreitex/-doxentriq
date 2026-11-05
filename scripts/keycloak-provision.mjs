// Trusted installation code, executed in the company platform image with internal TLS.
import { readFileSync } from 'node:fs';
const config = JSON.parse(readFileSync(0, 'utf8'));
const base = 'https://keycloak:8443';
async function call(path, options = {}, token) {
  const result = await fetch(base + path, { ...options, redirect: 'error', signal: AbortSignal.timeout(15000), headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...options.headers } });
  if (!result.ok) throw new Error(`Identity provisioning failed HTTP ${result.status}`);
  return result.status === 204 || result.headers.get('content-length') === '0' ? null : result.json();
}
const token = (await call('/realms/master/protocol/openid-connect/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'bootstrap-admin', password: config.bootstrapPassword }) })).access_token;
if (config.action === 'recover-owner') {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(config.ownerSubject)) throw new Error('Invalid configured owner UUID');
  const owner = await call(`/admin/realms/platform/users/${encodeURIComponent(config.ownerSubject)}`, {}, token);
  if (owner.id !== config.ownerSubject || owner.username !== 'owner' || owner.federationLink) throw new Error('Protected local owner identity mismatch');
  const identities = await call(`/admin/realms/platform/users/${owner.id}/federated-identity`, {}, token);
  const owners = await call('/admin/realms/platform/roles/platform-owner/users?first=0&max=2', {}, token);
  if (identities.length || owners.length !== 1 || owners[0].id !== owner.id) throw new Error('Permanent local owner uniqueness check failed');
  const credentials = await call(`/admin/realms/platform/users/${owner.id}/credentials`, {}, token);
  const otp = credentials.filter(credential => credential.type === 'otp');
  const recovery = credentials.filter(credential => credential.type === 'recovery-authn-codes');
  let configureRecovery = false;
  if (config.resetTotp === true) {
    // /authentication/flows lists only top-level flows. Inspect the actual
    // browser's nested execution tree rather than treating that as absence.
    const flows = await call('/admin/realms/platform/authentication/flows/platform-browser/executions', {}, token);
    const configured = flows.filter(flow => flow.displayName === 'platform-owner-second-factor' && flow.authenticationFlow === true && flow.level === 1 && flow.requirement === 'CONDITIONAL');
    if (configured.length > 1 || (!configured.length && recovery.length)) throw new Error('Existing owner recovery policy needs company repair before reset');
    if (configured.length) {
      const realm = await call('/admin/realms/platform', {}, token);
      const providers = await call('/admin/realms/platform/authentication/required-actions', {}, token);
      const actions = await call('/admin/realms/platform/authentication/flows/platform-owner-second-factor/executions', {}, token);
      const forms = await call('/admin/realms/platform/authentication/flows/platform-forms/executions', {}, token);
      const factor = actions.filter(action => action.providerId === 'auth-recovery-authn-code-form' && action.requirement === 'ALTERNATIVE');
      const password = forms.filter(action => action.providerId === 'auth-username-password-form' && action.requirement === 'REQUIRED');
      if (realm.browserFlow !== 'platform-browser' || factor.length !== 1 || password.length !== 1 || !actions.some(action => action.providerId === 'conditional-user-configured' && action.requirement === 'REQUIRED') || !actions.some(action => action.providerId === 'auth-otp-form' && action.requirement === 'ALTERNATIVE') || !providers.some(provider => provider.alias === 'CONFIGURE_RECOVERY_AUTHN_CODES' && provider.enabled === true)) throw new Error('Qualified owner recovery policy differs; reset refused');
      for (const [execution, reference, alias] of [[factor[0], 'mfa', 'verified-owner-recovery'], [password[0], 'pwd', 'verified-password']]) {
        if (!execution.authenticationConfig) throw new Error('Owner MFA reference configuration is missing');
        const referenceConfig = await call(`/admin/realms/platform/authentication/config/${encodeURIComponent(execution.authenticationConfig)}`, {}, token);
        // Keycloak 26.8 masks universal AMR properties as unknown metadata.
        // A mask is not a value attestation: retain exact company aliases and
        // execution shape, and keep token/MFA acceptance independently strict.
        // This operation never changes authenticator references or grants.
        if (referenceConfig.alias !== alias || ![reference, '**********'].includes(referenceConfig.config?.['default.reference.value']) || !['1800', '**********'].includes(referenceConfig.config?.['default.reference.maxAge'])) throw new Error('Owner MFA reference policy differs; reset refused');
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
  if (config.resetTotp === true && after.some(credential => credential.type === 'otp')) throw new Error('Owner TOTP removal verification failed');
  if (config.resetTotp === true && after.some(credential => credential.type === 'recovery-authn-codes')) throw new Error('Owner recovery-code removal verification failed');
  const confirmed = await call(`/admin/realms/platform/users/${owner.id}`, {}, token);
  if (!requiredActions.every(action => confirmed.requiredActions?.includes(action))) throw new Error('Owner re-enrollment verification failed');
  console.log(JSON.stringify({ ownerSubject: owner.id, passwordReset: true, totpReset: config.resetTotp === true, removedTotpCredentials: config.resetTotp === true ? otp.length : 0, removedRecoveryCredentials: config.resetTotp === true ? recovery.length : 0, recoveryEnrollmentRequired: configureRecovery, sessionsInvalidated: true, requiredActions }));
  process.exit(0);
}
const clients = await call('/admin/realms/master/clients?clientId=autosoft-provisioner', {}, token);
let client = clients[0];
if (!client) {
  const result = await fetch(base + '/admin/realms/master/clients', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ clientId: 'autosoft-provisioner', enabled: true, protocol: 'openid-connect', publicClient: false, secret: config.provisionerSecret, standardFlowEnabled: false, directAccessGrantsEnabled: false, serviceAccountsEnabled: true, fullScopeAllowed: true }) });
  if (result.status !== 201) throw new Error('Cannot create scoped realm provisioner');
  client = (await call('/admin/realms/master/clients?clientId=autosoft-provisioner', {}, token))[0];
}
const account = await call(`/admin/realms/master/clients/${client.id}/service-account-user`, {}, token);
const role = await call('/admin/realms/master/roles/create-realm', {}, token);
await call(`/admin/realms/master/users/${account.id}/role-mappings/realm`, { method: 'POST', body: JSON.stringify([role]) }, token);
// Verify the permanent client can obtain a token. Do not leave an untested provisioning credential.
await call('/realms/master/protocol/openid-connect/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'autosoft-provisioner', client_secret: config.provisionerSecret }) });
if (config.directoryReaderSecret) {
  const readerName = 'platform-directory-reader', realm = '/admin/realms/platform';
  if (typeof config.directoryReaderSecret !== 'string' || config.directoryReaderSecret.length < 32) throw new Error('Protected directory reader credential is invalid');
  const found = await call(`${realm}/clients?clientId=${readerName}`, {}, token);
  if (found.length > 1) throw new Error('Directory reader identity is ambiguous');
  const desired = { clientId: readerName, enabled: true, protocol: 'openid-connect', publicClient: false, secret: config.directoryReaderSecret, standardFlowEnabled: false, directAccessGrantsEnabled: false, implicitFlowEnabled: false, serviceAccountsEnabled: true, fullScopeAllowed: false, attributes: { 'autosoft.directory-reader': '1' } };
  if (!found.length) await call(`${realm}/clients`, { method: 'POST', body: JSON.stringify(desired) }, token);
  const readers = await call(`${realm}/clients?clientId=${readerName}`, {}, token);
  if (readers.length !== 1) throw new Error('Exact protected directory reader unavailable');
  const reader = await call(`${realm}/clients/${readers[0].id}`, {}, token);
  if (reader.clientId !== readerName || reader.attributes?.['autosoft.directory-reader'] !== '1' || !reader.enabled || reader.publicClient || !reader.serviceAccountsEnabled || reader.standardFlowEnabled || reader.directAccessGrantsEnabled || reader.implicitFlowEnabled || reader.fullScopeAllowed) throw new Error('Existing directory reader policy differs; company review required');
  const account = await call(`${realm}/clients/${reader.id}/service-account-user`, {}, token);
  const managers = await call(`${realm}/clients?clientId=realm-management`, {}, token);
  if (managers.length !== 1) throw new Error('Exact platform management client unavailable');
  const managementId = managers[0].id, names = ['view-users', 'view-realm', 'view-identity-providers'];
  const existing = await call(`${realm}/users/${account.id}/role-mappings`, {}, token);
  if (existing.realmMappings?.some(role => ['platform-owner', 'platform-admin', 'platform-builder', 'platform-viewer'].includes(role.name)) || Object.values(existing.clientMappings ?? {}).some(mapping => mapping.id === managementId && mapping.mappings.some(role => !names.includes(role.name)))) throw new Error('Directory reader has unexpected privileges; provisioning refused');
  const roles = await Promise.all(names.map(name => call(`${realm}/clients/${managementId}/roles/${name}`, {}, token)));
  const scopes = await call(`${realm}/clients/${reader.id}/scope-mappings/clients/${managementId}`, {}, token);
  if (scopes.some(role => !names.includes(role.name))) throw new Error('Directory reader token scope has unexpected privileges; provisioning refused');
  await call(`${realm}/clients/${reader.id}/scope-mappings/clients/${managementId}`, { method: 'POST', body: JSON.stringify(roles) }, token);
  await call(`${realm}/users/${account.id}/role-mappings/clients/${managementId}`, { method: 'POST', body: JSON.stringify(roles) }, token);
  const confirmed = await call(`${realm}/users/${account.id}/role-mappings/clients/${managementId}`, {}, token);
  if (confirmed.length !== names.length || !names.every(name => confirmed.some(role => role.name === name && role.clientRole && role.containerId === managementId))) throw new Error('Directory reader read-only role verification failed');
  // Token verification proves the stable protected credential without replacing
  // an existing client's secret, roles outside this reader, or user accounts.
  const readonlyToken = (await call('/realms/platform/protocol/openid-connect/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'client_credentials', client_id: readerName, client_secret: config.directoryReaderSecret }) })).access_token;
  await call(`${realm}/users/profile`, {}, readonlyToken);
  await call(`${realm}/identity-provider/instances`, {}, readonlyToken);
}
console.log('Scoped app realm provisioner configured.');
