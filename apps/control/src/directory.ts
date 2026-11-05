import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import type { AppAccessSnapshot } from '../../../packages/core/src/access.ts';
import type { DirectoryApproval, DirectoryActivation, DirectoryScope, DirectorySubject, DirectoryDependencies, DirectoryIdentityConfiguration } from '../../../packages/core/src/directory.ts';
import { requireOwner } from './auth.ts';
import { validateAccessSnapshot } from './access.ts';
import type { Store, State } from './store.ts';
import { notify } from './store.ts';
import type { Config } from './config.ts';
import { createDirectoryHttp, type DirectoryHttp } from './directory-http.ts';
import { resolveDirectoryMembership, verifyDirectoryConnection, validateDirectoryCredentials } from './directory-provider.ts';

const uuid = z.string().uuid(), hex = z.string().regex(/^[a-f0-9]{64}$/), immutable = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);
const domain = z.string().regex(/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,}$/);
const scopeBody = z.object({ connectionId: uuid, provider: z.enum(['microsoft', 'google']), tenantId: immutable, workspaceDomain: domain.nullable().default(null), groupIds: z.array(immutable).min(1).max(50), evidenceTtlSeconds: z.number().int().min(1).max(300).default(60), accessExpiresAt: z.string().datetime() }).strict();
const configurationSchema = z.object({ appId: uuid, provider: z.enum(['microsoft', 'google']), tenantId: immutable, workspaceDomain: domain.nullable(), bindingHash: hex, checkedAt: z.string().datetime() }).strict();
const subjectSchema = configurationSchema.omit({}).extend({ appSubject: uuid, upstreamUserId: immutable, policyHash: hex, releaseId: uuid }).strict();
const fault = (statusCode: number, message: string) => Object.assign(new Error(message), { statusCode });
const sha = (value: string) => createHash('sha256').update(value).digest('hex');
const fresh = (value: string, max = 60000) => Number.isFinite(Date.parse(value)) && Date.parse(value) <= Date.now() + 10000 && Date.now() - Date.parse(value) <= max;
export const directoryArtifactHash = (scope: DirectoryScope) => hashArtifact({ action: 'activate_directory', scope });
function crypt(key: Buffer, id: string, value: unknown): string {
  const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(Buffer.from(id)); const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]); return [nonce, cipher.getAuthTag(), encrypted].map(part => part.toString('base64')).join('.');
}
function decrypt(key: Buffer, id: string, value: string): unknown {
  try {
    if (value.length > 40000 || value.split('.').length !== 3) throw new Error(); const [nonce, tag, encrypted] = value.split('.').map(part => Buffer.from(part, 'base64'));
    if (nonce!.length !== 12 || tag!.length !== 16) throw new Error(); const decipher = createDecipheriv('aes-256-gcm', key, nonce!); decipher.setAAD(Buffer.from(id)); decipher.setAuthTag(tag!); return JSON.parse(Buffer.concat([decipher.update(encrypted!), decipher.final()]).toString('utf8'));
  } catch { throw fault(503, 'Protected directory evidence or credential is unavailable. Use protected setup; never enter credentials in chat.'); }
}
export function validateDirectoryScope(state: State, scope: DirectoryScope, snapshot: AppAccessSnapshot): void {
  validateAccessSnapshot(snapshot, state, scope.appId);
  const connection = state.connections[scope.connectionId], app = state.apps[scope.appId];
  const expires = Date.parse(scope.accessExpiresAt), credentialExpires = connection?.expiresAt ? Date.parse(connection.expiresAt) : Infinity;
  if (!app || app.status === 'archived' || scope.schemaVersion !== 1 || !hex.safeParse(scope.identityBindingHash).success || scope.policyHash !== snapshot.policyHash || !connection || connection.type !== scope.provider || connection.status !== 'configured' || !connection.appIds.includes(app.id) || connection.secretRef !== scope.credentialRef || !state.secrets[scope.credentialRef] || sha(state.secrets[scope.credentialRef]!) !== scope.credentialCiphertextSha256 || hashArtifact(connection) !== scope.registryHash) throw fault(409, 'The app, approved policy, directory registry or credential version changed. Group permissions are unavailable until a new review.');
  if (connection.capabilities.length !== 1 || connection.capabilities[0] !== 'directory.groups.read' || connection.roots.length !== 1 || connection.roots[0] !== scope.tenantId || connection.endpoints.length !== 1 || connection.endpoints[0] !== (scope.provider === 'microsoft' ? 'https://graph.microsoft.com/v1.0' : 'https://admin.googleapis.com/admin/directory/v1')) throw fault(409, 'Directory connections require one exact official directory endpoint, immutable tenant/customer root and only directory.groups.read capability.');
  if (!Number.isFinite(expires) || expires <= Date.now() || expires > Date.now() + 90 * 86400000 || !Number.isFinite(credentialExpires) && credentialExpires !== Infinity || expires > credentialExpires || scope.evidenceTtlSeconds < 1 || scope.evidenceTtlSeconds > 300 || !Number.isInteger(scope.evidenceTtlSeconds)) throw fault(409, 'Directory authorization expires within 90 days and credential lifetime; evidence may remain valid for at most five minutes.');
  if (scope.provider === 'microsoft' ? !uuid.safeParse(scope.tenantId).success || scope.workspaceDomain !== null || scope.groupIds.some(id => !uuid.safeParse(id).success) : !/^C[A-Za-z0-9_-]{1,127}$/.test(scope.tenantId) || !domain.safeParse(scope.workspaceDomain).success) throw fault(400, 'Use immutable Microsoft tenant/group IDs or a Workspace customer ID and exact hosted domain.');
  if (new Set(scope.groupIds).size !== scope.groupIds.length || !scope.groupIds.length || scope.groupIds.length > 50 || scope.groupIds.some(id => !snapshot.policy.groupMappings.some(mapping => mapping.provider === scope.provider && mapping.tenantId === scope.tenantId && mapping.groupId === id && mapping.connectionId === scope.connectionId))) throw fault(409, 'Each directory group must already be an inactive draft in the exact approved app policy.');
}
function protectedCredentials(state: State, config: Config, scope: DirectoryScope): unknown {
  const value = decrypt(config.secretKey, scope.credentialRef, state.secrets[scope.credentialRef]!); try { validateDirectoryCredentials(scope, value); } catch { throw fault(409, 'Directory credentials require the dedicated provider schema and explicitly consented read scopes. Complete protected setup, never chat.'); } return value;
}
function exactApproval(state: State, id: string, appId: string, snapshot: AppAccessSnapshot, approved: boolean): DirectoryApproval {
  const item = state.directoryApprovals[id];
  if (!item || item.appId !== appId || item.action !== 'activate_directory' || item.artifactHash !== directoryArtifactHash(item.scope) || item.consumedAt || Date.parse(item.expiresAt) <= Date.now() || !Number.isFinite(Date.parse(item.expiresAt)) || approved && (!item.approvedBy || !item.approvedAt)) throw fault(409, 'An unused five-minute review for this exact directory authorization is required.'); validateDirectoryScope(state, item.scope, snapshot); return item;
}
function validateConfiguration(value: unknown, scope: Pick<DirectoryScope, 'appId' | 'provider' | 'tenantId' | 'workspaceDomain'>): DirectoryIdentityConfiguration {
  const parsed = configurationSchema.safeParse(value);
  if (!parsed.success || parsed.data.appId !== scope.appId || parsed.data.provider !== scope.provider || parsed.data.tenantId !== scope.tenantId || parsed.data.workspaceDomain !== scope.workspaceDomain || !fresh(parsed.data.checkedAt)) throw fault(503, 'Exact protected provider configuration is missing or stale; no directory permission was activated.'); return parsed.data;
}
/** Each call is bounded. The resolver performs fixed reads and token exchanges only. */
function boundedReads(http: DirectoryHttp): DirectoryHttp {
  const started = Date.now(); let count = 0;
  return async input => { if (++count > 80 || Date.now() - started > 30000) throw fault(503, 'Directory resolution exceeded its read/time bounds.'); const result = await http(input); if (Date.now() - started > 30000) throw fault(503, 'Directory resolution exceeded its time bound.'); return result; };
}
export async function installDirectoryRoutes(server: FastifyInstance, store: Store, config: Config, dependencies: DirectoryDependencies, options: { http?: DirectoryHttp } = {}): Promise<void> {
  const http = options.http ?? createDirectoryHttp();
  // Keep the remote read outside the serialized store transaction.
  async function currentSnapshot(appId: string): Promise<AppAccessSnapshot> {
    if (!dependencies.accessSnapshot) throw fault(503, 'Protected application access service unavailable.'); const result = await dependencies.accessSnapshot({ appId }); return store.read(state => validateAccessSnapshot(result, state, appId));
  }
  async function configuration(scope: Pick<DirectoryScope, 'appId' | 'provider' | 'tenantId' | 'workspaceDomain'>) { if (!dependencies.directoryIdentityConfiguration) throw fault(503, 'Protected immutable-provider configuration reader unavailable. Contact the company operator.'); const input = { appId: scope.appId, provider: scope.provider, tenantId: scope.tenantId, workspaceDomain: scope.workspaceDomain }; return validateConfiguration(await dependencies.directoryIdentityConfiguration(input), scope); }
  server.get<{ Params: { id: string } }>('/api/v1/apps/:id/access/directory', async request => { requireOwner(request); const evidence = await currentSnapshot(request.params.id); return store.read(state => ({ policyHash: evidence.policyHash, approvals: Object.values(state.directoryApprovals).filter(item => item.appId === request.params.id), activations: Object.values(state.directoryActivations).filter(item => item.appId === request.params.id).map(item => { let available = !item.disabledAt; try { validateDirectoryScope(state, item.scope, evidence); } catch { available = false; } return { ...item, available, detail: available ? 'Activated for per-request immutable identity and fresh membership checks; this is not a permanent role grant.' : 'Authorization disabled, expired or changed. Group access fails closed.' }; }) })); });
  server.post<{ Params: { id: string } }>('/api/v1/apps/:id/access/directory/approval', async request => {
    requireOwner(request); const body = scopeBody.parse(request.body), evidence = await currentSnapshot(request.params.id), identity = await configuration({ appId: request.params.id, ...body });
    const approval = await store.transaction(state => {
      const connection = state.connections[body.connectionId]; if (!connection?.secretRef || !state.secrets[connection.secretRef]) throw fault(409, 'Protected directory credentials must be configured before review.');
      const scope: DirectoryScope = { schemaVersion: 1, ...body, appId: request.params.id, policyHash: evidence.policyHash, identityBindingHash: identity.bindingHash, registryHash: hashArtifact(connection), credentialRef: connection.secretRef, credentialCiphertextSha256: sha(state.secrets[connection.secretRef]!) }; validateDirectoryScope(state, scope, evidence); protectedCredentials(state, config, scope);
      const item: DirectoryApproval = { id: randomUUID(), action: 'activate_directory', appId: scope.appId, scope, artifactHash: directoryArtifactHash(scope), impact: [`Activate ${scope.provider} directory group authorization only for ${state.apps[scope.appId]!.name} (${scope.appId}).`, `Immutable tenant/customer: ${scope.tenantId}${scope.workspaceDomain ? `; hosted domain: ${scope.workspaceDomain}` : ''}. Exact groups: ${scope.groupIds.join(', ')}.`, ...scope.groupIds.map(id => { const mapping = evidence.policy.groupMappings.find(mapping => mapping.connectionId === scope.connectionId && mapping.provider === scope.provider && mapping.tenantId === scope.tenantId && mapping.groupId === id)!; return `Group ${id} grants only these reviewed app permissions: ${[...new Set(mapping.roleIds.flatMap(roleId => evidence.policy.roles.find(role => role.id === roleId)!.permissions))].join(', ')}.`; }), `Evidence expires after ${scope.evidenceTtlSeconds} seconds; authorization ends ${scope.accessExpiresAt}. Revocation can take at most this evidence lifetime.`, 'Dedicated directory consent and protected immutable SSO claims are required. The connector performs fixed read operations; it does not prove that the upstream credential lacks broader permissions. Local invitations and platform privileges are separate. No permanent Keycloak group role is assigned.', 'Incomplete pagination, absent identity binding, stale evidence and provider failures grant no group permissions. Google cross-domain nested groups and Microsoft hidden-membership groups are unsupported.'], expiresAt: new Date(Date.now() + 300000).toISOString(), approvedAt: null, approvedBy: null, consumedAt: null }; state.directoryApprovals[item.id] = item; return item;
    }); return { approval };
  });
  server.post<{ Params: { id: string } }>('/api/v1/directory/approvals/:id/approve', async request => {
    requireOwner(request); const body = z.object({ artifactHash: hex }).strict().parse(request.body), original = await store.read(state => state.directoryApprovals[request.params.id]); if (!original) throw fault(404, 'Directory review not found.');
    const evidence = await currentSnapshot(original.appId), identity = await configuration(original.scope);
    return { approval: await store.transaction(state => { const item = exactApproval(state, original.id, original.appId, evidence, false); if (item.approvedAt || item.artifactHash !== body.artifactHash || identity.bindingHash !== item.scope.identityBindingHash) throw fault(409, 'The exact directory review or protected identity configuration changed.'); item.approvedAt = new Date().toISOString(); item.approvedBy = request.principal!.id; return item; }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/apps/:id/access/directory/activate', async request => {
    requireOwner(request); const body = z.object({ approvalId: uuid }).strict().parse(request.body), evidence = await currentSnapshot(request.params.id);
    const prepared = await store.read(state => { const item = exactApproval(state, body.approvalId, request.params.id, evidence, true); if (item.approvedBy !== request.principal!.id) throw fault(403, 'Only the approving permanent owner can activate this scope.'); return { approval: item, credentials: protectedCredentials(state, config, item.scope) }; });
    const identity = await configuration(prepared.approval.scope); if (identity.bindingHash !== prepared.approval.scope.identityBindingHash) throw fault(409, 'Protected provider binding changed since review.');
    try { await verifyDirectoryConnection(boundedReads(http), prepared.approval.scope, prepared.credentials); } catch { throw fault(503, 'Directory consent, tenant/customer or group verification is unavailable. Authorization remains inactive; contact the company operator.'); }
    const current = await currentSnapshot(request.params.id), refreshedIdentity = await configuration(prepared.approval.scope);
    if (refreshedIdentity.bindingHash !== identity.bindingHash) throw fault(409, 'Protected provider binding changed during verification.');
    return { activation: await store.transaction(state => { const approval = exactApproval(state, body.approvalId, request.params.id, current, true); if (approval.artifactHash !== prepared.approval.artifactHash || !fresh(identity.checkedAt)) throw fault(409, 'Directory scope or identity evidence changed during verification.'); const at = new Date().toISOString(); approval.consumedAt = at;
      for (const item of Object.values(state.directoryActivations)) if (item.appId === approval.appId && item.scope.connectionId === approval.scope.connectionId && !item.disabledAt) item.disabledAt = at;
      const activation: DirectoryActivation = { id: randomUUID(), appId: approval.appId, approvalId: approval.id, artifactHash: approval.artifactHash, scope: approval.scope, activatedAt: at, checkedAt: at, disabledAt: null }; state.directoryActivations[activation.id] = activation; notify(state, 'info', 'Directory authorization activated', `${state.apps[approval.appId]!.name}: exact immutable group policy enabled for fresh backend membership checks. No permanent identity role was assigned.`); return activation; }) };
  });
  server.post<{ Params: { id: string; activationId: string } }>('/api/v1/apps/:id/access/directory/:activationId/disable', async request => { requireOwner(request); z.object({}).strict().parse(request.body); return store.transaction(state => { const item = state.directoryActivations[request.params.activationId]; if (!item || item.appId !== request.params.id) throw fault(404, 'Directory activation not found.'); item.disabledAt = new Date().toISOString(); for (const [id, record] of Object.entries(state.directoryEvidence)) if (record.activationId === item.id) delete state.directoryEvidence[id]; return { disabled: true }; }); });
  server.post<{ Params: { id: string } }>('/api/public/v1/apps/:id/directory/authorize', async request => {
    const body = z.object({ target: z.enum(['api', 'mcp']).default('api') }).strict().parse(request.body), appId = uuid.parse(request.params.id);
    if (!dependencies.directoryIdentityKeys || !dependencies.directoryIdentitySubject || !dependencies.directoryIdentityConfiguration) throw fault(503, 'Protected directory authorization service unavailable.');
    const authorization = request.headers.authorization; if (!authorization || !/^Bearer [^\s]+$/.test(authorization) || authorization.length > 16384) throw fault(401, 'A signed app access token is required.');
    const evidence = await currentSnapshot(appId), keys = await dependencies.directoryIdentityKeys({ appId });
    const realm = 'app-' + sha(appId).slice(0, 24), issuer = config.oidcIssuer?.replace(/\/realms\/platform\/?$/, `/realms/${realm}`);
    if (!issuer || issuer === config.oidcIssuer || keys.appId !== appId || keys.releaseId !== evidence.releaseId || keys.policyHash !== evidence.policyHash || keys.issuer !== issuer || keys.audience !== `app-${appId}` || !fresh(keys.checkedAt) || !Array.isArray(keys.jwks?.keys) || !keys.jwks.keys.length || keys.jwks.keys.length > 32 || keys.jwks.keys.some(key => !['RS256', 'ES256'].includes(key.alg ?? '') || key.use !== 'sig' || ['d', 'p', 'q', 'k', 'jku', 'x5u'].some(name => Object.hasOwn(key, name)))) throw fault(503, 'Fresh keys for this exact published app issuer are unavailable.');
    let subject: string, tokenExpires: number;
    try { const { payload } = await jwtVerify(authorization.slice(7), createLocalJWKSet(keys.jwks), { issuer, audience: body.target === 'mcp' ? `${appId}:mcp` : keys.audience, algorithms: ['RS256', 'ES256'], requiredClaims: ['sub', 'iat', 'exp', 'app_id'], maxTokenAge: '15m', clockTolerance: 5 }); if (payload.app_id !== appId) throw new Error(); subject = uuid.parse(payload.sub); tokenExpires = payload.exp! * 1000; } catch { throw fault(401, 'The signed token is invalid, expired or belongs to another app/audience.'); }
    const activations = await store.read(state => Object.values(state.directoryActivations).filter(item => item.appId === appId && !item.disabledAt));
    const permissions = new Set<string>(); let validUntil = Math.min(tokenExpires, Date.now() + 300000);
    for (const activation of activations) {
      const scope = activation.scope;
      await store.read(state => { if (state.directoryActivations[activation.id]?.disabledAt || state.directoryActivations[activation.id]?.artifactHash !== activation.artifactHash) throw fault(409, 'Directory authorization changed.'); validateDirectoryScope(state, scope, evidence); });
      const identity = await configuration(scope); if (identity.bindingHash !== scope.identityBindingHash) throw fault(503, 'Protected upstream identity configuration changed; group permissions are unavailable.');
      const parsed = subjectSchema.safeParse(await dependencies.directoryIdentitySubject({ appId, appSubject: subject, provider: scope.provider, tenantId: scope.tenantId, workspaceDomain: scope.workspaceDomain }));
      if (!parsed.success || parsed.data.appId !== appId || parsed.data.appSubject !== subject || parsed.data.provider !== scope.provider || parsed.data.tenantId !== scope.tenantId || parsed.data.workspaceDomain !== scope.workspaceDomain || parsed.data.policyHash !== evidence.policyHash || parsed.data.releaseId !== evidence.releaseId || !fresh(parsed.data.checkedAt)) throw fault(503, 'Exact immutable upstream app identity is unavailable.');
      const upstream: DirectorySubject = parsed.data, recordId = sha(hashArtifact({ activationId: activation.id, bindingHash: upstream.bindingHash, appSubject: subject }));
      let groups: string[], expiresAt: string;
      const cached = await store.read(state => state.directoryEvidence[recordId]);
      const membershipSchema = z.object({ activationId: uuid, bindingHash: hex, appSubject: uuid, groupIds: z.array(immutable).max(50), checkedAt: z.string().datetime(), expiresAt: z.string().datetime() }).strict();
      if (cached && cached.appId === appId && cached.activationId === activation.id && Date.parse(cached.expiresAt) > Date.now()) {
        const proof = membershipSchema.parse(decrypt(config.secretKey, recordId, cached.encrypted));
        if (proof.activationId !== activation.id || proof.bindingHash !== upstream.bindingHash || proof.appSubject !== subject || proof.expiresAt !== cached.expiresAt || !fresh(proof.checkedAt, scope.evidenceTtlSeconds * 1000) || Date.parse(proof.expiresAt) - Date.parse(proof.checkedAt) > scope.evidenceTtlSeconds * 1000 || proof.groupIds.some(id => !scope.groupIds.includes(id))) throw fault(503, 'Stored membership evidence is invalid or stale.'); groups = proof.groupIds; expiresAt = proof.expiresAt;
      } else {
        const credentials = await store.read(state => { validateDirectoryScope(state, scope, evidence); return protectedCredentials(state, config, scope); });
        try { groups = await resolveDirectoryMembership(boundedReads(http), scope, upstream, credentials); } catch { throw fault(503, 'Directory membership is unavailable or incomplete. No group permission is granted; contact the company operator.'); }
        const resolvedPolicy = await currentSnapshot(appId);
        const checkedAt = new Date().toISOString(); expiresAt = new Date(Math.min(Date.now() + scope.evidenceTtlSeconds * 1000, Date.parse(scope.accessExpiresAt))).toISOString();
        await store.transaction(state => { validateDirectoryScope(state, scope, resolvedPolicy); const item = state.directoryActivations[activation.id]; if (!item || item.disabledAt || item.artifactHash !== activation.artifactHash) throw fault(409, 'Directory authorization was revoked during resolution.');
          for (const [id, record] of Object.entries(state.directoryEvidence)) if (Date.parse(record.expiresAt) <= Date.now()) delete state.directoryEvidence[id]; if (Object.keys(state.directoryEvidence).length >= 10000 && !state.directoryEvidence[recordId]) throw fault(503, 'Directory evidence storage bound reached.'); state.directoryEvidence[recordId] = { id: recordId, appId, activationId: activation.id, expiresAt, encrypted: crypt(config.secretKey, recordId, { activationId: activation.id, bindingHash: upstream.bindingHash, appSubject: subject, groupIds: groups, checkedAt, expiresAt }) }; });
      }
      validUntil = Math.min(validUntil, Date.parse(expiresAt), Date.parse(scope.accessExpiresAt));
      for (const mapping of evidence.policy.groupMappings) if (mapping.connectionId === scope.connectionId && mapping.provider === scope.provider && mapping.tenantId === scope.tenantId && groups.includes(mapping.groupId)) for (const roleId of mapping.roleIds) for (const permission of evidence.policy.roles.find(role => role.id === roleId)!.permissions) permissions.add(permission);
    }
    // Revalidate the protected policy after all remote reads and the exact
    // encrypted credential/registry/activation baseline before returning.
    const current = await currentSnapshot(appId); if (current.policyHash !== evidence.policyHash || current.releaseId !== evidence.releaseId || tokenExpires <= Date.now() || validUntil <= Date.now()) throw fault(409, 'App identity policy or token changed during authorization.');
    await store.read(state => { for (const activation of activations) { const item = state.directoryActivations[activation.id]; if (!item || item.disabledAt || item.artifactHash !== activation.artifactHash) throw fault(409, 'Directory authorization was revoked.'); validateDirectoryScope(state, activation.scope, current); } });
    return { appId, subject, audience: body.target === 'mcp' ? `${appId}:mcp` : keys.audience, permissions: [...permissions].sort(), policyHash: current.policyHash, checkedAt: new Date().toISOString(), validUntil: new Date(validUntil).toISOString() };
  });
}
