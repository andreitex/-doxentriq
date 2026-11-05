import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import type { AccessApproval, AppAccessPolicy, AppAccessSnapshot, AppInvitation, AccessActor, AccessOperationResult, AccessPolicyRequest, AcceptInvitationRequest } from '../../../packages/core/src/access.ts';
import type { Config } from './config.ts';
import type { Store, State } from './store.ts';
import { notify } from './store.ts';
import type { DirectoryDependencies } from '../../../packages/core/src/directory.ts';
import { installDirectoryRoutes } from './directory.ts';
import { installAppAccountRoutes } from './app-accounts.ts';
import type { AppAccountDependencies } from '../../../packages/core/src/app-accounts.ts';

export type InvitationRecord = AppInvitation & { tokenHash: string; status: 'pending' | 'accepting' | 'accepted' | 'revoked' | 'needs_attention'; operationId?: string; acceptedAt: string | null; userId: string | null };
export type AccessChange = { approvalId: string; policy?: AppAccessPolicy; invitation?: AppInvitation };
export type AccessOperation = { id: string; appId: string; action: 'access_policy' | 'invitation'; approvalId: string; artifactHash: string; status: 'running' | 'succeeded' | 'failed'; createdAt: string; completedAt: string | null; detail?: string; request: AccessPolicyRequest | Omit<AcceptInvitationRequest, 'password'> };
export type AccessDependencies = DirectoryDependencies & AppAccountDependencies & { accessSnapshot?: (input: { appId: string }) => Promise<AppAccessSnapshot>; applyAccessPolicy?: (input: AccessPolicyRequest) => Promise<AccessOperationResult>; acceptAppInvitation?: (input: AcceptInvitationRequest) => Promise<AccessOperationResult>; accessOperation?: (input: { appId: string; operationId: string }) => Promise<AccessOperationResult> };
const hex = z.string().regex(/^[a-f0-9]{64}$/), uuid = z.string().uuid();
const permission = z.string().regex(/^[a-z][a-z0-9._:-]{0,79}$/);
const roleSchema = z.object({ id: uuid, name: z.string().trim().min(1).max(80).regex(/^[^\x00-\x1f\u2028\u2029]+$/).refine(value => Buffer.byteLength(value) <= 80), permissions: z.array(permission).min(1).max(100) }).strict();
const mappingSchema = z.object({ provider: z.enum(['microsoft', 'google']), tenantId: z.string().min(1).max(128).regex(/^[a-zA-Z0-9_-]+$/), groupId: z.string().min(1).max(128).regex(/^[a-zA-Z0-9_-]+$/), connectionId: uuid, roleIds: z.array(uuid).min(1).max(50), status: z.literal('pending_validation') }).strict();
export const accessPolicySchema = z.object({ schemaVersion: z.literal(1), appId: uuid, invitationsEnabled: z.boolean(), requireTotp: z.literal(true), roles: z.array(roleSchema).max(50), groupMappings: z.array(mappingSchema).max(50) }).strict();
const snapshotSchema = z.object({ appId: uuid, releaseId: uuid, identityHash: hex, policyHash: hex, permissions: z.array(permission).max(100), policy: accessPolicySchema, checkedAt: z.string().datetime() }).strict();
const httpError = (statusCode: number, message: string) => Object.assign(new Error(message), { statusCode });
const now = () => new Date().toISOString();
export const accessPolicyHash = (policy: AppAccessPolicy) => hashArtifact(policy);
export const accessActionHash = (change: AccessChange, basePolicyHash: string): string => change.policy ? hashArtifact({ action: 'access_policy', appId: change.policy.appId, basePolicyHash, policy: change.policy }) : hashArtifact({ action: 'invitation', invitation: change.invitation });
const tokenHash = (value: string) => createHash('sha256').update(value).digest('hex');
const publicInvitation = ({ tokenHash: _tokenHash, ...record }: InvitationRecord) => record;
function currentApp(state: State, appId: string) { const app = state.apps[appId]; if (!app || app.status === 'archived') throw httpError(404, 'Application not found.'); return app; }
function approvedChange(state: State, id: string, appId: string, action: AccessApproval['action']): { approval: AccessApproval; change: AccessChange } {
  const approval = state.accessApprovals[id], change = state.accessChanges[id];
  if (!approval || !change || approval.appId !== appId || approval.action !== action || !approval.approvedBy || !approval.approvedAt || approval.consumedAt || !Number.isFinite(Date.parse(approval.expiresAt)) || Date.parse(approval.expiresAt) <= Date.now() || accessActionHash(change, approval.basePolicyHash) !== approval.artifactHash) throw httpError(409, 'A current approval for this exact app access action is required.');
  return { approval, change };
}
function validatePolicy(policy: AppAccessPolicy, snapshot: AppAccessSnapshot): void {
  const roleIds = new Set<string>(), names = new Set<string>();
  if (policy.appId !== snapshot.appId || accessPolicyHash(snapshot.policy) !== snapshot.policyHash || new Set(snapshot.permissions).size !== snapshot.permissions.length) throw httpError(503, 'Protected identity policy returned inconsistent evidence.');
  for (const role of policy.roles) {
    if (roleIds.has(role.id) || names.has(role.name.toLocaleLowerCase()) || new Set(role.permissions).size !== role.permissions.length || role.permissions.some(value => !snapshot.permissions.includes(value))) throw httpError(400, 'Roles must be unique and may only grant protected application permissions.');
    roleIds.add(role.id); names.add(role.name.toLocaleLowerCase());
  }
  const groups = new Set<string>();
  for (const mapping of policy.groupMappings) {
    const key = `${mapping.provider}:${mapping.tenantId}:${mapping.groupId}`;
    if (groups.has(key) || mapping.roleIds.some(id => !roleIds.has(id)) || new Set(mapping.roleIds).size !== mapping.roleIds.length || mapping.provider === 'microsoft' && (!uuid.safeParse(mapping.tenantId).success || !uuid.safeParse(mapping.groupId).success)) throw httpError(400, 'Group drafts require unique immutable provider group and tenant identifiers and approved role IDs.');
    groups.add(key);
  }
}
export function validateAccessSnapshot(value: unknown, state: State, appId: string): AppAccessSnapshot {
  const parsed = snapshotSchema.safeParse(value); if (!parsed.success) throw httpError(503, 'Protected application access evidence is unavailable or malformed.');
  const snapshot = parsed.data; const app = currentApp(state, appId);
  if (snapshot.appId !== appId || snapshot.policy.appId !== appId || snapshot.releaseId !== app.activeReleaseId || !state.releases[snapshot.releaseId] || state.releases[snapshot.releaseId]?.appId !== appId || Date.now() - Date.parse(snapshot.checkedAt) > 60000 || Date.parse(snapshot.checkedAt) > Date.now() + 10000) throw httpError(503, 'Protected application access evidence is stale or belongs to another release.');
  validatePolicy(snapshot.policy, snapshot); return snapshot;
}
function validateResult(value: unknown, operation: AccessOperation): AccessOperationResult {
  const schema = z.object({ operationId: z.string(), appId: uuid, status: z.enum(['running', 'succeeded', 'failed', 'unknown']), action: z.enum(['access_policy', 'invitation']).optional(), artifactHash: hex.optional(), policyHash: hex.optional(), invitationId: uuid.optional(), userId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$/).optional(), detail: z.string().max(1000).optional() }).strict();
  const parsed = schema.safeParse(value); if (!parsed.success || parsed.data.operationId !== operation.id || parsed.data.appId !== operation.appId || parsed.data.status !== 'unknown' && (parsed.data.artifactHash !== operation.artifactHash || parsed.data.action !== operation.action)) throw httpError(503, 'Identity operation confirmation is unavailable or does not match its exact action.');
  if (parsed.data.status === 'succeeded' && (operation.action === 'access_policy' ? parsed.data.policyHash !== accessPolicyHash((operation.request as AccessPolicyRequest).policy) : !parsed.data.userId || parsed.data.invitationId !== (operation.request as Omit<AcceptInvitationRequest, 'password'>).invitation.id)) throw httpError(503, 'Identity service did not confirm the exact approved policy or invited user.');
  return parsed.data;
}
async function finishOperation(store: Store, operation: AccessOperation, result: AccessOperationResult): Promise<void> {
  await store.transaction(state => {
    const item = state.accessOperations[operation.id]; if (!item || item.status !== 'running') return;
    if (result.status === 'succeeded' || result.status === 'failed') { item.status = result.status; item.completedAt = now(); item.detail = result.detail ?? (result.status === 'succeeded' ? 'Confirmed by the protected app identity service.' : 'The identity service reported failure.'); }
    if (item.action === 'invitation') {
      const invitation = state.invitations[(item.request as Omit<AcceptInvitationRequest, 'password'>).invitation.id];
      if (invitation && item.status === 'succeeded') { invitation.status = 'accepted'; invitation.acceptedAt = now(); invitation.userId = result.userId!; notify(state, 'info', 'Application invitation accepted', `${state.apps[item.appId]?.name}: ${invitation.email} joined with the reviewed app roles.`); }
      else if (invitation && item.status === 'failed') invitation.status = 'needs_attention';
    } else if (item.status === 'succeeded') notify(state, 'info', 'Application access policy applied', `${state.apps[item.appId]?.name}: approved role policy ${result.policyHash} was confirmed independently of code releases.`);
  });
}
export async function reconcileAccessOperations(store: Store, dependencies: AccessDependencies, appId?: string): Promise<void> {
  if (!dependencies.accessOperation) return;
  const operations = await store.read(state => Object.values(state.accessOperations).filter(item => item.status === 'running' && (!appId || item.appId === appId)));
  for (const operation of operations) {
    try { const result = validateResult(await dependencies.accessOperation({ operationId: operation.id, appId: operation.appId }), operation); await finishOperation(store, operation, result); } catch { /* Ambiguous outcomes stay pending; passwords and remote writes are never replayed. */ }
  }
}

export async function installAccessRoutes(server: FastifyInstance, store: Store, config: Config, dependencies: AccessDependencies): Promise<void> {
  await installDirectoryRoutes(server, store, config, dependencies);
  await installAppAccountRoutes(server, store, config, dependencies);
  async function snapshot(appId: string): Promise<AppAccessSnapshot> {
    if (!dependencies.accessSnapshot) throw httpError(503, 'The protected application identity service is unavailable. No access change was attempted.');
    await store.read(state => currentApp(state, appId));
    const remote = await dependencies.accessSnapshot({ appId }); const result = await store.read(state => validateAccessSnapshot(remote, state, appId));
    await store.transaction(state => { validateAccessSnapshot(result, state, appId); state.accessSnapshots[appId] = result; }); return result;
  }
  server.get<{ Params: { id: string } }>('/api/v1/apps/:id/access', async request => {
    await reconcileAccessOperations(store, dependencies, request.params.id); const evidence = await snapshot(request.params.id);
    return store.read(state => ({ snapshot: evidence, invitations: Object.values(state.invitations).filter(item => item.appId === request.params.id).map(publicInvitation), approvals: Object.values(state.accessApprovals).filter(item => item.appId === request.params.id), operations: Object.values(state.accessOperations).filter(item => item.appId === request.params.id).map(({ request: _request, ...item }) => item) }));
  });
  server.post<{ Params: { id: string } }>('/api/v1/apps/:id/access/policy-approval', async request => {
    const body = z.object({ basePolicyHash: hex, invitationsEnabled: z.boolean(), roles: z.array(roleSchema).max(50), groupMappings: z.array(mappingSchema).max(50).default([]) }).strict().parse(request.body);
    const evidence = await snapshot(request.params.id); if (evidence.policyHash !== body.basePolicyHash) throw httpError(409, 'The app access policy changed. Refresh it and request a new review.');
    const policy: AppAccessPolicy = { schemaVersion: 1, appId: evidence.appId, invitationsEnabled: body.invitationsEnabled, requireTotp: true, roles: body.roles, groupMappings: body.groupMappings }; validatePolicy(policy, evidence);
    const approval = await store.transaction(state => {
      const app = currentApp(state, evidence.appId); validateAccessSnapshot(evidence, state, app.id);
      for (const mapping of policy.groupMappings) { const connection = state.connections[mapping.connectionId]; if (!connection || connection.type !== mapping.provider || !connection.appIds.includes(app.id)) throw httpError(400, 'Each group draft must reference an app-authorized provider directory connection.'); }
      const id = randomUUID(), change: AccessChange = { approvalId: id, policy };
      const impact = [`Change access roles for ${app.name}, independently of application code and rollback.`, `New local invitations: ${policy.invitationsEnabled ? 'allowed' : 'blocked'}. Existing accounts are preserved. Invited accounts must enroll authenticator MFA.`, ...policy.roles.map(role => `${role.name} (${role.id}) grants: ${role.permissions.join(', ')}.`), ...evidence.policy.roles.filter(role => !policy.roles.some(next => next.id === role.id)).map(role => `Remove role ${role.name}; existing app users lose this role's permissions.`), 'Invitations tied to a different policy hash become invalid when this policy changes.', ...(policy.groupMappings.length ? ['SSO group mappings are saved as inactive drafts using immutable provider IDs. They grant no access until a separately verified directory resolver is configured.'] : [])];
      const approval: AccessApproval = { id, appId: app.id, action: 'access_policy', artifactHash: accessActionHash(change, evidence.policyHash), basePolicyHash: evidence.policyHash, impact, expiresAt: new Date(Date.now() + 1800000).toISOString(), approvedBy: null, approvedAt: null, consumedAt: null }; state.accessApprovals[id] = approval; state.accessChanges[id] = change; return approval;
    }); return { approval, policy };
  });
  server.post<{ Params: { id: string } }>('/api/v1/apps/:id/access/invitation-approval', async request => {
    const body = z.object({ email: z.string().trim().toLowerCase().email().max(254), roleIds: z.array(uuid).min(1).max(50) }).strict().parse(request.body);
    const evidence = await snapshot(request.params.id);
    if (!evidence.policy.invitationsEnabled || new Set(body.roleIds).size !== body.roleIds.length || body.roleIds.some(id => !evidence.policy.roles.some(role => role.id === id))) throw httpError(409, 'New invitations require an enabled policy and exact approved app roles.');
    const result = await store.transaction(state => {
      const app = currentApp(state, evidence.appId); validateAccessSnapshot(evidence, state, app.id); const id = randomUUID();
      const invitation: AppInvitation = { id: randomUUID(), appId: app.id, email: body.email, roleIds: body.roleIds, policyHash: evidence.policyHash, expiresAt: new Date(Date.now() + 48 * 3600000).toISOString(), createdBy: request.principal!.id, createdAt: now(), approvalId: id }; const change: AccessChange = { approvalId: id, invitation };
      const approval: AccessApproval = { id, appId: app.id, action: 'invitation', artifactHash: accessActionHash(change, evidence.policyHash), basePolicyHash: evidence.policyHash, impact: [`Invite ${body.email} to ${app.name} with roles: ${body.roleIds.map(id => evidence.policy.roles.find(role => role.id === id)!.name).join(', ')}.`, `One-use invitation expires ${invitation.expiresAt}. Anyone possessing its link may set up this app account; deliver it privately to the intended person.`, 'The link is shown once; no email is automatically sent. Possession does not verify the email address. Authenticator MFA enrollment is required.'], expiresAt: new Date(Date.now() + 1800000).toISOString(), approvedBy: null, approvedAt: null, consumedAt: null }; state.accessChanges[id] = change; state.accessApprovals[id] = approval; return { approval, invitation };
    }); return result;
  });
  server.post<{ Params: { id: string } }>('/api/v1/access/approvals/:id/approve', async request => {
    const body = z.object({ artifactHash: hex }).strict().parse(request.body), approval = await store.read(state => state.accessApprovals[request.params.id]);
    if (!approval) throw httpError(404, 'App access approval not found.'); const evidence = await snapshot(approval.appId);
    return { approval: await store.transaction(state => {
      const item = state.accessApprovals[approval.id], change = state.accessChanges[approval.id];
      if (!item || !change || item.approvedAt || item.consumedAt || Date.parse(item.expiresAt) <= Date.now() || item.basePolicyHash !== evidence.policyHash || body.artifactHash !== item.artifactHash || accessActionHash(change, item.basePolicyHash) !== body.artifactHash) throw httpError(409, 'The exact app access review expired, changed or has already been used.');
      validateAccessSnapshot(evidence, state, item.appId); if (change.policy) validatePolicy(change.policy, evidence); item.approvedBy = request.principal!.id; item.approvedAt = now(); state.accessActors[item.id] = { id: request.principal!.id, mfa: true }; return item;
    }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/apps/:id/access/apply', async request => {
    if (!dependencies.applyAccessPolicy) throw httpError(503, 'Identity policy application is unavailable. No change was attempted.');
    const body = z.object({ approvalId: uuid }).strict().parse(request.body), evidence = await snapshot(request.params.id);
    const operation = await store.transaction(state => {
      const { approval, change } = approvedChange(state, body.approvalId, request.params.id, 'access_policy');
      if (approval.basePolicyHash !== evidence.policyHash || !change.policy) throw httpError(409, 'The approved policy baseline changed. Refresh and review again.'); validateAccessSnapshot(evidence, state, request.params.id);
      if (Object.values(state.accessOperations).some(item => item.appId === request.params.id && item.status === 'running')) throw httpError(409, 'An app identity operation is awaiting confirmation.');
      const id = randomUUID(), actor = state.accessActors[approval.id]; if (!actor?.mfa || actor.id !== approval.approvedBy) throw httpError(409, 'The exact MFA approval identity is unavailable.'); approval.consumedAt = now();
      const operation: AccessOperation = { id, appId: request.params.id, action: 'access_policy', approvalId: approval.id, artifactHash: approval.artifactHash, status: 'running', createdAt: now(), completedAt: null, request: { operationId: id, appId: request.params.id, basePolicyHash: approval.basePolicyHash, policy: change.policy, approval: { ...approval }, principal: actor } }; state.accessOperations[id] = operation; return operation;
    });
    try { const result = validateResult(await dependencies.applyAccessPolicy(operation.request as AccessPolicyRequest), operation); await finishOperation(store, operation, result); }
    catch (fault) { if ((fault as { confirmedRejected?: boolean }).confirmedRejected) await finishOperation(store, operation, { operationId: operation.id, appId: operation.appId, action: operation.action, artifactHash: operation.artifactHash, status: 'failed', detail: 'Rejected before identity changes. Request a new review after resolving the issue.' }); }
    return { operation: await store.read(state => { const { request: _request, ...item } = state.accessOperations[operation.id]!; return item; }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/apps/:id/access/invitations', async request => {
    if (!config.appsOrigin || new URL(config.appsOrigin).protocol !== 'https:') throw httpError(503, 'The protected HTTPS invitation portal is unavailable.');
    const body = z.object({ approvalId: uuid }).strict().parse(request.body), evidence = await snapshot(request.params.id), token = randomBytes(32).toString('base64url');
    const invitation = await store.transaction(state => {
      const { approval, change } = approvedChange(state, body.approvalId, request.params.id, 'invitation');
      if (!change.invitation || approval.basePolicyHash !== evidence.policyHash || !evidence.policy.invitationsEnabled || change.invitation.roleIds.some(id => !evidence.policy.roles.some(role => role.id === id)) || Date.parse(change.invitation.expiresAt) <= Date.now()) throw httpError(409, 'The invitation no longer matches the current approved app policy.'); validateAccessSnapshot(evidence, state, request.params.id);
      approval.consumedAt = now(); const record: InvitationRecord = { ...change.invitation, tokenHash: tokenHash(token), status: 'pending', acceptedAt: null, userId: null }; state.invitations[record.id] = record; return publicInvitation(record);
    }); return { invitation, link: `${new URL(config.appsOrigin).origin}/invite#${token}` };
  });
  server.post<{ Params: { id: string; invitationId: string } }>('/api/v1/apps/:id/access/invitations/:invitationId/revoke', async request => {
    z.object({}).strict().parse(request.body ?? {}); await store.transaction(state => { currentApp(state, request.params.id); const invitation = state.invitations[request.params.invitationId]; if (!invitation || invitation.appId !== request.params.id) throw httpError(404, 'Invitation not found.'); if (invitation.status !== 'pending') throw httpError(409, 'Only an unused invitation can be revoked. Accepted accounts require a separately reviewed access policy change.'); invitation.status = 'revoked'; }); return { revoked: true };
  });
  async function inspectToken(token: string) {
    const invitation = await store.read(state => Object.values(state.invitations).find(item => item.tokenHash === tokenHash(token)));
    if (!invitation || !['pending', 'accepting', 'accepted'].includes(invitation.status) || Date.parse(invitation.expiresAt) <= Date.now()) throw httpError(410, 'This invitation is unavailable, used, revoked or expired.');
    if (invitation.operationId) await reconcileAccessOperations(store, dependencies, invitation.appId);
    const evidence = await snapshot(invitation.appId);
    if (evidence.policyHash !== invitation.policyHash || !evidence.policy.invitationsEnabled || invitation.roleIds.some(id => !evidence.policy.roles.some(role => role.id === id))) throw httpError(410, 'This invitation no longer matches the current app access policy. Ask the app administrator for a new invitation.');
    return { invitation: await store.read(state => state.invitations[invitation.id]!), evidence };
  }
  const publicConfig = { rateLimit: { max: 15, timeWindow: '1 minute' } };
  server.post('/api/public/v1/invitations/inspect', { config: publicConfig }, async (request, reply) => {
    const { token } = z.object({ token: z.string().regex(/^[a-zA-Z0-9_-]{43}$/) }).strict().parse(request.body); const { invitation, evidence } = await inspectToken(token);
    if (invitation.status === 'accepted') throw httpError(410, 'This invitation has already been accepted. Sign in on the application page.');
    const app = await store.read(state => currentApp(state, invitation.appId)); reply.header('Referrer-Policy', 'no-referrer');
    return { app: { name: app.name, url: `https://${app.slug}.${new URL(config.appsOrigin!).host}/` }, email: invitation.email, roles: evidence.policy.roles.filter(role => invitation.roleIds.includes(role.id)).map(role => ({ name: role.name, permissions: role.permissions })), expiresAt: invitation.expiresAt, status: invitation.status, requireTotp: true, emailVerified: false };
  });
  server.post('/api/public/v1/invitations/accept', { config: publicConfig }, async (request, reply) => {
    if (!dependencies.acceptAppInvitation) throw httpError(503, 'The protected app identity service is unavailable. Account setup was not attempted.');
    const body = z.object({ token: z.string().regex(/^[a-zA-Z0-9_-]{43}$/), password: z.string().min(12).max(128).regex(/^[^\x00-\x1f\x7f]+$/) }).strict().parse(request.body); const { invitation, evidence } = await inspectToken(body.token);
    if (invitation.status === 'accepted') throw httpError(410, 'This invitation has already been accepted.');
    if (invitation.operationId) return reply.code(202).send({ status: 'pending', message: 'The original account setup is awaiting identity-service confirmation. No password reset or duplicate account was attempted.' });
    const operation = await store.transaction(state => {
      const record = state.invitations[invitation.id]; if (!record || record.status !== 'pending' || record.operationId || record.policyHash !== evidence.policyHash || Date.parse(record.expiresAt) <= Date.now()) throw httpError(409, 'Invitation setup already started or is no longer available.'); validateAccessSnapshot(evidence, state, record.appId);
      const approval = state.accessApprovals[record.approvalId], actor = state.accessActors[record.approvalId]; if (!approval?.approvedBy || !approval.consumedAt || !actor?.mfa || actor.id !== approval.approvedBy) throw httpError(409, 'The invitation approval identity is unavailable.');
      const { tokenHash: _hash, status: _status, acceptedAt: _accepted, userId: _user, operationId: _operation, ...binding } = record;
      if (accessActionHash({ approvalId: approval.id, invitation: binding }, approval.basePolicyHash) !== approval.artifactHash) throw httpError(409, 'The reviewed invitation was changed.');
      const id = randomUUID(); const operation: AccessOperation = { id, appId: record.appId, action: 'invitation', approvalId: approval.id, artifactHash: approval.artifactHash, status: 'running', createdAt: now(), completedAt: null, request: { operationId: id, invitation: binding, approval: { ...approval }, principal: actor } }; state.accessOperations[id] = operation; record.status = 'accepting'; record.operationId = id; return operation;
    });
    try { const result = validateResult(await dependencies.acceptAppInvitation({ ...(operation.request as Omit<AcceptInvitationRequest, 'password'>), password: body.password }), operation); await finishOperation(store, operation, result); }
    catch (fault) { if ((fault as { confirmedRejected?: boolean }).confirmedRejected) await finishOperation(store, operation, { operationId: operation.id, appId: operation.appId, action: operation.action, artifactHash: operation.artifactHash, status: 'failed', detail: 'Rejected before account creation; ask the administrator to inspect and issue a new invitation.' }); }
    const completed = await store.read(state => state.invitations[invitation.id]!);
    if (completed.status !== 'accepted') return reply.code(202).send({ status: completed.status === 'needs_attention' ? 'needs_attention' : 'pending', message: 'Account setup is not confirmed. Contact the app administrator; the original operation is retained and will not be blindly retried.' });
    const app = await store.read(state => currentApp(state, invitation.appId)); return { status: 'accepted', url: `https://${app.slug}.${new URL(config.appsOrigin!).host}/`, requireTotp: true, emailVerified: false };
  });
}
