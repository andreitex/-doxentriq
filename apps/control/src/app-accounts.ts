import { createHash, randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { appAccountArtifactHash, appAccountSnapshotSchema, appAccountStatusSchema, type AppAccountApproval, type AppAccountDependencies, type AppAccountOperationIdentity, type AppAccountSnapshot, type AppAccountStatus, type AppAccountTarget, type DisableAppAccountRequest } from '../../../packages/core/src/app-accounts.ts';
import { requireOwner } from './auth.ts';
import type { Config } from './config.ts';
import { notify, type State, type Store } from './store.ts';

export type AppAccountOperation = AppAccountOperationIdentity & { status: 'pending' | 'disabled' | 'failed'; createdAt: string; checkedAt: string | null; detail: string; request: DisableAppAccountRequest };
const uuid = z.string().uuid(), hex = z.string().regex(/^[a-f0-9]{64}$/), iso = () => new Date().toISOString();
const fault = (statusCode: number, message: string) => Object.assign(new Error(message), { statusCode });
function currentReview(item: AppAccountApproval): boolean { const created = Date.parse(item.createdAt), expires = Date.parse(item.expiresAt); return uuid.safeParse(item.id).success && item.action === 'disable_app_account' && item.appId === item.snapshot.appId && appAccountSnapshotSchema.safeParse(item.snapshot).success && item.snapshot.enabled && item.artifactHash === appAccountArtifactHash(item.snapshot) && Number.isFinite(created) && Number.isFinite(expires) && created <= Date.now() + 10000 && expires > Date.now() && expires > created && expires - created <= 300000; }
function owner(request: FastifyRequest, state: State, config: Config) {
  requireOwner(request); const session = request.session && state.sessions[request.session.id];
  if (!session || session.principal.id !== request.principal!.id || !session.principal.localOwner || !session.principal.mfa || config.ownerSubject && session.principal.id !== config.ownerSubject || Date.parse(session.expiresAt) <= Date.now() || !Number.isFinite(Date.parse(session.expiresAt)) || config.authMode !== 'development' && (!session.accessExpiresAt || !Number.isFinite(Date.parse(session.accessExpiresAt)) || Date.parse(session.accessExpiresAt) <= Date.now())) throw fault(403, 'A current permanent owner session with MFA is required.');
  return { id: session.principal.id, localOwner: true, mfa: true };
}
function target(state: State, appId: string, invitationId: string): AppAccountTarget {
  const app = state.apps[appId], invitation = state.invitations[invitationId];
  if (!app || app.status === 'archived' || !app.activeReleaseId || !invitation || invitation.appId !== appId || invitation.status !== 'accepted' || !uuid.safeParse(invitation.userId).success || !uuid.safeParse(invitation.operationId).success) throw fault(409, 'An exact accepted local invitation in this published application is required.');
  const operation = state.accessOperations[invitation.operationId!];
  if (!operation || operation.appId !== appId || operation.action !== 'invitation' || operation.status !== 'succeeded' || operation.approvalId !== invitation.approvalId || !('invitation' in operation.request) || operation.request.invitation.id !== invitation.id) throw fault(409, 'The original confirmed account creation is unavailable.');
  return { appId, invitationId, userId: invitation.userId!, creationOperationId: invitation.operationId! };
}
function validateSnapshot(value: unknown, state: State, expected: AppAccountTarget): AppAccountSnapshot {
  const parsed = appAccountSnapshotSchema.safeParse(value); if (!parsed.success) throw fault(503, 'Protected account or token-lifetime evidence is unavailable.'); const snapshot = parsed.data;
  const current = target(state, expected.appId, expected.invitationId), app = state.apps[expected.appId]!, invitation = state.invitations[expected.invitationId]!;
  if ((['appId', 'invitationId', 'userId', 'creationOperationId'] as const).some(key => snapshot[key] !== expected[key] || current[key] !== expected[key]) || snapshot.releaseId !== app.activeReleaseId || snapshot.realm !== `app-${createHash('sha256').update(snapshot.appId).digest('hex').slice(0, 24)}` || snapshot.username !== invitation.email || snapshot.email !== invitation.email || Date.parse(snapshot.checkedAt) > Date.now() + 10000 || Date.now() - Date.parse(snapshot.checkedAt) > 60000) throw fault(503, 'The account evidence is stale, changed or belongs to another application.');
  return snapshot;
}
function identity(operation: AppAccountOperation): AppAccountOperationIdentity { const { operationId, approvalId, appId, invitationId, userId, artifactHash } = operation; return { operationId, approvalId, appId, invitationId, userId, artifactHash }; }
function validateStatus(value: unknown, operation: AppAccountOperation): AppAccountStatus {
  const parsed = appAccountStatusSchema.safeParse(value); if (!parsed.success || Object.entries(identity(operation)).some(([key, value]) => parsed.data[key as keyof AppAccountOperationIdentity] !== value) || Date.parse(parsed.data.checkedAt) > Date.now() + 10000 || Date.now() - Date.parse(parsed.data.checkedAt) > 60000) throw fault(503, 'The exact account operation has not been independently confirmed.'); return parsed.data;
}
async function confirmed(store: Store, operation: AppAccountOperation, result: AppAccountStatus) {
  await store.transaction(state => { const item = state.appAccountOperations[operation.operationId]; if (!item || item.artifactHash !== operation.artifactHash) throw fault(409, 'Account operation identity changed.'); item.checkedAt = result.checkedAt;
    if (result.status === 'disabled') { const newlyConfirmed = item.status !== 'disabled'; item.status = 'disabled'; item.detail = 'The exact local account is disabled and its online sessions are absent. Existing signed tokens retain their own expiry.'; if (newlyConfirmed) notify(state, 'info', 'Application account disabled', `${state.apps[item.appId]?.name}: the reviewed local account was disabled. Records and business data remain.`); }
    else { item.status = 'pending'; item.detail = 'Account disablement is awaiting exact identity-service readback. No mutation was retried.'; }
  });
}
function pending(state: State, appId: string, userId: string, except?: string) {
  return Object.values(state.appAccountOperations).some(item => item.appId === appId && item.userId === userId && item.status === 'pending') || Object.values(state.appAccountApprovals).some(item => item.id !== except && item.appId === appId && item.snapshot.userId === userId && item.approvedAt && !item.consumedAt && Date.parse(item.expiresAt) > Date.now());
}
export async function installAppAccountRoutes(server: FastifyInstance, store: Store, config: Config, dependencies: AppAccountDependencies) {
  async function snapshot(request: FastifyRequest, appId: string, invitationId: string) { const input = await store.read(state => { owner(request, state, config); return target(state, appId, invitationId); }); if (!dependencies.appAccountSnapshot) throw fault(503, 'The protected account service is unavailable.'); const remote = await dependencies.appAccountSnapshot(input); return store.read(state => { owner(request, state, config); return validateSnapshot(remote, state, input); }); }
  server.get<{ Params: { id: string } }>('/api/v1/apps/:id/accounts', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const operations = await store.read(state => { owner(request, state, config); return Object.values(state.appAccountOperations).filter(item => item.appId === request.params.id); });
    for (const operation of operations.filter(item => item.status !== 'failed')) { try { if (dependencies.appAccountOperation) await confirmed(store, operation, validateStatus(await dependencies.appAccountOperation(identity(operation)), operation)); else throw new Error(); } catch { await store.transaction(state => { const item = state.appAccountOperations[operation.operationId]; if (item) { item.status = 'pending'; item.checkedAt = null; item.detail = 'Current account confirmation is unavailable. Inspect this original operation; no mutation was retried.'; } }); } }
    return store.read(state => { owner(request, state, config); if (!state.apps[request.params.id]) throw fault(404, 'Application not found.'); return { approvals: Object.values(state.appAccountApprovals).filter(item => item.appId === request.params.id), operations: Object.values(state.appAccountOperations).filter(item => item.appId === request.params.id).map(({ request: _request, ...item }) => item) }; });
  });
  server.post<{ Params: { id: string; invitationId: string } }>('/api/v1/apps/:id/accounts/:invitationId/disable-review', async request => {
    z.object({}).strict().parse(request.body ?? {}); const evidence = await snapshot(request, request.params.id, request.params.invitationId);
    return store.transaction(state => { owner(request, state, config); validateSnapshot(evidence, state, evidence); if (!evidence.enabled || pending(state, evidence.appId, evidence.userId)) throw fault(409, 'This account is disabled or another reviewed operation needs inspection.'); const createdAt = iso(), id = randomUUID();
      const approval: AppAccountApproval = { id, appId: evidence.appId, action: 'disable_app_account', artifactHash: appAccountArtifactHash(evidence), snapshot: evidence, createdAt, expiresAt: new Date(Date.parse(createdAt) + 300000).toISOString(), approvedBy: null, approvedAt: null, consumedAt: null, impact: [`Disable ${evidence.email} only in ${state.apps[evidence.appId]!.name}. Exact local user: ${evidence.userId}; invitation: ${evidence.invitationId}.`, 'Block new sign-in and session refresh, and log out this account’s online sessions. User records, role definitions, other accounts and business data are preserved.', `Current verified realm/client access-token lifetime limit: ${evidence.accessTokenLifespanSeconds} seconds. Already issued signed tokens remain valid until their own expiry; older configuration may have issued longer tokens.`, 'Federated accounts and accounts with offline sessions are unsupported by this action. Uncertain results remain pending for read-only inspection; no automatic retry or re-enablement occurs.'] }; state.appAccountApprovals[id] = approval; return { approval }; });
  });
  server.post<{ Params: { approvalId: string } }>('/api/v1/account-approvals/:approvalId/approve', async request => {
    const body = z.object({ artifactHash: hex }).strict().parse(request.body); const review = await store.read(state => { owner(request, state, config); const value = state.appAccountApprovals[request.params.approvalId]; if (!value) throw fault(404, 'Account review not found.'); return value; });
    const evidence = await snapshot(request, review.appId, review.snapshot.invitationId);
    return store.transaction(state => { const actor = owner(request, state, config), item = state.appAccountApprovals[review.id]; if (!item || !currentReview(item) || item.artifactHash !== body.artifactHash || item.artifactHash !== appAccountArtifactHash(evidence) || item.approvedAt || item.approvedBy || item.consumedAt || pending(state, item.appId, item.snapshot.userId, item.id)) throw fault(409, 'The exact current account review changed or was already approved.'); item.approvedBy = actor.id; item.approvedAt = iso(); return { approval: item }; });
  });
  server.post<{ Params: { id: string } }>('/api/v1/apps/:id/accounts/disable', async (request, reply) => {
    const body = z.object({ approvalId: uuid }).strict().parse(request.body); const review = await store.read(state => { owner(request, state, config); const item = state.appAccountApprovals[body.approvalId]; if (!item || item.appId !== request.params.id) throw fault(409, 'The exact app account approval is required.'); return item; });
    const evidence = await snapshot(request, review.appId, review.snapshot.invitationId); if (!dependencies.disableAppAccount) throw fault(503, 'The protected account service is unavailable. No disable operation was dispatched.');
    const operation = await store.transaction(state => { const actor = owner(request, state, config), item = state.appAccountApprovals[review.id]; validateSnapshot(evidence, state, evidence);
      if (!item || !currentReview(item) || item.appId !== request.params.id || !item.approvedAt || !Number.isFinite(Date.parse(item.approvedAt)) || Date.parse(item.approvedAt) < Date.parse(item.createdAt) || Date.parse(item.approvedAt) > Date.now() || item.approvedBy !== actor.id || item.consumedAt || item.artifactHash !== appAccountArtifactHash(evidence) || pending(state, item.appId, item.snapshot.userId, item.id)) throw fault(409, 'A current unused owner approval for this exact account is required.');
      item.consumedAt = iso(); const operationId = randomUUID(), value: AppAccountOperation = { operationId, approvalId: item.id, appId: item.appId, invitationId: item.snapshot.invitationId, userId: item.snapshot.userId, artifactHash: item.artifactHash, status: 'pending', createdAt: iso(), checkedAt: null, detail: 'Exact account disablement was dispatched; confirmation is pending.', request: { operationId, approval: structuredClone(item), principal: actor } }; state.appAccountOperations[operationId] = value; return value;
    });
    try { await confirmed(store, operation, validateStatus(await dependencies.disableAppAccount(operation.request), operation)); } catch (error) { if ((error as { confirmedRejected?: boolean }).confirmedRejected) await store.transaction(state => { const item = state.appAccountOperations[operation.operationId]; if (item) { item.status = 'failed'; item.detail = 'Rejected before account mutation. Refresh current evidence before a new review.'; } }); }
    const { request: _request, ...result } = await store.read(state => state.appAccountOperations[operation.operationId]!); return reply.code(result.status === 'disabled' ? 200 : result.status === 'failed' ? 409 : 202).send({ operation: result });
  });
}
