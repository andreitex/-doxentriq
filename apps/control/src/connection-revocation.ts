import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { withdrawalArtifactHash, withdrawalSnapshotHash, withdrawalSnapshotSchema, withdrawalStatusSchema, type WithdrawalChange, type WithdrawalIdentity, type WithdrawalRequest, type WithdrawalSnapshot, type WithdrawalStatus } from '../../../packages/core/src/connection-revocation.ts';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import { filesystemArtifactHash } from '../../../packages/core/src/connector-adapters.ts';
import { requireOwner } from './auth.ts';
import type { Config } from './config.ts';
import { notify, type Store, type State } from './store.ts';

export type WithdrawalApproval = { id: string; appId: string; connectionId: string; action: 'revoke_readonly_filesystem'; artifactHash: string; change: WithdrawalChange; impact: string[]; createdAt: string; expiresAt: string; approvedAt: string | null; approvedBy: string | null; consumedAt: string | null };
export type WithdrawalOperation = WithdrawalIdentity & { type: 'filesystem'; status: 'pending' | 'revoked' | 'failed'; snapshotHash: string; stoppedContainerIds: string[]; tombstone: boolean; createdAt: string; checkedAt: string | null; detail: string };
export type RevocationDependencies = { connectionRevocationSnapshot?: (input: { appId: string; connectionId: string }) => Promise<WithdrawalSnapshot>; revokeConnection?: (input: WithdrawalRequest) => Promise<WithdrawalStatus>; connectionRevocationStatus?: (input: WithdrawalIdentity) => Promise<WithdrawalStatus> };
const fault = (statusCode: number, message: string) => Object.assign(new Error(message), { statusCode }), now = () => new Date().toISOString(), uuid = z.string().uuid();
export function connectionWithdrawn(state: State, appId: string, connectionId: string): boolean { return Object.values(state.revocationOperations).some(operation => operation.appId === appId && operation.connectionId === connectionId && operation.status !== 'failed'); }
function approvedReviewPending(state: State, appId: string, connectionId: string, except?: string): boolean { return Object.values(state.revocationApprovals).some(review => review.id !== except && review.appId === appId && review.connectionId === connectionId && review.approvedAt && !review.consumedAt && Date.parse(review.expiresAt) > Date.now()); }

// Stop authority uses historical exact grant provenance. Expired/disabled roots
// and archived apps can be withdrawn; those records never grant new access.
function originalGrant(state: State, appId: string, connectionId: string, ownerSubject: string) {
  const item = state.connections[connectionId];
  if (!item || item.type !== 'filesystem' || !state.apps[appId]) throw fault(404, 'Retained filesystem application/connection not found. Samba withdrawal is unavailable for historical receipts without immutable IDs.');
  const operations = Object.values(state.adapterOperations).filter(operation => operation.appId === appId && operation.connectionId === connectionId && operation.status === 'configured');
  if (operations.length !== 1) throw fault(409, 'One exact configured original filesystem grant is required; inspect any uncertain provisioning first.');
  const operation = operations[0]!, approval = state.adapterApprovals[operation.approvalId], scope = state.adapterChanges[operation.approvalId];
  if (!scope || !approval || scope.appId !== appId || scope.connectionId !== connectionId || approval.appId !== appId || approval.connectionId !== connectionId || approval.action !== 'approve_readonly_filesystem' || approval.approvedBy !== ownerSubject || !approval.approvedAt || !approval.consumedAt || approval.artifactHash !== filesystemArtifactHash(scope) || approval.artifactHash !== operation.artifactHash || operation.scopeHash !== operation.artifactHash) throw fault(409, 'Original filesystem approval provenance is unavailable. No withdrawal was dispatched.');
  return { item, operation };
}
function exactSnapshot(value: unknown, appId: string, connectionId: string): WithdrawalSnapshot {
  const snapshot = withdrawalSnapshotSchema.parse(value), { observedAt, snapshotHash, ...contents } = snapshot;
  if (snapshot.appId !== appId || snapshot.connectionId !== connectionId || snapshotHash !== withdrawalSnapshotHash(contents) || Date.parse(observedAt) > Date.now() || Date.now() - Date.parse(observedAt) >= 300000) throw fault(503, 'Exact complete runtime withdrawal inventory is unavailable, malformed or stale.'); return snapshot;
}
function review(state: State, id: string, ownerSubject: string, approved: boolean): WithdrawalApproval {
  const approval = state.revocationApprovals[id];
  if (!approval || approval.id !== id || approval.action !== 'revoke_readonly_filesystem' || approval.change.impactHash !== hashArtifact(approval.impact) || approval.artifactHash !== withdrawalArtifactHash(approval.change) || approval.change.snapshot.appId !== approval.appId || approval.change.snapshot.connectionId !== approval.connectionId || Date.parse(approval.expiresAt) <= Date.now() || !Number.isFinite(Date.parse(approval.expiresAt)) || approval.consumedAt || approved && (!approval.approvedAt || approval.approvedBy !== ownerSubject)) throw fault(409, 'A current unused five-minute exact owner withdrawal review is required.');
  exactSnapshot(approval.change.snapshot, approval.appId, approval.connectionId);
  const original = originalGrant(state, approval.appId, approval.connectionId, ownerSubject);
  if (hashArtifact(original.item) !== approval.change.registryHash || original.operation.scopeHash !== approval.change.snapshot.scopeHash || original.operation.approvalId !== approval.change.snapshot.grantApprovalId || connectionWithdrawn(state, approval.appId, approval.connectionId)) throw fault(409, 'Registry, original grant or withdrawal state changed. Inspect its retained operation.'); return approval;
}
function exactStatus(value: unknown, operation: WithdrawalOperation, approval: WithdrawalApproval): WithdrawalStatus {
  const status = withdrawalStatusSchema.parse(value);
  for (const key of ['operationId','approvalId','appId','connectionId','artifactHash'] as const) if (status[key] !== operation[key]) throw fault(503, 'Withdrawal result belongs to another retained exact operation.');
  const ids = new Set(approval.change.snapshot.targets.map(target => target.containerId));
  if (status.status !== 'unknown' && status.snapshotHash !== operation.snapshotHash || status.stoppedContainerIds.some(id => !ids.has(id)) || status.status === 'revoked' && status.stoppedContainerIds.length !== ids.size || Date.parse(status.checkedAt) > Date.now() + 1000 || Date.now() - Date.parse(status.checkedAt) >= 300000) throw fault(503, 'Withdrawal stop evidence does not match the complete reviewed inventory or current readback freshness.'); return status;
}
async function recordStatus(store: Store, operation: WithdrawalOperation, status: WithdrawalStatus): Promise<void> {
  if (status.status === 'unknown') return;
  await store.transaction(state => { const retained = state.revocationOperations[operation.operationId]; if (!retained || retained.artifactHash !== operation.artifactHash || retained.status === 'failed') return; const wasRevoked = retained.status === 'revoked'; retained.status = status.status === 'revoked' ? 'revoked' : 'pending'; retained.tombstone = true; retained.stoppedContainerIds = status.stoppedContainerIds; retained.checkedAt = status.checkedAt; retained.detail = status.status === 'revoked' ? 'Permanent runtime withdrawal retained; every reviewed original filesystem connector service is independently stopped. Data and credentials are preserved. Regrant needs a new connection ID.' : 'Permanent runtime withdrawal retained; one or more original stop outcomes need reconciliation. Data and credentials are preserved; do not dispatch again.'; if (!wasRevoked && retained.status === 'revoked') notify(state, 'warning', 'Filesystem access withdrawn', `${state.connections[retained.connectionId]?.name ?? retained.connectionId} was withdrawn only for ${state.apps[retained.appId]?.name ?? retained.appId}. Regrant requires a new connection identity.`); });
}
export async function reconcileConnectionWithdrawals(store: Store, dependencies: RevocationDependencies, appId: string, connectionId: string): Promise<void> {
  const records = await store.read(state => Object.values(state.revocationOperations).filter(operation => operation.appId === appId && operation.connectionId === connectionId && operation.status !== 'failed').slice(0, 32).map(operation => ({ operation, approval: state.revocationApprovals[operation.approvalId] })));
  for (const { operation, approval } of records) {
    try { if (!approval || !dependencies.connectionRevocationStatus) throw new Error(); const status = exactStatus(await dependencies.connectionRevocationStatus({ operationId: operation.operationId, approvalId: operation.approvalId, appId, connectionId, artifactHash: operation.artifactHash }), operation, approval); if (status.status === 'unknown') throw new Error(); await recordStatus(store, operation, status); }
    catch { await store.transaction(state => { const retained = state.revocationOperations[operation.operationId]; if (!retained || retained.status === 'failed') return; retained.status = 'pending'; retained.detail = 'Current withdrawal readback is unavailable, stale or uncertain. Any saved permanent access block and previous stop receipts remain; inspect again without repeating dispatch.'; }); }
  }
}
export async function installConnectionRevocationRoutes(server: FastifyInstance, store: Store, config: Config, dependencies: RevocationDependencies): Promise<void> {
  const owner = (request: Parameters<typeof requireOwner>[0]) => { requireOwner(request); if (request.principal!.id !== config.ownerSubject) throw fault(403, 'Only the permanent local owner with MFA may withdraw runtime connections.'); };
  server.get<{ Params: { id: string }; Querystring: { appId?: string } }>('/api/v1/connections/:id/revocation', async request => {
    owner(request); const appId = uuid.parse(request.query.appId), connectionId = uuid.parse(request.params.id);
    await store.read(state => { if (!state.connections[connectionId] || state.connections[connectionId]!.type !== 'filesystem' || !state.apps[appId]) throw fault(404, 'Filesystem app/connection not found.'); });
    await reconcileConnectionWithdrawals(store, dependencies, appId, connectionId);
    return store.read(state => ({ type: 'filesystem', approvals: Object.values(state.revocationApprovals).filter(item => item.appId === appId && item.connectionId === connectionId), operations: Object.values(state.revocationOperations).filter(item => item.appId === appId && item.connectionId === connectionId) }));
  });
  server.post<{ Params: { id: string } }>('/api/v1/connections/:id/revocation/approval', async request => {
    owner(request); const { appId } = z.object({ appId: uuid }).strict().parse(request.body), connectionId = uuid.parse(request.params.id);
    const before = await store.read(state => { if (approvedReviewPending(state, appId, connectionId)) throw fault(409, 'A prior approved review has an uncertain unused outcome. Inspect it; it must expire before another review.'); return originalGrant(state, appId, connectionId, config.ownerSubject!); });
    if (!dependencies.connectionRevocationSnapshot) throw fault(503, 'Independent filesystem withdrawal inventory is unavailable. Nothing was stopped.');
    const snapshot = exactSnapshot(await dependencies.connectionRevocationSnapshot({ appId, connectionId }), appId, connectionId);
    return { approval: await store.transaction(state => { const current = originalGrant(state, appId, connectionId, config.ownerSubject!); if (approvedReviewPending(state, appId, connectionId) || hashArtifact(before) !== hashArtifact(current) || snapshot.scopeHash !== current.operation.scopeHash || snapshot.grantApprovalId !== current.operation.approvalId || connectionWithdrawn(state, appId, connectionId)) throw fault(409, 'Original scope or withdrawal state changed while inventory was checked.'); if (Object.values(state.revocationApprovals).filter(item => item.appId === appId).length >= 256) throw fault(409, 'Withdrawal approval history reached its bounded capacity.');
      const id = randomUUID(), change = { snapshot, registryHash: hashArtifact(current.item), impactHash: "" }, createdAt = now(), approval: WithdrawalApproval = { id, appId, connectionId, action: 'revoke_readonly_filesystem', artifactHash: withdrawalArtifactHash(change), change, impact: [`Withdraw list/read access for ${state.apps[appId]!.name} (${appId}) using ${current.item.name} (${connectionId}). Other applications retain their own scopes.`, `Stop ${snapshot.targets.length} independently proven original filesystem connector service(s), including retained previews and releases. The application may report unavailable document imports.`, 'Permanently block this app’s connection before stopping its filesystem connector services. App code rollback cannot restore this grant; regrant requires a new connection ID.', 'No documents, application/database records, credentials, containers or volumes are deleted. Registry metadata edits alone are not runtime revocation.', 'Unknown or drifted container outcomes stay pending. The company reconciler only stops the exact original IDs; it never starts a connector.'], createdAt, expiresAt: new Date(Date.parse(snapshot.observedAt) + 300000).toISOString(), approvedAt: null, approvedBy: null, consumedAt: null }; change.impactHash = hashArtifact(approval.impact); approval.artifactHash = withdrawalArtifactHash(change); state.revocationApprovals[id] = approval; return approval;
    }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/connection-revocations/approvals/:id/approve', async request => {
    owner(request); const { artifactHash } = z.object({ artifactHash: z.string().regex(/^[a-f0-9]{64}$/) }).strict().parse(request.body);
    return { approval: await store.transaction(state => { const approval = review(state, request.params.id, config.ownerSubject!, false); if (approvedReviewPending(state, approval.appId, approval.connectionId, approval.id) || approval.artifactHash !== artifactHash || approval.approvedAt) throw fault(409, 'Exact withdrawal review changed or was already approved.'); approval.approvedAt = now(); approval.approvedBy = request.principal!.id; return approval; }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/connections/:id/revoke', async request => {
    owner(request); const { approvalId } = z.object({ approvalId: uuid }).strict().parse(request.body); if (!dependencies.revokeConnection) throw fault(503, 'Runtime withdrawal is unavailable. No withdrawal was dispatched.');
    const { operation, approval } = await store.transaction(state => { const approval = review(state, approvalId, config.ownerSubject!, true); if (approval.connectionId !== request.params.id) throw fault(409, 'Approval belongs to another connection.'); const operation: WithdrawalOperation = { operationId: randomUUID(), approvalId, appId: approval.appId, connectionId: approval.connectionId, artifactHash: approval.artifactHash, type: 'filesystem', status: 'pending', snapshotHash: approval.change.snapshot.snapshotHash, stoppedContainerIds: [], tombstone: false, createdAt: now(), checkedAt: null, detail: 'Exact withdrawal intent retained before dispatch. The saved permanent access block and stop outcome need independent confirmation.' }; approval.consumedAt = now(); state.revocationOperations[operation.operationId] = operation; return { operation, approval }; });
    try { const input: WithdrawalRequest = { schemaVersion: 1, action: 'revoke_readonly_filesystem', operationId: operation.operationId, approvalId, artifactHash: approval.artifactHash, change: approval.change, approvedAt: approval.approvedAt!, expiresAt: approval.expiresAt, principal: { id: request.principal!.id, mfa: true, localOwner: true } }; await recordStatus(store, operation, exactStatus(await dependencies.revokeConnection(input), operation, approval)); }
    catch (error) { if ((error as { confirmedRejected?: boolean }).confirmedRejected === true) await store.transaction(state => { const retained = state.revocationOperations[operation.operationId]!; if (!retained.tombstone) { retained.status = 'failed'; retained.detail = 'Runtime confirmed rejection before saving any permanent access block or stopping a connector service. Prepare a fresh exact review after correcting the reported prerequisites.'; } }); }
    return { operation: await store.read(state => state.revocationOperations[operation.operationId]) };
  });
}
