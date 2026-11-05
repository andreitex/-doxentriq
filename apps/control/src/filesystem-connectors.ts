import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { filesystemArtifactHash, filesystemScopeSchema, filesystemSourcesSchema, filesystemStatusSchema, type FilesystemScope, type FilesystemSource, type FilesystemStatus, type FilesystemProvisionRequest, type FilesystemOperationIdentity } from '../../../packages/core/src/connector-adapters.ts';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import type { ConnectionRecord } from '../../../packages/core/src/types.ts';
import { requireOwner } from './auth.ts';
import type { Config } from './config.ts';
import { notify, type State, type Store } from './store.ts';
import { connectionWithdrawn } from './connection-revocation.ts';

export type AdapterApproval = { id: string; appId: string; connectionId: string; action: 'approve_readonly_filesystem'; artifactHash: string; impact: string[]; createdAt: string; expiresAt: string; approvedAt: string | null; approvedBy: string | null; consumedAt: string | null };
export type AdapterOperation = FilesystemOperationIdentity & { status: 'pending' | 'configured' | 'failed'; type: 'filesystem'; scopeHash: string | null; liveRootVerified: false; createdAt: string; completedAt: string | null; detail: string };
export type AdapterDependencies = { filesystemSources?: (appId: string) => Promise<z.infer<typeof filesystemSourcesSchema>>; provisionFilesystem?: (input: FilesystemProvisionRequest) => Promise<FilesystemStatus>; filesystemStatus?: (input: FilesystemOperationIdentity) => Promise<FilesystemStatus> };
const uuid = z.string().uuid(), hex = z.string().regex(/^[a-f0-9]{64}$/), alias = z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,79}$/);
const fault = (statusCode: number, message: string) => Object.assign(new Error(message), { statusCode });
const timestamp = () => new Date().toISOString();
function connection(state: State, id: string): ConnectionRecord { const item = state.connections[id]; if (!item) throw fault(404, 'Connection not found.'); return item; }
export function validateFilesystemRegistry(state: State, scope: FilesystemScope, at = Date.now()): void {
  filesystemScopeSchema.parse(scope);
  if (connectionWithdrawn(state, scope.appId, scope.connectionId)) throw fault(409, 'This app/connection has a retained withdrawal intent. Inspect its runtime status; regrant requires a new connection ID.');
  const item = connection(state, scope.connectionId), app = state.apps[scope.appId];
  if (!app || app.status === 'archived' || item.type !== 'filesystem' || item.status === 'disabled' || !item.appIds.includes(scope.appId) || item.secretRef !== null) throw fault(409, 'The current application needs an authorized credential-free filesystem registry entry. Host credentials and paths are not accepted.');
  if (item.endpoints.length !== 1 || item.endpoints[0] !== `filesystem://${scope.sourceRootId}` || item.roots.length !== 1 || item.roots[0] !== scope.root || item.capabilities.length !== 2 || new Set(item.capabilities).size !== 2 || !item.capabilities.includes('files.list') || !item.capabilities.includes('files.read') || hashArtifact(item) !== scope.registryHash) throw fault(409, 'The exact company source ID, logical alias, registry version and only files.list/files.read must match the reviewed filesystem scope.');
  const expiry = Date.parse(scope.accessExpiresAt), sourceExpiry = Date.parse(scope.sourceExpiresAt), registryExpiry = item.expiresAt ? Date.parse(item.expiresAt) : NaN;
  if (![expiry, sourceExpiry, registryExpiry].every(Number.isFinite) || expiry <= at || expiry > at + 90 * 86400000 || sourceExpiry <= at || registryExpiry <= at || expiry > sourceExpiry || expiry > registryExpiry) throw fault(409, 'Filesystem access needs an explicit expiry within 90 days and both company source and registry lifetimes.');
}
function retainedApproval(state: State, id: string, connectionId: string, approved: boolean): { approval: AdapterApproval; scope: FilesystemScope } {
  const approval = state.adapterApprovals[id], scope = state.adapterChanges[id];
  if (!approval || !scope || approval.id !== id || approval.connectionId !== connectionId || scope.connectionId !== connectionId || approval.appId !== scope.appId || approval.action !== 'approve_readonly_filesystem' || approval.artifactHash !== filesystemArtifactHash(scope) || !Number.isFinite(Date.parse(approval.expiresAt)) || Date.parse(approval.expiresAt) <= Date.now() || approval.consumedAt || approved && (!approval.approvedAt || !approval.approvedBy)) throw fault(409, 'A current five-minute owner review for this exact filesystem artifact is required.');
  validateFilesystemRegistry(state, scope); return { approval, scope };
}
async function sourceEvidence(dependencies: AdapterDependencies, appId: string, sourceRootId: string): Promise<FilesystemSource> {
  if (!dependencies.filesystemSources) throw fault(503, 'Company filesystem source and adapter qualification are unavailable. No filesystem connection was provisioned.');
  const value = filesystemSourcesSchema.parse(await dependencies.filesystemSources(appId));
  if (value.appId !== appId || new Set(value.sources.map(source => source.sourceRootId)).size !== value.sources.length) throw fault(503, 'Company filesystem evidence belongs to another application or is duplicated.');
  const source = value.sources.find(source => source.sourceRootId === sourceRootId);
  if (!source || Date.parse(source.sourceExpiresAt) <= Date.now()) throw fault(409, 'This company import root is not currently qualified and authorized for the exact application.'); return source;
}
function sameSource(scope: FilesystemScope, current: FilesystemSource): boolean {
  return hashArtifact(current) === hashArtifact({ sourceRootId: scope.sourceRootId, sourceEvidenceHash: scope.sourceEvidenceHash, sourceExpiresAt: scope.sourceExpiresAt, templateSourceHash: scope.templateSourceHash, templateImage: scope.templateImage, qualificationReportHash: scope.qualificationReportHash });
}
function exactStatus(value: unknown, operation: AdapterOperation): FilesystemStatus {
  const status = filesystemStatusSchema.parse(value);
  for (const key of ['operationId', 'approvalId', 'appId', 'connectionId', 'artifactHash'] as const) if (status[key] !== operation[key]) throw fault(503, 'Filesystem runtime receipt differs from the retained exact operation.');
  if (status.status === 'configured' && status.scopeHash !== operation.artifactHash) throw fault(503, 'Filesystem runtime scope hash differs from the reviewed artifact.'); return status;
}
async function recordStatus(store: Store, operation: AdapterOperation, status: FilesystemStatus): Promise<void> {
  if (status.status !== 'configured') return;
  await store.transaction(state => { const retained = state.adapterOperations[operation.operationId]; if (!retained || retained.status !== 'pending' || retained.artifactHash !== operation.artifactHash) return; retained.status = 'configured'; retained.scopeHash = status.scopeHash!; retained.completedAt = timestamp(); retained.detail = 'Runtime retained the exact company-qualified read-only root approval. Actual root listing/openat2/mount evidence remains mandatory during application preview.'; notify(state, 'info', 'Read-only filesystem scope configured', `${state.connections[retained.connectionId]?.name} was configured for ${state.apps[retained.appId]?.name}; live read-only root verification is still required before application use.`); });
}
export async function reconcileAdapterOperations(store: Store, dependencies: AdapterDependencies, connectionId?: string): Promise<void> {
  if (!dependencies.filesystemStatus) return;
  const pending = await store.read(state => Object.values(state.adapterOperations).filter(operation => operation.status === 'pending' && (!connectionId || operation.connectionId === connectionId)).slice(0, 100));
  for (const operation of pending) { try { await recordStatus(store, operation, exactStatus(await dependencies.filesystemStatus({ operationId: operation.operationId, appId: operation.appId, connectionId: operation.connectionId, approvalId: operation.approvalId, artifactHash: operation.artifactHash }), operation)); } catch { /* Unknown dispatch cannot authorize repeating a provision request. */ } }
}
export async function installFilesystemRoutes(server: FastifyInstance, store: Store, config: Config, dependencies: AdapterDependencies): Promise<void> {
  const assertOwner = (request: Parameters<typeof requireOwner>[0]) => { requireOwner(request); if (request.principal!.id !== config.ownerSubject) throw fault(403, 'Only the permanent configured local owner may authorize filesystem roots.'); };
  server.get<{ Params: { id: string } }>('/api/v1/apps/:id/filesystem/sources', async request => {
    assertOwner(request); const appId = uuid.parse(request.params.id); await store.read(state => { if (!state.apps[appId] || state.apps[appId]!.status === 'archived') throw fault(404, 'Current application not found.'); });
    if (!dependencies.filesystemSources) throw fault(503, 'Company filesystem qualification is unavailable.'); const evidence = filesystemSourcesSchema.parse(await dependencies.filesystemSources(appId)); if (evidence.appId !== appId || new Set(evidence.sources.map(source => source.sourceRootId)).size !== evidence.sources.length) throw fault(503, 'Company source evidence belongs to another scope or is duplicated.');
    await store.read(state => { if (!state.apps[appId] || state.apps[appId]!.status === 'archived') throw fault(409, 'Application authorization changed while source evidence was being checked.'); }); return { ...evidence, sources: evidence.sources.filter(source => Date.parse(source.sourceExpiresAt) > Date.now()) };
  });
  server.get<{ Params: { id: string }; Querystring: { appId?: string } }>('/api/v1/connections/:id/filesystem/sources', async request => {
    assertOwner(request); const appId = uuid.parse(request.query.appId); const item = await store.read(state => { const item = connection(state, request.params.id); if (item.type !== 'filesystem' || item.status === 'disabled' || !item.appIds.includes(appId) || !state.apps[appId] || state.apps[appId]!.status === 'archived') throw fault(409, 'The application lacks this filesystem registry scope.'); return item; });
    if (!dependencies.filesystemSources) throw fault(503, 'Company filesystem qualification is unavailable.'); const evidence = filesystemSourcesSchema.parse(await dependencies.filesystemSources(appId)); if (evidence.appId !== appId || new Set(evidence.sources.map(source => source.sourceRootId)).size !== evidence.sources.length) throw fault(503, 'Company source evidence is for another app or is duplicated.');
    await store.read(state => { const current = connection(state, item.id); if (hashArtifact(current) !== hashArtifact(item) || !state.apps[appId] || state.apps[appId]!.status === 'archived') throw fault(409, 'The registered filesystem scope changed while source evidence was checked.'); }); return { ...evidence, sources: evidence.sources.filter(source => Date.parse(source.sourceExpiresAt) > Date.now() && item.endpoints.includes(`filesystem://${source.sourceRootId}`)) };
  });
  server.get<{ Params: { id: string } }>('/api/v1/connections/:id/filesystem/provisioning', async request => { await store.read(state => connection(state, request.params.id)); await reconcileAdapterOperations(store, dependencies, request.params.id); return store.read(state => ({ approvals: Object.values(state.adapterApprovals).filter(approval => approval.connectionId === request.params.id), operations: Object.values(state.adapterOperations).filter(operation => operation.connectionId === request.params.id).map(operation => ({ ...operation, accessExpiresAt: state.adapterChanges[operation.approvalId]?.accessExpiresAt ?? null })) })); });
  server.post<{ Params: { id: string } }>('/api/v1/connections/:id/filesystem/approval', async request => {
    assertOwner(request); const body = z.object({ appId: uuid, sourceRootId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/), root: alias, accessExpiresAt: z.string().datetime() }).strict().parse(request.body); const source = await sourceEvidence(dependencies, body.appId, body.sourceRootId);
    return { approval: await store.transaction(state => { const item = connection(state, request.params.id); const scope: FilesystemScope = { ...source, ...body, connectionId: item.id, type: 'filesystem', registryHash: hashArtifact(item) }; validateFilesystemRegistry(state, scope);
      if (Object.values(state.adapterOperations).some(operation => operation.connectionId === item.id && operation.appId === body.appId && operation.status !== 'failed')) throw fault(409, 'A retained operation already exists for this app/connection; inspect its status. Changed scopes need a new connection identity.');
      if (Object.values(state.adapterApprovals).filter(approval => approval.appId === body.appId).length >= 256) throw fault(409, 'Filesystem approval history reached its bounded capacity; company maintenance is required.');
      const id = randomUUID(), approval: AdapterApproval = { id, appId: body.appId, connectionId: item.id, action: 'approve_readonly_filesystem', artifactHash: filesystemArtifactHash(scope), impact: [`Allow ${state.apps[body.appId]!.name} (${body.appId}) to list and read only company import ${body.sourceRootId}, logical root ${body.root}.`, 'One read-only encrypted import mount; no client-selected host path, outbound network, write permission, symlink, hardlink, special file or cross-mount traversal.', `Company source evidence ${source.sourceEvidenceHash}; adapter source ${source.templateSourceHash}, image ${source.templateImage}, actual runsc qualification ${source.qualificationReportHash}.`, `Access expires ${body.accessExpiresAt}, within company source expiry ${source.sourceExpiresAt}. This exact review expires after five minutes.`, 'Runtime independently rechecks source identity, qualification and Medium+ security gates. Configuration alone is not a live root-access verification.'], createdAt: timestamp(), expiresAt: new Date(Date.now() + 300000).toISOString(), approvedAt: null, approvedBy: null, consumedAt: null }; state.adapterChanges[id] = scope; state.adapterApprovals[id] = approval; return approval;
    }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/adapters/approvals/:id/approve', async request => {
    assertOwner(request); const body = z.object({ artifactHash: hex }).strict().parse(request.body); const saved = await store.read(state => { const original = state.adapterApprovals[request.params.id]; if (!original) throw fault(404, 'Adapter approval not found.'); return retainedApproval(state, original.id, original.connectionId, false); }); const current = await sourceEvidence(dependencies, saved.scope.appId, saved.scope.sourceRootId);
    return { approval: await store.transaction(state => { const { approval, scope } = retainedApproval(state, request.params.id, saved.scope.connectionId, false); if (approval.approvedAt || approval.artifactHash !== body.artifactHash || !sameSource(scope, current)) throw fault(409, 'The exact filesystem review/source changed or was already approved.'); approval.approvedAt = timestamp(); approval.approvedBy = request.principal!.id; return approval; }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/connections/:id/filesystem/provision', async request => {
    assertOwner(request); if (!dependencies.provisionFilesystem) throw fault(503, 'Trusted filesystem provisioning is unavailable.'); const body = z.object({ approvalId: uuid }).strict().parse(request.body); const saved = await store.read(state => retainedApproval(state, body.approvalId, request.params.id, true)); const current = await sourceEvidence(dependencies, saved.scope.appId, saved.scope.sourceRootId);
    const prepared = await store.transaction(state => { const { approval, scope } = retainedApproval(state, body.approvalId, request.params.id, true); if (approval.approvedBy !== request.principal!.id || !sameSource(scope, current)) throw fault(409, 'The approving owner or exact company source/adapter baseline changed.'); if (Object.values(state.adapterOperations).some(operation => operation.connectionId === scope.connectionId && operation.appId === scope.appId && operation.status !== 'failed')) throw fault(409, 'An operation is already retained; no blind dispatch retry is allowed.');
      approval.consumedAt = timestamp(); const operationId = randomUUID(), operation: AdapterOperation = { operationId, approvalId: approval.id, appId: scope.appId, connectionId: scope.connectionId, artifactHash: approval.artifactHash, type: 'filesystem', status: 'pending', scopeHash: null, liveRootVerified: false, createdAt: timestamp(), completedAt: null, detail: 'Exact approved request retained before dispatch. Unknown outcomes remain pending for read-only reconciliation.' }; state.adapterOperations[operationId] = operation; const input: FilesystemProvisionRequest = { schemaVersion: 1, action: 'approve_readonly_filesystem', operationId, approvalId: approval.id, artifactHash: approval.artifactHash, scope, approvedAt: approval.approvedAt!, principal: { id: request.principal!.id, mfa: true, localOwner: true } }; return { operation, input };
    });
    try { await recordStatus(store, prepared.operation, exactStatus(await dependencies.provisionFilesystem(prepared.input), prepared.operation)); } catch (value) { if ((value as { confirmedRejected?: unknown })?.confirmedRejected === true) await store.transaction(state => { const operation = state.adapterOperations[prepared.operation.operationId]; if (operation?.status === 'pending') { operation.status = 'failed'; operation.completedAt = timestamp(); operation.detail = 'Runtime proved rejection before execution; resolve company setup and request a new exact review.'; } }); }
    return { operation: await store.read(state => state.adapterOperations[prepared.operation.operationId]) };
  });
}
