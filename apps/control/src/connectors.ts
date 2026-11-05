import { createDecipheriv, createHash, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { hashArtifact, redact } from '../../../packages/core/src/security.ts';
import type { ConnectionRecord, Principal } from '../../../packages/core/src/types.ts';
import type { SambaProvisionRequest, ConnectorStatus } from '../../../packages/core/src/connectors.ts';
import { requireOwner } from './auth.ts';
import type { Store, State } from './store.ts';
import { notify } from './store.ts';
import type { Config } from './config.ts';
import { connectionWithdrawn } from './connection-revocation.ts';

export type ConnectorScope = { appId: string; connectionId: string; type: 'samba'; serverIp: string; share: string; root: string; readonlyAclEvidenceSha256: string; aclEvidenceCheckedAt: string; aclEvidenceDescription: string; accessExpiresAt: string; credentialRef: string; credentialCiphertextSha256: string; registryHash: string };
export type ConnectorApproval = { id: string; appId: string; connectionId: string; action: 'approve_readonly_samba'; artifactHash: string; impact: string[]; createdAt: string; expiresAt: string; approvedAt: string | null; approvedBy: string | null; consumedAt: string | null };
export type ConnectorOperation = { id: string; approvalId: string; appId: string; connectionId: string; artifactHash: string; status: 'pending' | 'configured' | 'failed'; scopeHash: string | null; liveShareVerified: false; createdAt: string; completedAt: string | null; detail: string };
export type ConnectorDependencies = { provisionSamba?: (input: SambaProvisionRequest) => Promise<ConnectorStatus>; connectorStatus?: (input: { appId: string; connectionId: string; approvalId: string }) => Promise<ConnectorStatus> };
const hex = z.string().regex(/^[a-f0-9]{64}$/), uuid = z.string().uuid();
const fault = (statusCode: number, message: string) => Object.assign(new Error(message), { statusCode });
const now = () => new Date().toISOString();
const cipherHash = (value: string) => createHash('sha256').update(value).digest('hex');
export function validSambaName(value: string): boolean { return !!value && Buffer.byteLength(value) <= 240 && !/[\\/:%<>|?*"\x00-\x1f\x7f]/.test(value) && !['.', '..'].includes(value) && !value.startsWith(' ') && !/[. ]$/.test(value); }
export function validSambaIp(value: string): boolean { if (isIP(value) !== 4 || value.split('.').map(part => String(Number(part))).join('.') !== value) return false; const [a, b] = value.split('.').map(Number); return a! > 0 && a !== 127 && !(a === 169 && b === 254) && a! < 224; }
const name = z.string().refine(validSambaName, 'Use one ordinary share name or logical root alias, with no filesystem path or wildcard.');
const schema = z.object({ appId: uuid, serverIp: z.string().refine(validSambaIp, 'Use one unicast literal IPv4 Samba server.'), share: name.refine(value => !value.endsWith('$'), 'Hidden administrative shares are not supported.'), root: name, readonlyAclEvidenceSha256: hex, aclEvidenceCheckedAt: z.string().datetime(), aclEvidenceDescription: z.string().trim().min(10).max(1000), accessExpiresAt: z.string().datetime() }).strict();
export const connectorArtifactHash = (scope: ConnectorScope) => hashArtifact({ schemaVersion: 1, action: 'approve_readonly_samba', scope });
function connection(state: State, id: string): ConnectionRecord { const item = state.connections[id]; if (!item) throw fault(404, 'Connection not found.'); return item; }
function validateScopeRegistry(state: State, scope: ConnectorScope): void {
  if (connectionWithdrawn(state, scope.appId, scope.connectionId)) throw fault(409, 'This app/connection has a retained withdrawal intent. Regrant requires a new connection ID.');
  const item = connection(state, scope.connectionId), app = state.apps[scope.appId];
  if (!app || app.status === 'archived' || item.type !== 'samba' || !item.appIds.includes(scope.appId) || item.status === 'disabled' || !item.secretRef || item.secretRef !== scope.credentialRef || !state.secrets[scope.credentialRef]) throw fault(409, 'The approved app, Samba registry access or encrypted credential reference is unavailable.');
  if (item.capabilities.length !== 2 || new Set(item.capabilities).size !== 2 || !item.capabilities.includes('files.list') || !item.capabilities.includes('files.read')) throw fault(409, 'The Samba registry must explicitly allow only files.list and files.read.');
  if (!item.roots.includes(scope.root) || !item.endpoints.some(value => { try { const endpoint = new URL(value); return endpoint.protocol === 'smb:' && endpoint.hostname === scope.serverIp && (!endpoint.port || endpoint.port === '445') && !endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash && decodeURIComponent(endpoint.pathname).replace(/\/$/, '') === `/${scope.share}`; } catch { return false; } })) throw fault(409, 'The exact Samba server, share and logical root must already be authorized by the registry.');
  if (hashArtifact(item) !== scope.registryHash || cipherHash(state.secrets[scope.credentialRef]!) !== scope.credentialCiphertextSha256) throw fault(409, 'Connection scope or stored credential version changed after review. Request a new approval.');
  const expires = Date.parse(scope.accessExpiresAt), evidence = Date.parse(scope.aclEvidenceCheckedAt), credentialExpires = item.expiresAt ? Date.parse(item.expiresAt) : null;
  if (!Number.isFinite(expires) || expires <= Date.now() || expires > Date.now() + 90 * 86400000 || !Number.isFinite(evidence) || evidence > Date.now() + 60000 || Date.now() - evidence > 86400000 || credentialExpires !== null && (!Number.isFinite(credentialExpires) || credentialExpires <= Date.now() || expires > credentialExpires)) throw fault(409, 'Samba access must expire within 90 days and credential lifetime; owner-reviewed read-only ACL evidence must be current within 24 hours.');
}
function credentials(state: State, config: Config, scope: ConnectorScope): SambaProvisionRequest['credentials'] {
  try {
    const envelope = state.secrets[scope.credentialRef]; if (!envelope) throw new Error(); const parts = envelope.split('.'); if (parts.length !== 3) throw new Error();
    const [nonce, tag, data] = parts.map(value => Buffer.from(value, 'base64')); if (nonce!.length !== 12 || tag!.length !== 16) throw new Error();
    const decipher = createDecipheriv('aes-256-gcm', config.secretKey, nonce!); decipher.setAAD(Buffer.from(scope.credentialRef)); decipher.setAuthTag(tag!);
    const value: unknown = JSON.parse(Buffer.concat([decipher.update(data!), decipher.final()]).toString('utf8'));
    return z.object({ username: z.string().min(1).max(1024).refine(value => !value.includes('\0') && Buffer.byteLength(value) <= 1024), password: z.string().min(1).max(1024).refine(value => !value.includes('\0') && Buffer.byteLength(value) <= 1024) }).strict().parse(value);
  } catch { throw fault(409, 'The protected Samba credential must contain only a dedicated read-only username and password. Recreate the connection with valid protected credentials; do not enter them into chat.'); }
}
function exactApproval(state: State, id: string, connectionId: string, approved: boolean): { approval: ConnectorApproval; scope: ConnectorScope } {
  const approval = state.connectorApprovals[id], scope = state.connectorChanges[id];
  if (!approval || !scope || approval.connectionId !== connectionId || scope.connectionId !== connectionId || approval.appId !== scope.appId || approval.action !== 'approve_readonly_samba' || approval.artifactHash !== connectorArtifactHash(scope) || !Number.isFinite(Date.parse(approval.expiresAt)) || Date.parse(approval.expiresAt) <= Date.now() || approval.consumedAt || approved && (!approval.approvedAt || !approval.approvedBy)) throw fault(409, 'A current five-minute owner approval for this exact Samba scope is required.');
  validateScopeRegistry(state, scope); return { approval, scope };
}
function validateStatus(value: unknown, operation: ConnectorOperation): ConnectorStatus {
  const parsed = z.object({ status: z.enum(['configured', 'unknown']), appId: uuid, connectionId: uuid, approvalId: uuid, scopeHash: hex.optional(), liveShareVerified: z.literal(false) }).strict().safeParse(value);
  if (!parsed.success || parsed.data.appId !== operation.appId || parsed.data.connectionId !== operation.connectionId || parsed.data.approvalId !== operation.approvalId || parsed.data.status === 'configured' && !parsed.data.scopeHash) throw fault(503, 'Runtime connector evidence is malformed or belongs to another scope. Provisioning remains unconfirmed.'); return parsed.data;
}
async function recordStatus(store: Store, operation: ConnectorOperation, status: ConnectorStatus): Promise<void> {
  if (status.status !== 'configured') return;
  await store.transaction(state => { const item = state.connectorOperations[operation.id]; if (!item || item.status !== 'pending') return; item.status = 'configured'; item.scopeHash = status.scopeHash!; item.completedAt = now(); item.detail = 'Runtime retained the exact reviewed encrypted configuration. Actual share access is verified during application preview; this does not prove remote write denial.'; notify(state, 'info', 'Read-only Samba scope configured', `${state.connections[item.connectionId]?.name}: reviewed for ${state.apps[item.appId]?.name}. Actual encrypted share verification remains required before application use.`); });
}
export async function reconcileConnectorOperations(store: Store, dependencies: ConnectorDependencies, connectionId?: string): Promise<void> {
  if (!dependencies.connectorStatus) return;
  const operations = await store.read(state => Object.values(state.connectorOperations).filter(item => item.status === 'pending' && (!connectionId || item.connectionId === connectionId)));
  for (const operation of operations) { try { await recordStatus(store, operation, validateStatus(await dependencies.connectorStatus({ appId: operation.appId, connectionId: operation.connectionId, approvalId: operation.approvalId }), operation)); } catch { /* Missing/ambiguous credentials or receipts cannot authorize a retry. */ } }
}
export async function installConnectorRoutes(server: FastifyInstance, store: Store, config: Config, dependencies: ConnectorDependencies): Promise<void> {
  server.get<{ Params: { id: string } }>('/api/v1/connections/:id/provisioning', async request => { await store.read(state => connection(state, request.params.id)); await reconcileConnectorOperations(store, dependencies, request.params.id); return store.read(state => ({ approvals: Object.values(state.connectorApprovals).filter(item => item.connectionId === request.params.id), operations: Object.values(state.connectorOperations).filter(item => item.connectionId === request.params.id).map(item => ({ ...item, accessExpiresAt: state.connectorChanges[item.approvalId]?.accessExpiresAt ?? null })) })); });
  server.post<{ Params: { id: string } }>('/api/v1/connections/:id/samba/approval', async request => {
    requireOwner(request); const body = schema.parse(request.body); if (String(redact(body.aclEvidenceDescription)) !== body.aclEvidenceDescription) throw fault(400, 'ACL descriptions must not contain credentials. Upload or review credentials through protected setup.');
    return { approval: await store.transaction(state => { const item = connection(state, request.params.id); if (!item.secretRef || !state.secrets[item.secretRef]) throw fault(409, 'Stored Samba credentials are required before scope review.');
      const scope: ConnectorScope = { ...body, type: 'samba', connectionId: item.id, credentialRef: item.secretRef, credentialCiphertextSha256: cipherHash(state.secrets[item.secretRef]!), registryHash: hashArtifact(item) }; validateScopeRegistry(state, scope); const protectedCredentials = credentials(state, config, scope); if (String(redact(body.aclEvidenceDescription, [protectedCredentials.password, protectedCredentials.username])) !== body.aclEvidenceDescription) throw fault(400, 'The ACL description must not contain stored credentials.');
      if (Object.values(state.connectorOperations).some(operation => operation.connectionId === item.id && operation.appId === body.appId && operation.status !== 'failed')) throw fault(409, 'This connection already has a retained runtime operation for that app. Refresh its status; changed scope or credentials require a new connection identity.');
      const id = randomUUID(), approval: ConnectorApproval = { id, appId: body.appId, connectionId: item.id, action: 'approve_readonly_samba', artifactHash: connectorArtifactHash(scope), impact: [`Provision ${item.name} only for ${state.apps[body.appId]?.name} (${body.appId}).`, `Permit read-only files.list and files.read on ${body.serverIp}:445, entire ordinary share ${body.share}, exposed through logical root ${body.root}. No subtree restriction is implied.`, `Owner-reviewed remote account/share ACL artifact ${body.readonlyAclEvidenceSha256}, checked ${body.aclEvidenceCheckedAt}: ${body.aclEvidenceDescription}`, `Access expires ${body.accessExpiresAt}; this review expires after five minutes. Stored credential reference ${scope.credentialRef}, encrypted credential version ${scope.credentialCiphertextSha256}.`, 'Credentials are passed only to the isolated trusted connector. Runtime image scanning and company protocol qualification must pass. Configured state does not prove live share access or remote write denial; the actual encrypted read/list probe must pass during application preview.'], createdAt: now(), expiresAt: new Date(Date.now() + 300000).toISOString(), approvedAt: null, approvedBy: null, consumedAt: null }; state.connectorApprovals[id] = approval; state.connectorChanges[id] = scope; return approval;
    }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/connectors/approvals/:id/approve', async request => {
    requireOwner(request); const body = z.object({ artifactHash: hex }).strict().parse(request.body);
    return { approval: await store.transaction(state => { const original = state.connectorApprovals[request.params.id]; if (!original) throw fault(404, 'Connector approval not found.'); const { approval } = exactApproval(state, original.id, original.connectionId, false); if (approval.approvedAt || approval.artifactHash !== body.artifactHash) throw fault(409, 'The exact connector review changed or was already approved.'); approval.approvedBy = request.principal!.id; approval.approvedAt = now(); return approval; }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/connections/:id/samba/provision', async request => {
    requireOwner(request); if (!dependencies.provisionSamba) throw fault(503, 'Trusted Samba provisioning is unavailable. No connector was provisioned.'); const body = z.object({ approvalId: uuid }).strict().parse(request.body);
    const prepared = await store.transaction(state => { const { approval, scope } = exactApproval(state, body.approvalId, request.params.id, true); if (approval.approvedBy !== request.principal!.id) throw fault(403, 'The exact approving permanent owner must provision this connector.');
      if (Object.values(state.connectorOperations).some(operation => operation.connectionId === scope.connectionId && operation.appId === scope.appId && operation.status !== 'failed')) throw fault(409, 'A connector operation already exists. Inspect its retained outcome; provisioning cannot be blindly retried.');
      const protectedCredentials = credentials(state, config, scope); approval.consumedAt = now(); const id = randomUUID();
      const operation: ConnectorOperation = { id, approvalId: approval.id, appId: scope.appId, connectionId: scope.connectionId, artifactHash: approval.artifactHash, status: 'pending', scopeHash: null, liveShareVerified: false, createdAt: now(), completedAt: null, detail: 'The exact protected request was retained before dispatch. Awaiting runtime confirmation; no automatic credential replay.' }; state.connectorOperations[id] = operation;
      const input: SambaProvisionRequest = { schemaVersion: 1, action: 'approve_readonly_samba', approvalId: approval.id, appId: scope.appId, connectionId: scope.connectionId, type: 'samba', serverIp: scope.serverIp, share: scope.share, root: scope.root, readonlyAclEvidenceSha256: scope.readonlyAclEvidenceSha256, approvedAt: approval.approvedAt!, expiresAt: scope.accessExpiresAt, principal: { id: request.principal!.id, mfa: true, localOwner: true }, credentials: protectedCredentials }; return { operation, input };
    });
    try { await recordStatus(store, prepared.operation, validateStatus(await dependencies.provisionSamba(prepared.input), prepared.operation)); }
    catch (value) { if ((value as { confirmedRejected?: boolean }).confirmedRejected) await store.transaction(state => { const operation = state.connectorOperations[prepared.operation.id]!; operation.status = 'failed'; operation.completedAt = now(); operation.detail = 'Runtime rejected the scope before execution. Resolve the protected setup and request a new review.'; }); }
    return { operation: await store.read(state => state.connectorOperations[prepared.operation.id]) };
  });
}
