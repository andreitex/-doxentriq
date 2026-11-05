import { createDecipheriv, createHash } from 'node:crypto';
import { hashArtifact, redact } from '../../../packages/core/src/security.ts';
import { validatedGenerationConnections, type GenerationConnectionInventory } from '../../../packages/core/src/connection-context.ts';
import type { ConnectionRecord } from '../../../packages/core/src/types.ts';
import type { ConnectorScope, ConnectorDependencies } from './connectors.ts';
import { connectorArtifactHash, validSambaName } from './connectors.ts';
import type { Store, State } from './store.ts';
import { filesystemArtifactHash, filesystemStatusSchema } from '../../../packages/core/src/connector-adapters.ts';
import type { AdapterDependencies, AdapterOperation } from './filesystem-connectors.ts';
import { validateFilesystemRegistry } from './filesystem-connectors.ts';
import { connectionWithdrawn } from './connection-revocation.ts';

type Item = GenerationConnectionInventory['connections'][number];
const ciphertextHash = (value: string) => createHash('sha256').update(value).digest('hex');

// Credential values are used only to remove accidental copies from descriptive
// registry fields. They never leave this function, including on decryption errors.
function protectedValues(state: State, item: ConnectionRecord, key: Buffer): string[] | null {
  if (!item.secretRef) return [];
  try {
    const envelope = state.secrets[item.secretRef]; if (!envelope) return null;
    const parts = envelope.split('.'); if (parts.length !== 3) return null;
    const [nonce, tag, data] = parts.map(value => Buffer.from(value, 'base64'));
    if (nonce!.length !== 12 || tag!.length !== 16) return null;
    const decipher = createDecipheriv('aes-256-gcm', key, nonce!); decipher.setAAD(Buffer.from(item.secretRef)); decipher.setAuthTag(tag!);
    const parsed: unknown = JSON.parse(Buffer.concat([decipher.update(data!), decipher.final()]).toString('utf8'));
    const strings: string[] = [];
    const walk = (value: unknown, depth: number): void => {
      if (depth > 8) throw new Error();
      if (typeof value === 'string' && value) strings.push(value);
      else if (Array.isArray(value)) value.forEach(entry => walk(entry, depth + 1));
      else if (value && typeof value === 'object') Object.values(value).forEach(entry => walk(entry, depth + 1));
    };
    walk(parsed, 0); return strings;
  } catch { return null; }
}
function cleanText(value: string, secrets: string[]): string {
  let cleaned = String(redact(value));
  for (const secret of secrets) cleaned = cleaned.split(secret).join('[REDACTED]');
  return cleaned;
}
function exactConfiguredScope(state: State, connection: ConnectionRecord, appId: string, at: number, ownerSubject?: string): { scope: ConnectorScope; scopeHash: string; approvalId: string } | null {
  if (connectionWithdrawn(state, appId, connection.id)) return null;
  if (!state.apps[appId] || state.apps[appId]!.status === 'archived' || connection.type !== 'samba' || connection.status !== 'configured' || !connection.appIds.includes(appId) || connection.expiresAt && (!Number.isFinite(Date.parse(connection.expiresAt)) || Date.parse(connection.expiresAt) <= at)) return null;
  const operations = Object.values(state.connectorOperations).filter(operation => operation.connectionId === connection.id && operation.appId === appId && operation.status === 'configured');
  if (operations.length !== 1) return null;
  const operation = operations[0]!, approval = state.connectorApprovals[operation.approvalId], scope = state.connectorChanges[operation.approvalId];
  if (!scope || !approval || scope.connectionId !== connection.id || scope.appId !== appId || approval.connectionId !== connection.id || approval.appId !== appId || approval.id !== operation.approvalId || !approval.approvedBy || ownerSubject && approval.approvedBy !== ownerSubject || !approval.approvedAt || !approval.consumedAt || approval.action !== 'approve_readonly_samba' || approval.artifactHash !== operation.artifactHash || approval.artifactHash !== connectorArtifactHash(scope) || !operation.scopeHash || !/^[a-f0-9]{64}$/.test(operation.scopeHash)) return null;
  if (!connection.secretRef || connection.secretRef !== scope.credentialRef || !state.secrets[scope.credentialRef] || ciphertextHash(state.secrets[scope.credentialRef]!) !== scope.credentialCiphertextSha256 || hashArtifact(connection) !== scope.registryHash) return null;
  if (!Number.isFinite(Date.parse(scope.accessExpiresAt)) || Date.parse(scope.accessExpiresAt) <= at || !/^[a-f0-9]{64}$/.test(scope.readonlyAclEvidenceSha256)) return null;
  const approved = Date.parse(approval.approvedAt), evidence = Date.parse(scope.aclEvidenceCheckedAt);
  if (!Number.isFinite(approved) || approved > at + 60000 || !Number.isFinite(evidence) || evidence > approved + 60000 || approved - evidence > 86400000) return null;
  if (!validSambaName(scope.root) || !connection.roots.includes(scope.root) || connection.capabilities.length !== 2 || new Set(connection.capabilities).size !== 2 || !connection.capabilities.includes('files.list') || !connection.capabilities.includes('files.read')) return null;
  return { scope, scopeHash: operation.scopeHash, approvalId: operation.approvalId };
}

function exactFilesystemOperation(state: State, connection: ConnectionRecord, appId: string, at: number, ownerSubject?: string): AdapterOperation | null {
  const operations = Object.values(state.adapterOperations).filter(operation => operation.connectionId === connection.id && operation.appId === appId && operation.type === 'filesystem' && operation.status === 'configured');
  if (operations.length !== 1) return null;
  const operation = operations[0]!, approval = state.adapterApprovals[operation.approvalId], scope = state.adapterChanges[operation.approvalId];
  if (!scope || !approval || scope.appId !== appId || scope.connectionId !== connection.id || approval.appId !== appId || approval.connectionId !== connection.id || !approval.approvedBy || ownerSubject && approval.approvedBy !== ownerSubject || !approval.approvedAt || !approval.consumedAt || approval.action !== 'approve_readonly_filesystem' || approval.artifactHash !== operation.artifactHash || operation.scopeHash !== operation.artifactHash || approval.artifactHash !== filesystemArtifactHash(scope)) return null;
  const approved = Date.parse(approval.approvedAt), consumed = Date.parse(approval.consumedAt), reviewExpiry = Date.parse(approval.expiresAt);
  if (![approved, consumed, reviewExpiry].every(Number.isFinite) || approved > at + 60000 || consumed < approved || consumed >= reviewExpiry || consumed - approved > 300000) return null;
  try { validateFilesystemRegistry(state, scope, at); } catch { return null; } return operation;
}
export async function generationConnectionInventory(store: Store, appId: string, options: { secretKey: Buffer; ownerSubject?: string; connectorStatus?: ConnectorDependencies['connectorStatus']; filesystemStatus?: AdapterDependencies['filesystemStatus']; now?: number }): Promise<GenerationConnectionInventory> {
  const at = options.now ?? Date.now();
  const state = await store.read(state => state), app = state.apps[appId];
  if (!app || app.status === 'archived') throw new Error('Connection context requires the current authorized application');
  const connections = Object.values(state.connections).filter(connection => connection.appIds.includes(appId));
  if (connections.length > 64) throw new Error('Application connection inventory exceeds its bounded model context');
  const items = await Promise.all(connections.map(async connection => {
    const secrets = protectedValues(state, connection, options.secretKey);
    const item: Item = { id: connection.id, name: secrets ? cleanText(connection.name, secrets).slice(0, 120) || 'Protected connection' : 'Protected connection', type: connection.type, appIds: [appId], roots: secrets ? connection.roots.filter(root => validSambaName(root) && Buffer.byteLength(root) <= 240 && cleanText(root, secrets) === root) : [], capabilities: ['files.list','files.read'].filter(capability => connection.capabilities.includes(capability)) as Item['capabilities'], expiresAt: connection.expiresAt, status: 'unavailable', reason: 'not_configured' };
    if (connectionWithdrawn(state, appId, connection.id) || connection.status === 'disabled') item.reason = 'disabled';
    else if (connection.expiresAt && (!Number.isFinite(Date.parse(connection.expiresAt)) || Date.parse(connection.expiresAt) <= at)) { item.reason = 'expired'; if (!Number.isFinite(Date.parse(connection.expiresAt))) item.expiresAt = null; }
    else if (connection.type === 'filesystem') {
      const retained = exactFilesystemOperation(state, connection, appId, at, options.ownerSubject);
      if (!retained) item.reason = 'not_configured';
      else if (!options.filesystemStatus) item.reason = 'runtime_unavailable';
      else try {
        const proof = filesystemStatusSchema.parse(await options.filesystemStatus({ operationId: retained.operationId, approvalId: retained.approvalId, appId, connectionId: connection.id, artifactHash: retained.artifactHash }));
        if (proof.status !== 'configured' || proof.operationId !== retained.operationId || proof.approvalId !== retained.approvalId || proof.appId !== appId || proof.connectionId !== connection.id || proof.artifactHash !== retained.artifactHash || proof.scopeHash !== retained.scopeHash) throw new Error();
        const fresh = await store.read(current => { const item = current.connections[connection.id]; const operation = item ? exactFilesystemOperation(current, item, appId, options.now ?? Date.now(), options.ownerSubject) : null; return operation && operation.operationId === retained.operationId && operation.artifactHash === retained.artifactHash ? current.adapterChanges[operation.approvalId] : null; });
        if (!fresh || cleanText(fresh.root, secrets ?? []) !== fresh.root) throw new Error(); item.status = 'usable'; item.reason = null; item.roots = [fresh.root]; item.capabilities = ['files.list','files.read']; item.expiresAt = fresh.accessExpiresAt;
      } catch { item.reason = 'runtime_unavailable'; }
    }
    else if (secrets === null || connection.status === 'needs_credentials' || !connection.secretRef) item.reason = 'protected_setup_unavailable';
    else if (connection.type !== 'samba') item.reason = 'unsupported';
    else {
      const retained = exactConfiguredScope(state, connection, appId, at, options.ownerSubject);
      if (!retained) item.reason = Object.values(state.connectorOperations).some(operation => operation.appId === appId && operation.connectionId === connection.id && operation.status === 'configured') ? 'scope_changed' : 'not_configured';
      else if (!options.connectorStatus) item.reason = 'runtime_unavailable';
      else {
        try {
          const proof = await options.connectorStatus({ appId, connectionId: connection.id, approvalId: retained.approvalId });
          if (proof.status !== 'configured' || proof.appId !== appId || proof.connectionId !== connection.id || proof.approvalId !== retained.approvalId || proof.scopeHash !== retained.scopeHash || proof.liveShareVerified !== false || !secrets || cleanText(retained.scope.root, secrets) !== retained.scope.root) throw new Error();
          const stillCurrent = await store.read(current => {
            const currentConnection = current.connections[connection.id];
            return currentConnection ? exactConfiguredScope(current, currentConnection, appId, options.now ?? Date.now(), options.ownerSubject) : null;
          });
          if (!stillCurrent || stillCurrent.approvalId !== retained.approvalId || stillCurrent.scopeHash !== retained.scopeHash) throw new Error();
          item.status = 'usable'; item.reason = null; item.roots = [retained.scope.root]; item.capabilities = ['files.list','files.read']; item.expiresAt = retained.scope.accessExpiresAt;
        } catch { item.reason = 'runtime_unavailable'; }
      }
    }
    return item;
  }));
  const stillAuthorized = await store.read(current => {
    if (!current.apps[appId] || current.apps[appId]!.status === 'archived') throw new Error('The application changed while connection context was being verified');
    return new Set(Object.values(current.connections).filter(connection => connection.appIds.includes(appId) && !connectionWithdrawn(current, appId, connection.id)).map(connection => connection.id));
  });
  return validatedGenerationConnections({ schemaVersion: 1, connections: items.filter(item => stillAuthorized.has(item.id)) }, appId, options.now ?? Date.now());
}
