import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { Pool } from 'mysql2/promise';
import type { AppRecord, JobRecord, ReleaseRecord, ApprovalRecord, ConnectionRecord, NotificationRecord, ProgressEvent, BudgetReservation, Principal } from '../../../packages/core/src/types.ts';
import type { SecurityReport, SecurityFindingSnapshot, BackupReport } from './reports.ts';
import type { BudgetChange } from './budget.ts';
import type { SpendingAuthorityRecord } from './spending-authority.ts';
import type { ModelCallRecord } from './model-records.ts';
import type { ModelCheckpointRecord, GenerationContextRecord } from './model-checkpoints.ts';
import type { RecoveryGrantRecord, ObservationState, ObservationAttempt, RecoveryIntent } from './observation.ts';
import type { AccessApproval, AppAccessSnapshot, AccessActor } from '../../../packages/core/src/access.ts';
import type { AccessChange, AccessOperation, InvitationRecord } from './access.ts';
import type { ConnectorApproval, ConnectorOperation, ConnectorScope } from './connectors.ts';
import type { IntegrationResearchRecord } from './integration-research.ts';
import type { AdapterApproval, AdapterOperation } from './filesystem-connectors.ts';
import type { FilesystemScope } from '../../../packages/core/src/connector-adapters.ts';
import type { DirectoryApproval, DirectoryActivation, DirectoryEvidenceRecord } from '../../../packages/core/src/directory.ts';
import type { WithdrawalApproval, WithdrawalOperation } from './connection-revocation.ts';
import type { AppAccountApproval } from '../../../packages/core/src/app-accounts.ts';
import type { AppAccountOperation } from './app-accounts.ts';
import type { ExternalEffectRecord, ExternalEventRecord } from './external-effects.ts';
import type { StripeWebhookApproval, StripeWebhookEndpoint } from './stripe-webhooks.ts';

export type OutboxRecord = { id: string; jobId: string; publishedAt: string | null; createdAt: string };
export type Lease = { owner: string; until: string };
export type Session = { id: string; principal: Principal; csrfToken: string; expiresAt: string; accessExpiresAt?: string; encryptedRefreshToken?: string };
export type AuthState = { verifier: string; nonce: string; expiresAt: string };
export type PreviewSession = { appId: string; host: string; sessionId: string; expiresAt: string; releaseId?: string };
export type Operation = { id: string; appId: string; releaseId: string; baseReleaseId: string | null; action: 'publish' | 'rollback'; status: 'running' | 'succeeded' | 'failed'; approvalId?: string; artifactHash?: string; error?: string; createdAt: string };
export type State = {
  portalListings: Record<string, import('./portal-listing.ts').PortalListing>; portalListingHistory: Record<string, import('./portal-listing.ts').PortalListing>;
  apps: Record<string, AppRecord>; jobs: Record<string, JobRecord>; releases: Record<string, ReleaseRecord>;
  approvals: Record<string, ApprovalRecord>; connections: Record<string, ConnectionRecord>; notifications: Record<string, NotificationRecord>;
  spendingAuthorities: Record<string, SpendingAuthorityRecord>;
  reservations: Record<string, BudgetReservation>; outbox: Record<string, OutboxRecord>; leases: Record<string, Lease>;
  sessions: Record<string, Session>; authStates: Record<string, AuthState>; secrets: Record<string, string>;
  operations: Record<string, Operation>; events: ProgressEvent[]; nextEventId: number;
  securityReports: Record<string, SecurityReport>; securityFindingStates: Record<string, SecurityFindingSnapshot>; backupReports: Record<string, BackupReport>;
  approvalScans: Record<string, string>;
  budgetApprovals: Record<string, BudgetChange>; settings: Record<string, { monthlyLimitUsd?: number }>;
  repairAttempts: Record<string, { review: number; verification: number }>;
  previewTickets: Record<string, PreviewSession>; previewSessions: Record<string, PreviewSession>;
  modelCalls: Record<string, ModelCallRecord>;
  modelCheckpoints: Record<string, ModelCheckpointRecord>; generationContexts: Record<string, GenerationContextRecord>;
  recoveryGrants: Record<string, RecoveryGrantRecord>; recoveryGrantScans: Record<string, string>;
  observations: Record<string, ObservationState>; observationAttempts: Record<string, ObservationAttempt>; observationLeases: Record<string, Lease>; recoveryIntents: Record<string, RecoveryIntent>;
  accessSnapshots: Record<string, AppAccessSnapshot>; accessApprovals: Record<string, AccessApproval>; accessChanges: Record<string, AccessChange>; accessActors: Record<string, AccessActor>; accessOperations: Record<string, AccessOperation>; invitations: Record<string, InvitationRecord>;
  connectorApprovals: Record<string, ConnectorApproval>; connectorChanges: Record<string, ConnectorScope>; connectorOperations: Record<string, ConnectorOperation>;
  integrationResearch: Record<string, IntegrationResearchRecord>;
  adapterApprovals: Record<string, AdapterApproval>; adapterChanges: Record<string, FilesystemScope>; adapterOperations: Record<string, AdapterOperation>;
  directoryApprovals: Record<string, DirectoryApproval>; directoryActivations: Record<string, DirectoryActivation>; directoryEvidence: Record<string, DirectoryEvidenceRecord>;
  revocationApprovals: Record<string, WithdrawalApproval>; revocationOperations: Record<string, WithdrawalOperation>;
  appAccountApprovals: Record<string, AppAccountApproval>; appAccountOperations: Record<string, AppAccountOperation>;
  externalEffects: Record<string, ExternalEffectRecord>; externalEvents: Record<string, ExternalEventRecord>;
  stripeWebhookApprovals: Record<string, StripeWebhookApproval>; stripeWebhookEndpoints: Record<string, StripeWebhookEndpoint>;
};
export const emptyState = (): State => ({ portalListings: {}, portalListingHistory: {}, stripeWebhookApprovals: {}, stripeWebhookEndpoints: {}, spendingAuthorities: {}, externalEffects: {}, externalEvents: {}, apps: {}, jobs: {}, releases: {}, approvals: {}, connections: {}, notifications: {}, reservations: {}, outbox: {}, leases: {}, sessions: {}, authStates: {}, secrets: {}, operations: {}, securityReports: {}, securityFindingStates: {}, backupReports: {}, approvalScans: {}, budgetApprovals: {}, settings: {}, repairAttempts: {}, previewTickets: {}, previewSessions: {}, modelCalls: {}, modelCheckpoints: {}, generationContexts: {}, recoveryGrants: {}, recoveryGrantScans: {}, observations: {}, observationAttempts: {}, observationLeases: {}, recoveryIntents: {}, accessSnapshots: {}, accessApprovals: {}, accessChanges: {}, accessActors: {}, accessOperations: {}, invitations: {}, connectorApprovals: {}, connectorChanges: {}, connectorOperations: {}, integrationResearch: {}, adapterApprovals: {}, adapterChanges: {}, adapterOperations: {}, directoryApprovals: {}, directoryActivations: {}, directoryEvidence: {}, revocationApprovals: {}, revocationOperations: {}, appAccountApprovals: {}, appAccountOperations: {}, events: [], nextEventId: 1 });
export interface Store { mode: 'mysql' | 'development'; transaction<T>(action: (state: State) => T | Promise<T>): Promise<T>; read<T>(action: (state: State) => T): Promise<T>; close(): Promise<void>; subscribe?(jobId: string, listener: () => void): () => void; }

/** Transactions serialize mutations, including event/outbox creation and budget reservation. */
export class JsonStore implements Store {
  readonly mode = 'development'; private state: State = emptyState(); private queue: Promise<unknown> = Promise.resolve();
  constructor(private readonly file?: string) {}
  async initialize(): Promise<void> {
    if (!this.file) return;
    try { this.state = { ...emptyState(), ...JSON.parse(await readFile(this.file, 'utf8')) as State }; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  transaction<T>(action: (state: State) => T | Promise<T>): Promise<T> {
    const pending = this.queue.then(async () => {
      const next = structuredClone(this.state); const result = await action(next);
      if (this.file) {
        await mkdir(dirname(this.file), { recursive: true, mode: 0o700 });
        const tmp = `${this.file}.${randomUUID()}.tmp`;
        await writeFile(tmp, JSON.stringify(next), { mode: 0o600 }); await rename(tmp, this.file);
      }
      this.state = next; return structuredClone(result);
    });
    this.queue = pending.catch(() => undefined); return pending;
  }
  async read<T>(action: (state: State) => T): Promise<T> { await this.queue; return structuredClone(action(this.state)); }
  async close(): Promise<void> { await this.queue; }
}

/** The installation revision row gives serializable, crash-safe state transitions.
 * Records and events are separately indexed; no business state is stored in Redis. */
export class MysqlStore implements Store {
  readonly mode = 'mysql';
  constructor(private readonly pool: Pool) {}
  async initialize(): Promise<void> {
    await this.pool.query('CREATE TABLE IF NOT EXISTS platform_revision (id TINYINT PRIMARY KEY, revision BIGINT NOT NULL) ENGINE=InnoDB');
    await this.pool.query('INSERT IGNORE INTO platform_revision VALUES (1, 0)');
    await this.pool.query('CREATE TABLE IF NOT EXISTS platform_records (collection VARCHAR(32) NOT NULL, id VARCHAR(128) NOT NULL, app_id VARCHAR(128) NULL, payload JSON NOT NULL, PRIMARY KEY (collection,id), INDEX app_records(app_id,collection)) ENGINE=InnoDB');
    await this.pool.query('CREATE TABLE IF NOT EXISTS platform_events (id BIGINT PRIMARY KEY, job_id VARCHAR(128) NOT NULL, created_at DATETIME(3) NOT NULL, payload JSON NOT NULL, INDEX job_events(job_id,id), INDEX event_retention(created_at)) ENGINE=InnoDB');
  }
  private async load(executor: Pick<Pool, 'query'>): Promise<State> {
    const state = emptyState();
    // MySQL drivers may decode JSON scalar strings differently from JSON objects.
    // Explicit text casting gives one unambiguous representation for encrypted strings and hashes.
    const [records] = await executor.query('SELECT collection,id,CAST(payload AS CHAR CHARACTER SET utf8mb4) AS payload FROM platform_records');
    for (const record of records as unknown as { collection: string; id: string; payload: unknown }[]) {
      const payload = typeof record.payload === 'string' ? JSON.parse(record.payload) : record.payload;
      if (record.collection === 'metadata') { state.nextEventId = Number((payload as { nextEventId: number }).nextEventId); continue; }
      const bucket = state[record.collection as keyof State];
      if (bucket && !Array.isArray(bucket) && typeof bucket === 'object') (bucket as Record<string, unknown>)[record.id] = payload;
    }
    const [events] = await executor.query('SELECT CAST(payload AS CHAR CHARACTER SET utf8mb4) AS payload FROM platform_events ORDER BY id');
    state.events = (events as unknown as { payload: unknown }[]).map(row => typeof row.payload === 'string' ? JSON.parse(row.payload) as ProgressEvent : row.payload as ProgressEvent);
    return state;
  }
  async transaction<T>(action: (state: State) => T | Promise<T>): Promise<T> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction(); await connection.query('SELECT revision FROM platform_revision WHERE id=1 FOR UPDATE');
      const before = await this.load(connection as unknown as Pick<Pool, 'query'>); const state = structuredClone(before);
      const result = await action(state);
      for (const collection of Object.keys(state) as (keyof State)[]) {
        if (collection === 'events' || collection === 'nextEventId') continue;
        const oldRecords = before[collection] as Record<string, unknown>; const records = state[collection] as Record<string, unknown>;
        for (const id of Object.keys(oldRecords)) if (!(id in records)) await connection.query('DELETE FROM platform_records WHERE collection=? AND id=?', [collection, id]);
        for (const [id, value] of Object.entries(records)) {
          if (JSON.stringify(oldRecords[id]) === JSON.stringify(value)) continue;
          const appId = (value as { appId?: string }).appId ?? (collection === 'apps' ? id : null);
          await connection.query('INSERT INTO platform_records(collection,id,app_id,payload) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE app_id=VALUES(app_id),payload=VALUES(payload)', [collection, id, appId, JSON.stringify(value)]);
        }
      }
      await connection.query("INSERT INTO platform_records(collection,id,payload) VALUES ('metadata','state',?) ON DUPLICATE KEY UPDATE payload=VALUES(payload)", [JSON.stringify({ nextEventId: state.nextEventId })]);
      const oldIds = new Set(before.events.map(event => event.id)); const newIds = new Set(state.events.map(event => event.id));
      for (const event of state.events) if (!oldIds.has(event.id)) await connection.query('INSERT INTO platform_events VALUES (?,?,?,?)', [event.id, event.jobId, new Date(event.createdAt), JSON.stringify(event)]);
      for (const event of before.events) if (!newIds.has(event.id)) await connection.query('DELETE FROM platform_events WHERE id=?', [event.id]);
      await connection.query('UPDATE platform_revision SET revision=revision+1 WHERE id=1'); await connection.commit(); return result;
    } catch (error) { await connection.rollback(); throw error; } finally { connection.release(); }
  }
  async read<T>(action: (state: State) => T): Promise<T> {
    const connection = await this.pool.getConnection();
    try { await connection.beginTransaction(); const state = await this.load(connection as unknown as Pick<Pool, 'query'>); const result = action(state); await connection.commit(); return result; }
    catch (error) { await connection.rollback(); throw error; } finally { connection.release(); }
  }
  async close(): Promise<void> { await this.pool.end(); }
}

export function event(state: State, job: JobRecord, stage: JobRecord['stage'], message: string, kind: ProgressEvent['kind'] = 'status', detail?: Record<string, unknown>): ProgressEvent {
  job.stage = stage; job.updatedAt = new Date().toISOString();
  const next: ProgressEvent = { id: state.nextEventId++, jobId: job.id, stage, kind, message, createdAt: job.updatedAt, ...(detail ? { detail } : {}) };
  state.events.push(next); return next;
}
export function notify(state: State, severity: NotificationRecord['severity'], title: string, message: string): void {
  if (Object.values(state.notifications).some(item => !item.read && item.title === title && item.message === message)) return;
  const id = randomUUID(); state.notifications[id] = { id, severity, title, message, read: false, createdAt: new Date().toISOString() };
}
export function enqueue(state: State, jobId: string): void {
  if (Object.values(state.outbox).some(item => item.jobId === jobId && !item.publishedAt)) return;
  const id = randomUUID(); state.outbox[id] = { id, jobId, publishedAt: null, createdAt: new Date().toISOString() };
}
