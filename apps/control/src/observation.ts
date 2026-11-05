import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { hashArtifact, releaseArtifactHash, redact } from '../../../packages/core/src/index.ts';
import { stages, imageSchema } from '../../../packages/core/src/schemas.ts';
import type { AppRecord, ReleaseRecord, RecoveryGrant, ReleaseObservation, ReleaseObservationRequest } from '../../../packages/core/src/types.ts';
import type { Store, State } from './store.ts';
import { notify } from './store.ts';
import type { EngineDependencies } from './engine.ts';
import { latestSecurityReports } from './reports.ts';
import { reconcileDeployments } from './deployments.ts';
import { currentDatabaseSchema, recordDatabaseSchema } from './schema-state.ts';

export type RecoveryGrantRecord = Omit<RecoveryGrant, 'approvedBy' | 'approvedAt' | 'publicationOperationId'> & { approvedBy: string | null; approvedAt: string | null; publicationOperationId: string | null };
export type ObservationState = { appId: string; releaseId: string; publicationOperationId: string; checkedAt: string; status: ReleaseObservation['status']; detail: string; consecutiveFailures: string[]; recoveryStatus: 'monitoring' | 'needs_attention' | 'pending' | 'recovered'; recoveryReason?: string; recoveryOperationId?: string };
export type ObservationAttempt = { id: string; appId: string; releaseId: string; request: ReleaseObservationRequest; startedAt: string; completedAt: string | null; result?: ReleaseObservation; error?: string };
type RecoveryRequest = Parameters<NonNullable<EngineDependencies['recoverRelease']>>[0];
export type RecoveryIntent = { id: string; appId: string; grantId: string; failedReleaseId: string; targetReleaseId: string; operationId: string; request: RecoveryRequest; status: 'pending' | 'running' | 'succeeded' | 'failed'; createdAt: string; dispatchedAt: string | null; error?: string };
export function recoveryAuthorizationHash(grant: RecoveryGrantRecord): string {
  return hashArtifact({ id: grant.id, appId: grant.appId, failedReleaseId: grant.failedReleaseId, failedArtifactHash: grant.failedArtifactHash, failedImages: grant.failedImages, targetReleaseId: grant.targetReleaseId, targetArtifactHash: grant.targetArtifactHash, targetImages: grant.targetImages, currentSchemaVersion: grant.currentSchemaVersion, expiresAt: grant.expiresAt, publicationApprovalId: grant.publicationApprovalId });
}
export function recoveryScanHash(state: State, releaseId: string): string { return hashArtifact(latestSecurityReports(state).find(report => report.subject === 'app' && report.releaseId === releaseId) ?? null); }
function fresh(date: string, now: number, maxAge: number): boolean { const time = Date.parse(date); return Number.isFinite(time) && time <= now + 60000 && now - time <= maxAge; }
function targetReasons(state: State, target: ReleaseRecord | undefined, appId: string, schemaVersion: number, now: number): string[] {
  if (!target || target.appId !== appId || !['published', 'superseded'].includes(target.status) || !target.publishedAt) return ['The exact previously published recovery release is unavailable.'];
  const reasons: string[] = [];
  if (target.artifactHash !== releaseArtifactHash(target) || !/^[a-f0-9]{40,64}$/.test(target.commit) || !target.images.length || target.images.some(image => !imageSchema.safeParse(image).success)) reasons.push('Recovery artifacts or source identity changed.');
  if (schemaVersion < target.compatibleSchemaMin || schemaVersion > target.compatibleSchemaMax) reasons.push('The previous release cannot use the current database schema.');
  if (target.migrations.some(item => item.destructive)) reasons.push('Automatic recovery cannot authorize destructive migrations or data restoration.');
  if (target.evidence.status !== 'passed' || new Set(target.evidence.checks.map(check => check.name)).size !== target.evidence.checks.length || target.evidence.checks.some(check => !check.passed) || stages.some(stage => !target.evidence.checks.some(check => check.name === stage && check.passed))) reasons.push('The recovery release lacks complete immutable verification evidence.');
  const report = latestSecurityReports(state).find(item => item.subject === 'app' && item.appId === appId && item.releaseId === target.id);
  const security = report ? { status: report.status, checkedAt: report.checkedAt, feedUpdatedAt: report.feedUpdatedAt, findings: report.findings, coverage: report.coverage.map(item => item.status === 'passed') } : { ...target.evidence, coverage: target.evidence.checks.map(item => item.passed) };
  if (security.status !== 'passed' || !security.coverage.length || security.coverage.some(passed => !passed) || !fresh(security.checkedAt, now, 86400000) || !fresh(security.feedUpdatedAt, now, 86400000) || security.findings.some(item => ['UNKNOWN', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(item.severity))) reasons.push('The exact recovery release needs fresh, complete security scanning without Medium-or-higher or unclassified findings.');
  return reasons;
}
export function draftRecoveryGrant(state: State, app: AppRecord, release: ReleaseRecord, approvalId: string, now = Date.now()): RecoveryGrantRecord {
  if (!app.activeReleaseId || release.baseReleaseId !== app.activeReleaseId) throw Object.assign(new Error('Automatic recovery requires the exact current previously published release.'), { statusCode: 409 });
  const schemaVersion = Math.max(currentDatabaseSchema(state, app), release.schemaVersion);
  const target = state.releases[app.activeReleaseId]; const reasons = targetReasons(state, target, app.id, schemaVersion, now);
  if (reasons.length) throw Object.assign(new Error(reasons.join(' ')), { statusCode: 409 });
  const grant: RecoveryGrantRecord = { id: randomUUID(), appId: app.id, failedReleaseId: release.id, failedArtifactHash: releaseArtifactHash(release), failedImages: [...release.images], targetReleaseId: target!.id, targetArtifactHash: target!.artifactHash, targetImages: [...target!.images], currentSchemaVersion: schemaVersion, approvedBy: null, approvedAt: null, expiresAt: new Date(now + 30 * 86400000).toISOString(), authorizationHash: '', publicationApprovalId: approvalId, publicationOperationId: null };
  grant.authorizationHash = recoveryAuthorizationHash(grant); return grant;
}
export function validateDraftRecovery(state: State, grant: RecoveryGrantRecord, now = Date.now()): void {
  if (grant.authorizationHash !== recoveryAuthorizationHash(grant) || !Number.isFinite(Date.parse(grant.expiresAt)) || Date.parse(grant.expiresAt) > now + 30 * 86400000 + 60000 || Date.parse(grant.expiresAt) <= now) throw Object.assign(new Error('The reviewed automatic recovery authorization changed or expired.'), { statusCode: 409 });
  const target = state.releases[grant.targetReleaseId]; const failed = state.releases[grant.failedReleaseId];
  const app = state.apps[grant.appId];
  if (!failed || !app || failed.appId !== grant.appId || releaseArtifactHash(failed) !== grant.failedArtifactHash || JSON.stringify(failed.images) !== JSON.stringify(grant.failedImages) || target?.artifactHash !== grant.targetArtifactHash || JSON.stringify(target?.images) !== JSON.stringify(grant.targetImages) || Math.max(currentDatabaseSchema(state, app), failed.schemaVersion) !== grant.currentSchemaVersion) throw Object.assign(new Error('The exact recovery artifacts or live database schema changed after review.'), { statusCode: 409 });
  const reasons = targetReasons(state, target, grant.appId, grant.currentSchemaVersion, now); if (reasons.length) throw Object.assign(new Error(reasons.join(' ')), { statusCode: 409 });
}
const observationSchema = z.object({ observationId: z.string().uuid(), appId: z.string().uuid(), releaseId: z.string().uuid(), artifactHash: z.string().regex(/^[a-f0-9]{64}$/), images: z.array(imageSchema).min(1), publicationOperationId: z.string().uuid(), checkedAt: z.string().datetime(), status: z.enum(['healthy', 'unhealthy', 'unavailable', 'superseded']), detail: z.string().max(5000), evidenceHash: z.string().regex(/^[a-f0-9]{64}$/) }).strict();
function validatedObservation(value: unknown, expected: ReleaseObservationRequest, now: number): ReleaseObservation {
  const result = observationSchema.safeParse(value);
  if (!result.success || hashArtifact(result.success ? { observationId: result.data.observationId, appId: result.data.appId, releaseId: result.data.releaseId, artifactHash: result.data.artifactHash, images: result.data.images, publicationOperationId: result.data.publicationOperationId } : null) !== hashArtifact(expected) || !fresh(result.success ? result.data.checkedAt : '', now, 5 * 60000)) throw new Error('The runtime observation is malformed, stale or identifies a different release.');
  return redact(result.data);
}
function attention(state: State, observation: ObservationState, reason: string) {
  if (observation.recoveryStatus !== 'needs_attention' || observation.recoveryReason !== reason) notify(state, 'error', 'Published application needs recovery attention', `${state.apps[observation.appId]?.name ?? observation.appId}: ${reason}`);
  observation.recoveryStatus = 'needs_attention'; observation.recoveryReason = reason;
}

/** Persist checks and the exact one-shot recovery intent before dispatch; uncertain dispatches are reconciled, never blindly repeated. */
export async function observePublishedReleases(store: Store, dependencies: EngineDependencies, options: { now?: number; intervalMs?: number } = {}): Promise<void> {
  const now = options.now ?? Date.now(), interval = options.intervalMs ?? 60000, owner = randomUUID();
  await reconcileDeployments(store, dependencies);
  await store.transaction(state => { for (const intent of Object.values(state.recoveryIntents)) { const operation = state.operations[intent.operationId]; if (operation?.status === 'succeeded') intent.status = 'succeeded'; if (operation?.status === 'failed') { intent.status = 'failed'; intent.error = operation.error; } } });
  const apps = await store.read(state => Object.values(state.apps).filter(app => app.status !== 'archived' && !!app.activeReleaseId));
  for (const candidate of apps) {
    const request = await store.transaction(state => {
      const app = state.apps[candidate.id]; const release = app?.activeReleaseId ? state.releases[app.activeReleaseId] : undefined;
      if (!app || !release || release.status !== 'published' || Object.values(state.operations).some(operation => operation.appId === app.id && operation.status === 'running')) return null;
      const last = state.observations[app.id], lease = state.observationLeases[app.id];
      if (lease && Date.parse(lease.until) > now || last?.releaseId === release.id && now - Date.parse(last.checkedAt) < interval) return null;
      const operation = Object.values(state.operations).filter(item => item.appId === app.id && item.releaseId === release.id && item.status === 'succeeded').sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))[0];
      if (!operation) { if (!last || last.detail !== 'A trusted publication operation is required for ongoing observation.') { state.observations[app.id] = { appId: app.id, releaseId: release.id, publicationOperationId: '', checkedAt: new Date(now).toISOString(), status: 'unavailable', detail: 'A trusted publication operation is required for ongoing observation.', consecutiveFailures: [], recoveryStatus: 'needs_attention' }; notify(state, 'warning', 'Application observation unavailable', `${app.name}: no exact publication receipt is recorded.`); } return null; }
      const request: ReleaseObservationRequest = { observationId: randomUUID(), appId: app.id, releaseId: release.id, artifactHash: release.artifactHash, images: [...release.images], publicationOperationId: operation.id };
      state.observationLeases[app.id] = { owner, until: new Date(now + 360000).toISOString() }; state.observationAttempts[request.observationId] = { id: request.observationId, appId: app.id, releaseId: release.id, request, startedAt: new Date(now).toISOString(), completedAt: null }; return request;
    });
    if (!request) continue;
    try {
      const raw = dependencies.observe ? await dependencies.observe(request) : { ...request, checkedAt: new Date(now).toISOString(), status: 'unavailable', detail: 'The runtime observation service is unavailable.', evidenceHash: '0'.repeat(64) };
      const result = validatedObservation(raw, request, options.now ?? Date.now());
      const dispatch = await store.transaction(state => {
        const attempt = state.observationAttempts[request.observationId]!; attempt.result = result; attempt.completedAt = result.checkedAt;
        const app = state.apps[request.appId]; if (state.observationLeases[request.appId]?.owner !== owner || app?.activeReleaseId !== request.releaseId) return null;
        const prior = state.observations[app.id]; const failures = result.status === 'unhealthy' ? [...(prior?.releaseId === result.releaseId && prior.status === 'unhealthy' ? prior.consecutiveFailures : []), result.observationId].slice(-3) : [];
        const successfulRecovery = Object.values(state.recoveryIntents).find(intent => intent.appId === app.id && intent.targetReleaseId === result.releaseId && intent.operationId === result.publicationOperationId && intent.status === 'succeeded');
        const observation: ObservationState = { appId: app.id, releaseId: result.releaseId, publicationOperationId: result.publicationOperationId, checkedAt: result.checkedAt, status: result.status, detail: result.detail, consecutiveFailures: failures, recoveryStatus: successfulRecovery ? 'recovered' : 'monitoring', ...(successfulRecovery ? { recoveryOperationId: successfulRecovery.operationId } : prior?.releaseId === result.releaseId && prior.recoveryOperationId ? { recoveryOperationId: prior.recoveryOperationId } : {}) };
        state.observations[app.id] = observation;
        if (result.status === 'unavailable' || result.status === 'superseded') { const reason = result.status === 'superseded' ? 'The runtime route differs from the recorded release; reconcile its exact publication before continuing.' : result.detail; if (prior?.recoveryStatus === 'needs_attention' && prior.recoveryReason === reason) { observation.recoveryStatus = prior.recoveryStatus; observation.recoveryReason = reason; } else attention(state, observation, reason); return null; }
        if (result.status === 'healthy') { if (prior && prior.status !== 'healthy') notify(state, 'info', 'Application health restored', `${app.name}: ${result.detail}`); return null; }
        if (failures.length < 3) return null;
        const grant = Object.values(state.recoveryGrants).find(item => item.appId === app.id && item.failedReleaseId === result.releaseId && item.publicationOperationId === result.publicationOperationId);
        let reason = '';
        if (!grant || !grant.approvedBy || !grant.approvedAt || !grant.publicationOperationId) reason = 'Three runtime health checks failed. No explicit exact-release automatic recovery grant was approved; review a rollback before taking action.';
        else {
          try { validateDraftRecovery(state, grant, now); } catch (error) { reason = error instanceof Error ? error.message : 'The recovery grant is ineligible.'; }
          const approval = state.approvals[grant.publicationApprovalId]; const publication = state.operations[grant.publicationOperationId];
          if (!reason && (!approval || !approval.consumedAt || approval.approvedBy !== grant.approvedBy || approval.approvedAt !== grant.approvedAt || approval.artifactHash !== grant.failedArtifactHash || publication?.status !== 'succeeded' || publication.releaseId !== grant.failedReleaseId || publication.baseReleaseId !== grant.targetReleaseId)) reason = 'The recovery grant does not match the exact approved publication history.';
          if (!reason && Object.values(state.recoveryIntents).some(intent => intent.grantId === grant.id)) reason = 'This one-shot recovery grant already has a dispatch or outcome. Inspect the exact recovery operation; another attempt requires approval.';
        }
        if (!reason && !dependencies.recoverRelease) reason = 'The automatic recovery runtime is unavailable; no rollback was attempted.';
        const proofs = failures.map(id => state.observationAttempts[id]?.result);
        if (!reason && (proofs.some(proof => !proof || proof.status !== 'unhealthy' || !fresh(proof.checkedAt, now, 5 * 60000)) || proofs.some((proof, index) => index > 0 && Date.parse(proof!.checkedAt) - Date.parse(proofs[index - 1]!.checkedAt) < 10000))) reason = 'Recovery needs three independently recorded health failures at least ten seconds apart and within five minutes.';
        if (reason) { if (prior?.recoveryStatus === 'needs_attention' && prior.recoveryReason === reason) { observation.recoveryStatus = prior.recoveryStatus; observation.recoveryReason = reason; } else attention(state, observation, reason); return null; }
        if (Object.values(state.operations).some(operation => operation.appId === app.id && operation.status === 'running')) return null;
        const activeGrant = grant as RecoveryGrant; const operationId = randomUUID(); const input: RecoveryRequest = { operationId, app: structuredClone(app), release: structuredClone(state.releases[activeGrant.targetReleaseId]!), grant: structuredClone(activeGrant), observationIds: [...failures], evidenceHashes: proofs.map(proof => proof!.evidenceHash) };
        const intent: RecoveryIntent = { id: randomUUID(), appId: app.id, grantId: activeGrant.id, failedReleaseId: result.releaseId, targetReleaseId: activeGrant.targetReleaseId, operationId, request: input, status: 'pending', createdAt: new Date(now).toISOString(), dispatchedAt: null };
        state.recoveryIntents[intent.id] = intent; state.operations[operationId] = { id: operationId, appId: app.id, releaseId: activeGrant.targetReleaseId, baseReleaseId: app.activeReleaseId, action: 'rollback', status: 'running', approvalId: activeGrant.id, artifactHash: activeGrant.targetArtifactHash, createdAt: new Date(now).toISOString() }; observation.recoveryStatus = 'pending'; observation.recoveryOperationId = operationId;
        return intent;
      });
      if (dispatch) {
        await store.transaction(state => { const intent = state.recoveryIntents[dispatch.id]!; intent.status = 'running'; intent.dispatchedAt = new Date().toISOString(); });
        try {
          const response = await dependencies.recoverRelease!(dispatch.request);
          await store.transaction(state => {
            const intent = state.recoveryIntents[dispatch.id]!, app = state.apps[intent.appId]!, operation = state.operations[intent.operationId]!, target = state.releases[intent.targetReleaseId]!;
            if (app.activeReleaseId !== intent.failedReleaseId || !response.healthy || !response.url || new URL(response.url).protocol !== 'https:' || !app.url || new URL(response.url).origin !== new URL(app.url).origin) throw new Error('Recovery outcome does not confirm the expected route and healthy release; reconcile the runtime receipt.');
            recordDatabaseSchema(state, app, target, response.schemaVersion, store.mode === 'mysql');
            state.releases[intent.failedReleaseId]!.status = 'superseded'; target.status = 'published'; app.activeReleaseId = target.id; app.url = response.url; app.status = 'published'; app.updatedAt = new Date().toISOString(); operation.status = 'succeeded'; intent.status = 'succeeded'; state.observations[app.id]!.recoveryStatus = 'recovered'; notify(state, 'warning', 'Approved automatic recovery completed', `${app.name}: recovered to exact version ${target.version} after three failed health checks. Current business data was preserved.`);
          });
        } catch (error) {
          const message = String(redact(error instanceof Error ? error.message : 'Recovery outcome is uncertain.'));
          await store.transaction(state => { const intent = state.recoveryIntents[dispatch.id]!, operation = state.operations[intent.operationId]!; intent.error = message; operation.error = message; if ((error as { confirmedRejected?: boolean })?.confirmedRejected === true) { operation.status = 'failed'; intent.status = 'failed'; } attention(state, state.observations[intent.appId]!, `Recovery operation ${intent.operationId} needs receipt reconciliation: ${message}`); });
          await reconcileDeployments(store, dependencies, dispatch.operationId);
        }
      }
    } catch (error) {
      await store.transaction(state => {
        const attempt = state.observationAttempts[request.observationId]; if (attempt) { attempt.completedAt = new Date(now).toISOString(); attempt.error = String(redact(error instanceof Error ? error.message : 'Observation unavailable.')); }
        const app = state.apps[request.appId]; if (state.observationLeases[request.appId]?.owner !== owner || app?.activeReleaseId !== request.releaseId) return;
        const prior = state.observations[request.appId]; const observation: ObservationState = { appId: request.appId, releaseId: request.releaseId, publicationOperationId: request.publicationOperationId, checkedAt: new Date(now).toISOString(), status: 'unavailable', detail: attempt?.error ?? 'Observation unavailable.', consecutiveFailures: [], recoveryStatus: 'monitoring' }; state.observations[request.appId] = observation;
        if (prior?.recoveryStatus === 'needs_attention' && prior.recoveryReason === observation.detail) { observation.recoveryStatus = prior.recoveryStatus; observation.recoveryReason = prior.recoveryReason; } else attention(state, observation, observation.detail);
      });
    } finally { await store.transaction(state => { if (state.observationLeases[request.appId]?.owner === owner) delete state.observationLeases[request.appId]; }); }
  }
}
