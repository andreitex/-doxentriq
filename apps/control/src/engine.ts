import { randomUUID } from 'node:crypto';
import { mkdir, writeFile, lstat, realpath, readdir, readFile } from 'node:fs/promises';
import { resolve, dirname, relative, isAbsolute, sep } from 'node:path';
import { releaseArtifactHash, redact, hashArtifact } from '../../../packages/core/src/index.ts';
import type { AppRecord, JobRecord, ReleaseRecord, Evidence, RecoveryGrant, ReleaseObservationRequest, ReleaseObservation } from '../../../packages/core/src/types.ts';
import type { Store, State } from './store.ts';
import { event, notify, enqueue } from './store.ts';
import { BudgetManager, BudgetLimitError, modelBillingReviewRequired, modelBillingHoldMessage, modelBillingHoldHint } from './budget.ts';
import { latestSecurityReports, preserveSecurityFindings } from './reports.ts';
import { validatedVerification } from './verification.ts';
import type { AccessDependencies } from './access.ts';
import type { ConnectorDependencies } from './connectors.ts';
import type { AdapterDependencies } from './filesystem-connectors.ts';
import type { RevocationDependencies } from './connection-revocation.ts';
import type { GenerationConnectionInventory } from '../../../packages/core/src/connection-context.ts';
import { validatedIntegrationResearch, type IntegrationResearchContext } from '../../../packages/core/src/research-context.ts';
import { IntegrationResearchUnavailable, type ResearchInput } from './integration-research.ts';
import { frozenGenerationContext, ModelCheckpointError } from './model-checkpoints.ts';
import type { GenerationInputContext } from '../../../packages/core/src/models.ts';
import { sourceFilesHash, pipelineDefinitionHash } from '../../../packages/core/src/source-hash.ts';
export type GenerationResult = { specification: Record<string, unknown>; files: { path: string; content: string }[]; pipeline: unknown; summary: string; costUsd?: number };
export type VerificationResult = { evidence: Evidence; images: string[]; commit: string; previewUrl: string | null; schemaVersion?: number; compatibleSchemaMin?: number; compatibleSchemaMax?: number; migrations?: ReleaseRecord['migrations']; migrationSnapshot?: ReleaseRecord['migrationSnapshot']; sourceBindingVersion?: 1; inputSourceHash?: string; pipelineHash?: string };
export type EngineDependencies = AccessDependencies & ConnectorDependencies & AdapterDependencies & RevocationDependencies & {
  planAndGenerate?: (input: { app: AppRecord; job: JobRecord; context: GenerationInputContext; budgetRemainingUsd: number }, hooks: ReturnType<BudgetManager['hooks']>) => Promise<GenerationResult>;
  generationConnections?: (appId: string) => Promise<GenerationConnectionInventory>;
  researchIntegrations?: (input: ResearchInput) => Promise<IntegrationResearchContext>;
  verify?: (input: { app: AppRecord; job: JobRecord; attemptId: string; workspacePath: string; pipeline: unknown; filesHash: string }) => Promise<VerificationResult>;
  deploy?: (input: { app: AppRecord; release: ReleaseRecord; approval: import('../../../packages/core/src/types.ts').ApprovalRecord; principal: import('../../../packages/core/src/types.ts').Principal; operationId: string; action: 'publish' | 'rollback' | 'emergency_rollback'; approvedFindings?: import('../../../packages/core/src/types.ts').Finding[]; recoveryGrant?: RecoveryGrant }) => Promise<{ url: string; healthy: boolean; schemaVersion?: number }>;
  operation?: (input: { operationId: string }) => Promise<{ status: 'running' | 'succeeded' | 'failed' | 'unknown'; url?: string; healthy?: boolean; schemaVersion?: number; appId?: string; releaseId?: string }>;
  cancelOperation?: (input: { operationId: string; appId: string; releaseId: string; approvalId: string; artifactHash: string }) => Promise<{ status: 'running' | 'failed' | 'unknown'; appId?: string; releaseId?: string }>;
  telemetry?: () => Promise<{ services?: unknown[]; broker?: { available: boolean; detail: string } }>;
  previousSource?: (input: { appId: string; commit: string }) => Promise<{ files: GenerationResult['files'] }>;
  observe?: (input: ReleaseObservationRequest) => Promise<ReleaseObservation>;
  recoverRelease?: (input: { operationId: string; app: AppRecord; release: ReleaseRecord; grant: RecoveryGrant; observationIds: string[]; evidenceHashes: string[] }) => Promise<{ url: string; healthy: boolean; schemaVersion?: number }>;
  publishedCatalog?: () => Promise<{ apps: { appId: string; releaseId: string; artifactHash: string; images: string[]; auth: 'public' | 'local' | 'sso' }[] }>;
  publicCatalog?: () => Promise<{ apps: { appId: string; releaseId: string; artifactHash: string; images: string[]; auth: 'public' }[] }>;
};
const terminal = new Set<JobRecord['stage']>(['completed', 'failed', 'cancelled', 'needs_attention', 'awaiting_approval', 'clarification', 'deployment', 'observation']);
type WorkerAttempt = Pick<JobRecord, 'id' | 'appId' | 'runtimeFence' | 'baseReleaseId'>;
function ownsAttemptLease(state: State, attempt: WorkerAttempt, owner: string): boolean {
  const job = state.jobs[attempt.id];
  return !!job && job.appId === attempt.appId && job.runtimeFence === attempt.runtimeFence && state.leases[attempt.id]?.owner === owner;
}
function ownsLiveAttempt(state: State, attempt: WorkerAttempt, owner: string): boolean {
  const job = state.jobs[attempt.id], lease = state.leases[attempt.id], app = state.apps[attempt.appId];
  return ownsAttemptLease(state, attempt, owner) && job?.stage !== 'cancelled' && !!lease && Date.parse(lease.until) > Date.now()
    && (!app || app.status !== 'archived' && app.runtimeFence === attempt.runtimeFence);
}
function ownsCurrentBaselineAttempt(state: State, attempt: WorkerAttempt, owner: string): boolean {
  return ownsLiveAttempt(state, attempt, owner) && state.jobs[attempt.id]?.baseReleaseId === attempt.baseReleaseId
    && (!state.apps[attempt.appId] || state.apps[attempt.appId]!.activeReleaseId === attempt.baseReleaseId);
}
function holdModelBilling(state: State, job: JobRecord): void {
  const alreadyHeld = job.stage === 'needs_attention' && job.result?.modelBillingHold === true;
  job.result = { ...(job.result ?? {}), error: modelBillingHoldMessage, modelBillingHold: true, budgetBlocked: false, attentionKind: 'runtime_unavailable', recoveryHint: modelBillingHoldHint };
  if (!alreadyHeld) event(state, job, 'needs_attention', modelBillingHoldMessage, 'error');
  const app = state.apps[job.appId];
  if (app?.status === 'building' && app.runtimeFence === job.runtimeFence) app.status = app.activeReleaseId ? 'published' : 'draft';
}
function safeMessage(error: unknown): string { return String(redact(error instanceof Error ? error.message : String(error))).slice(0, 2000); }
class VerificationFailure extends Error { constructor(readonly evidence: Evidence) { super(`Verification did not pass: ${evidence.checks.filter(check => !check.passed).map(check => `${check.name}: ${check.detail}`).join('; ') || evidence.status}`); } }
function repairStage(error: unknown): 'review' | 'verification' | null {
  if (error instanceof VerificationFailure) {
    const fresh = [error.evidence.checkedAt, error.evidence.feedUpdatedAt].every(date => Number.isFinite(Date.parse(date)) && Date.parse(date) <= Date.now() + 60000 && Date.now() - Date.parse(date) <= 86400000);
    const codeFailure = error.evidence.checks.some(check => ['dependencies', 'build', 'application_tests', 'acceptance'].includes(check.name) && !check.passed);
    return fresh && error.evidence.status === 'failed' && codeFailure && !error.evidence.checks.some(check => check.name === 'security' && !check.passed) ? 'verification' : null;
  }
  if (error && typeof error === 'object' && (error as { partialGeneration?: GenerationResult }).partialGeneration && safeMessage(error).startsWith('Independent code review needs changes:')) return 'review';
  return null;
}
function attention(error: unknown): { attentionKind: 'setup' | 'runtime_unavailable' | 'budget' | 'verification'; recoveryHint: string } {
  const message = safeMessage(error);
  if (error instanceof IntegrationResearchUnavailable) return { attentionKind: error.kind, recoveryHint: 'Ask the company operator to correct the protected official-source catalog or source availability, then retry. SDKs remain unqualified until independent dependency, security and protocol checks pass. Use protected forms for connection credentials.' };
  if (error instanceof ModelCheckpointError) return { attentionKind: 'runtime_unavailable', recoveryHint: 'Ask the company operator to reconcile the preserved paid model output, current request and connection scope. A restart or budget increase cannot repair a changed checkpoint; no replacement provider call was authorized.' };
  if (error instanceof BudgetLimitError) return { attentionKind: 'budget', recoveryHint: 'Review the spending and held reservations. Additional spending requires an exact budget approval.' };
  if (/qualified model|model pricing catalog|No suitable model|model request failed \(HTTP (?:401|403)\)|API credentials|API key|protected connection setup|missing.*(?:configuration|catalog)/i.test(message)) return { attentionKind: 'setup', recoveryHint: 'Ask the company operator to correct protected model or connection setup and qualification, then retry. Never enter passwords, tokens or API keys into chat.' };
  if (/unavailable|connection ended|without a confirmed billing|reservation remains held|ECONN|ETIMEDOUT|TLS|certificate|worker.*interruption|missing or stale|feed.*freshness/i.test(message)) return { attentionKind: 'runtime_unavailable', recoveryHint: 'Ask the company operator to inspect the unavailable service or held billing outcome. Retry only after it is corrected; enter credentials through protected setup.' };
  return { attentionKind: 'verification', recoveryHint: 'Generated work is preserved. Review the actual diagnostics with the company operator, correct the issue, and retry. Publication remains blocked.' };
}

export async function writeScopedFiles(root: string, files: GenerationResult['files']): Promise<string> {
  if (files.length === 0 || files.length > 500) throw new Error('Generated files must contain between 1 and 500 entries.');
  const hash = sourceFilesHash(files);
  await mkdir(root, { recursive: true, mode: 0o700 }); const canonicalRoot = await realpath(root); const seen = new Set<string>(); let total = 0;
  for (const file of files) {
    if (!file.path || isAbsolute(file.path) || file.path.includes('\\') || file.path.includes(':') || /[\x00-\x1f\x7f]/.test(file.path) || file.path.split('/').some(part => part === '..' || part === '.' || !part) || /(^|\/)\.(git|codex|agents|npmrc|env)(\/|$|\.)/i.test(file.path)) throw new Error('Generated path escapes its application workspace or targets protected metadata.');
    const target = resolve(canonicalRoot, file.path); const rel = relative(canonicalRoot, target);
    if (!rel || rel.startsWith(`..${sep}`) || isAbsolute(rel) || seen.has(rel.toLowerCase())) throw new Error('Invalid or duplicate generated path.');
    seen.add(rel.toLowerCase()); total += Buffer.byteLength(file.content); if (total > 20 * 1024 * 1024) throw new Error('Generated source exceeds the 20 MiB limit.');
    const segments = relative(canonicalRoot, dirname(target)).split(sep).filter(Boolean); let cursor = canonicalRoot;
    for (const segment of segments) {
      cursor = resolve(cursor, segment);
      try { const stat = await lstat(cursor); if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Generated path crosses a symlink or non-directory.'); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; await mkdir(cursor, { mode: 0o700 }); }
    }
    try { if ((await lstat(target)).isSymbolicLink()) throw new Error('Generated path targets a symlink.'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    await writeFile(target, file.content, { mode: 0o600, flag: 'wx' });
  }
  return hash;
}
async function readPreviousFiles(root: string): Promise<GenerationResult['files']> {
  const files: GenerationResult['files'] = []; let bytes = 0;
  const walk = async (directory: string) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (/^(node_modules|dist|artifacts|\.venv|venv|__pycache__|\.pytest_cache|\.cache|\.git|\.env.*|\.npmrc|autosoft\.pipeline\.json)$/.test(entry.name)) continue;
      if (entry.isSymbolicLink()) throw new Error('Previous source contains a symlink.');
      const file = resolve(directory, entry.name);
      if (entry.isDirectory()) await walk(file);
      else if (entry.isFile()) {
        const info = await lstat(file); bytes += info.size;
        if (bytes > 10 * 1024 * 1024 || files.length >= 500) throw new Error('Previous source exceeds the model context snapshot limit.');
        files.push({ path: relative(root, file).split(sep).join('/'), content: await readFile(file, 'utf8') });
      }
    }
  };
  await walk(root); return files;
}

export class WorkflowEngine {
  readonly workerId = randomUUID();
  constructor(private store: Store, private dependencies: EngineDependencies, private budgets: BudgetManager, private workspaceDir: string, private checkpointKey?: Buffer) {}
  private async stage(attempt: WorkerAttempt, stage: JobRecord['stage'], message: string, detail?: Record<string, unknown>) {
    await this.store.transaction(state => { const job = state.jobs[attempt.id]; if (!job || job.stage === 'cancelled') throw new Error('Job cancelled.'); if (!ownsCurrentBaselineAttempt(state, attempt, this.workerId)) throw new Error('Worker lease or runtime fence lost.'); if (stage === 'verification') { const app = state.apps[job.appId]; if (app) { app.previewReleaseId = null; app.previewUrl = null; } } event(state, job, stage, message, 'status', detail); });
  }
  async run(jobId: string): Promise<void> {
    const acquired = await this.store.transaction(state => {
      const job = state.jobs[jobId]; if (!job || terminal.has(job.stage)) return false;
      const lease = state.leases[jobId]; if (lease && new Date(lease.until).getTime() > Date.now()) return false;
      if (modelBillingReviewRequired(state, jobId)) { delete state.leases[jobId]; holdModelBilling(state, job); return false; }
      if (Object.entries(state.leases).some(([id, value]) => id !== jobId && state.jobs[id]?.appId === job.appId && new Date(value.until).getTime() > Date.now())) return false;
      state.leases[jobId] = { owner: this.workerId, until: new Date(Date.now() + 90000).toISOString() };
      const app = state.apps[job.appId]; if (app) {
        const fence = app.runtimeFence ?? 0;
        if (!Number.isSafeInteger(fence) || fence < 0 || fence >= Number.MAX_SAFE_INTEGER) throw new Error('The persistent application worker fence is invalid.');
        app.runtimeFence = fence + 1; job.runtimeFence = app.runtimeFence;
        app.status = 'building'; app.updatedAt = new Date().toISOString();
      } return { id: job.id, appId: job.appId, runtimeFence: job.runtimeFence, baseReleaseId: job.baseReleaseId };
    });
    if (!acquired) return;
    let sourceBeforeGeneration: GenerationResult['files'] | undefined;
    const heartbeat = setInterval(() => void this.store.transaction(state => { if (ownsLiveAttempt(state, acquired, this.workerId)) state.leases[jobId]!.until = new Date(Date.now() + 90000).toISOString(); }).catch(() => undefined), 20000); heartbeat.unref();
    try {
      const input = await this.store.read(state => ({ job: state.jobs[jobId]!, app: state.apps[state.jobs[jobId]!.appId]! }));
      if (!input.app) throw new Error('Application no longer exists.');
      if (input.app.activeReleaseId !== input.job.baseReleaseId) throw new Error('The application changed while this request was paused. Start a new request against the current release; preserved work remains available.');
      if (!this.dependencies.planAndGenerate) throw new Error('No qualified model provider is configured. Add a company-tested model catalog and model API credentials.');
      await this.stage(acquired, 'specification', 'Creating requirements, acceptance criteria and an application-specific pipeline.');
      let context = this.checkpointKey ? await frozenGenerationContext(this.store, this.checkpointKey, input, this.workerId) : undefined;
      if (!context) {
        const previous = await this.store.read(state => Object.values(state.jobs).filter(job => job.appId === input.app.id && job.id !== jobId && job.specification && (input.app.activeReleaseId ? job.result?.releaseId === input.app.activeReleaseId : true)).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0]);
        let previousFiles: GenerationResult['files'] | undefined;
        const priorPath = input.job.result?.workspacePath ?? previous?.result?.workspacePath;
        if (!input.job.result?.workspacePath && input.app.activeReleaseId && this.dependencies.previousSource) {
          const active = await this.store.read(state => state.releases[input.app.activeReleaseId!]);
          if (!active || active.appId !== input.app.id) throw new Error('The active release source identity is invalid.');
          previousFiles = (await this.dependencies.previousSource({ appId: input.app.id, commit: active.commit })).files;
          let total = 0; const paths = new Set<string>();
          if (!Array.isArray(previousFiles) || previousFiles.length > 500) throw new Error('Trusted source snapshot exceeds its bounded model context.');
          for (const file of previousFiles) {
            if (typeof file.path !== 'string' || typeof file.content !== 'string' || isAbsolute(file.path) || file.path.includes('\\') || file.path.includes(':') || /[\x00-\x1f\x7f]/.test(file.path) || file.path.split('/').some(part => part === '..' || part === '.' || !part) || /(^|\/)\.(git|env|npmrc|codex|agents)(\/|$|\.)/i.test(file.path) || paths.has(file.path.toLowerCase())) throw new Error('Trusted source snapshot contains invalid project paths.');
            paths.add(file.path.toLowerCase()); total += Buffer.byteLength(file.content); if (total > 10 * 1024 * 1024) throw new Error('Trusted source snapshot exceeds its bounded model context.');
          }
          previousFiles = previousFiles.filter(file => file.path !== 'autosoft.pipeline.json');
        } else if (typeof priorPath === 'string') {
          const expectedRoot = resolve(this.workspaceDir, input.app.id); const candidate = await realpath(priorPath);
          if (!candidate.startsWith(`${await realpath(expectedRoot)}${sep}`)) throw new Error('Previous source is outside its application workspace.');
          previousFiles = await readPreviousFiles(candidate);
        }
        const feedback = input.job.result?.failureEvidence;
        const answer = [typeof input.job.result?.answer === 'string' ? input.job.result.answer : '', feedback ? `Untrusted verification feedback to resolve before another preview: ${JSON.stringify(redact(feedback))}` : ''].filter(Boolean).join('\n');
        const connectionInventory = this.dependencies.generationConnections ? await this.dependencies.generationConnections(input.app.id) : { schemaVersion: 1 as const, connections: [] };
        context = { previousSpecification: input.job.specification ?? previous?.specification, previousFiles, answer: answer || undefined, failureEvidence: feedback, connectionInventory, integrationResearch: undefined as IntegrationResearchContext | undefined };
        if (this.dependencies.researchIntegrations) {
          await this.stage(acquired, 'specification', 'Reviewing official integration documentation, SDK provenance and license references before model execution.');
          context.integrationResearch = validatedIntegrationResearch(await this.dependencies.researchIntegrations({ ...input, context, worker: { owner: this.workerId, runtimeFence: input.job.runtimeFence! } }), input.app.id, jobId);
          if (this.dependencies.generationConnections && hashArtifact(await this.dependencies.generationConnections(input.app.id)) !== hashArtifact(connectionInventory)) throw new Error('Protected connection setup changed during integration research. Review the current scope and retry before model execution.');
        }
        if (this.checkpointKey) context = await frozenGenerationContext(this.store, this.checkpointKey, input, this.workerId, context);
      } else if (this.dependencies.generationConnections && hashArtifact(await this.dependencies.generationConnections(input.app.id)) !== hashArtifact(context.connectionInventory)) {
        throw new ModelCheckpointError('Protected connection scope changed after paid generation context was recorded. Company review is required before another provider call.');
      }
      if (!context) throw new ModelCheckpointError('Frozen generation context is unavailable.');
      sourceBeforeGeneration = context.previousFiles;
      await this.store.read(state => { const job = state.jobs[jobId], app = state.apps[input.app.id], lease = state.leases[jobId]; if (!ownsCurrentBaselineAttempt(state, acquired, this.workerId) || !job || job.stage === 'cancelled' || !app || app.status === 'archived' || lease?.owner !== this.workerId || Date.parse(lease.until) <= Date.now() || job.runtimeFence !== input.job.runtimeFence || app.runtimeFence !== input.job.runtimeFence || app.activeReleaseId !== input.job.baseReleaseId) throw new Error('Worker lease, application baseline or runtime fence lost before generation.'); });
      const generated = await this.dependencies.planAndGenerate({ ...input, context, budgetRemainingUsd: input.job.budgetUsd - input.job.costUsd }, this.budgets.hooks(jobId, { owner: this.workerId, runtimeFence: input.job.runtimeFence! }));
      const questions = generated.specification.questions;
      if (!generated.files.length && Array.isArray(questions) && questions.length) {
        await this.store.transaction(state => {
          const job = state.jobs[jobId]!; if (!ownsCurrentBaselineAttempt(state, acquired, this.workerId)) throw new Error('Worker lease, application baseline or runtime fence lost.');
          job.specification = generated.specification; job.result = { questions, attentionKind: 'clarification' }; event(state, job, 'clarification', `Please clarify these business requirements: ${questions.map(String).join('; ')}`, 'message', { questions });
        }); return;
      }
      await this.store.transaction(state => { const job = state.jobs[jobId]!; if (!ownsCurrentBaselineAttempt(state, acquired, this.workerId)) throw new Error('Job cancelled or worker lease lost.'); job.specification = generated.specification; event(state, job, 'implementation', 'Writing generated files into an isolated application workspace.'); });
      // A new attempt directory prevents stale files and a resumed job from changing reviewed artifacts.
      const attemptId = randomUUID(); const workspacePath = resolve(this.workspaceDir, input.app.id, jobId, attemptId);
      const pipelineHash = pipelineDefinitionHash(generated.pipeline);
      const filesHash = await writeScopedFiles(workspacePath, [...generated.files, { path: 'autosoft.pipeline.json', content: JSON.stringify(generated.pipeline, null, 2) }]);
      await this.store.transaction(state => { if (!ownsCurrentBaselineAttempt(state, acquired, this.workerId)) throw new Error('Worker lease or runtime fence lost.'); const job = state.jobs[jobId]!; job.result = { ...(job.result ?? {}), workspacePath, filesHash }; });
      await this.stage(acquired, 'verification', 'Running the mandatory build, test, security, packaging and migration stages.', { workspacePath, filesHash });
      if (!this.dependencies.verify) throw new Error('The sandbox pipeline broker is unavailable. Generated source is preserved; no build, security scan, preview or deployment has been claimed.');
      const base=input.job.baseReleaseId?await this.store.read(state=>state.releases[input.job.baseReleaseId!]):undefined;
      if (input.job.baseReleaseId&&(!base||base.appId!==input.app.id||base.artifactHash!==releaseArtifactHash(base)||base.images.length!==1)) throw new Error('Exact previous release identity is unavailable before migration capture.');
      const verified = validatedVerification(await this.dependencies.verify({ ...input, attemptId, workspacePath, pipeline: generated.pipeline, filesHash }), input.app.id,{jobId,attemptId,fence:input.job.runtimeFence!,baseReleaseId:input.job.baseReleaseId,baseArtifactHash:base?.artifactHash??'',baseImage:base?.images[0]??'',filesHash,pipelineHash});
      if (verified.evidence.status !== 'passed' || verified.evidence.checks.some(check => !check.passed)) throw new VerificationFailure(verified.evidence);
      await this.store.transaction(state => {
        const job = state.jobs[jobId]!, lease=state.leases[jobId], currentApp=state.apps[input.app.id]; if (!ownsCurrentBaselineAttempt(state, acquired, this.workerId) || job.stage === 'cancelled' || lease?.owner !== this.workerId || Date.parse(lease.until)<=Date.now() || job.runtimeFence!==input.job.runtimeFence || !currentApp || currentApp.runtimeFence!==input.job.runtimeFence || currentApp.activeReleaseId!==input.job.baseReleaseId) throw new Error('Worker lease, application baseline or runtime fence lost before accepting migration evidence.');
        const app = state.apps[job.appId]!; const id = randomUUID(); const previous = app.activeReleaseId ? state.releases[app.activeReleaseId] : undefined;
        const liveSchema = app.databaseSchemaVersion ?? previous?.schemaVersion ?? 1;
        const release: ReleaseRecord = { id, appId: app.id, version: `0.${Object.values(state.releases).filter(item => item.appId === app.id).length + 1}.0`, summary: generated.summary, artifactHash: '', commit: verified.commit, images: verified.images, schemaVersion: verified.schemaVersion ?? liveSchema, compatibleSchemaMin: verified.compatibleSchemaMin ?? liveSchema, compatibleSchemaMax: verified.compatibleSchemaMax ?? verified.schemaVersion ?? liveSchema, baseReleaseId: job.baseReleaseId, status: 'ready', evidence: verified.evidence, migrations: verified.migrations ?? [], createdAt: new Date().toISOString(), publishedAt: null };
        release.migrationSnapshot=verified.migrationSnapshot;
        release.artifactHash = releaseArtifactHash(release); state.releases[id] = release; app.status = 'preview'; app.previewUrl = verified.previewUrl; app.previewReleaseId = id;
        job.result = { releaseId: id, workspacePath, filesHash, summary: generated.summary }; event(state, job, 'awaiting_approval', 'Preview and verification evidence are ready. Review this release before publishing.', 'approval', { releaseId: id });
        notify(state, 'info', 'Release ready for review', `${app.name}: ${release.summary}`);
      });
    } catch (error) {
      const partial = error && typeof error === 'object' ? (error as { partialGeneration?: GenerationResult }).partialGeneration : undefined;
      if (partial?.files?.length && await this.store.read(state => ownsCurrentBaselineAttempt(state, acquired, this.workerId))) {
        try {
          const path = resolve(this.workspaceDir, (await this.store.read(state => state.jobs[jobId]!.appId)), jobId, randomUUID());
          const preserved = new Map((sourceBeforeGeneration ?? []).filter(file => !['app.manifest.json', 'pipeline.json', 'autosoft.pipeline.json', 'migrations.json'].includes(file.path)).map(file => [file.path, file]));
          for (const file of partial.files) preserved.set(file.path, file);
          const filesHash = await writeScopedFiles(path, [...preserved.values()]);
          await this.store.transaction(state => { const job = state.jobs[jobId]; if (job && ownsCurrentBaselineAttempt(state, acquired, this.workerId)) { job.specification = partial.specification; job.result = { ...(job.result ?? {}), workspacePath: path, filesHash }; } });
        } catch { /* Invalid generated paths are never preserved outside the sandbox boundary. */ }
      }
      await this.store.transaction(state => {
        const job = state.jobs[jobId]; if (!job || !ownsLiveAttempt(state, acquired, this.workerId)) return;
        if (modelBillingReviewRequired(state, jobId)) { holdModelBilling(state, job); return; }
        const stage = ownsCurrentBaselineAttempt(state, acquired, this.workerId) ? repairStage(error) : null; const counters = state.repairAttempts[jobId] ?? { review: 0, verification: 0 };
        if (stage && counters[stage] < 3) {
          counters[stage]++; state.repairAttempts[jobId] = counters; job.attempts++;
          job.result = { ...(job.result ?? {}), error: safeMessage(error), failureEvidence: error instanceof VerificationFailure ? redact(error.evidence) : { review: safeMessage(error) } };
          event(state, job, 'queued', `Verification found a repairable issue. Automatic ${stage} repair ${counters[stage]} of 3 will use the preserved source and actual diagnostics.`, 'error'); enqueue(state, job.id); return;
        }
        job.result = { ...(job.result ?? {}), error: safeMessage(error), budgetBlocked: error instanceof BudgetLimitError, ...attention(error) }; event(state, job, 'needs_attention', safeMessage(error), 'error');
        const app = state.apps[job.appId]; if (app) app.status = app.activeReleaseId ? 'published' : 'draft';
        notify(state, 'warning', 'Application development needs attention', `${app?.name ?? job.appId}: ${safeMessage(error)}`);
      });
    } finally {
      clearInterval(heartbeat); await this.store.transaction(state => { if (ownsAttemptLease(state, acquired, this.workerId)) delete state.leases[jobId]; });
    }
  }
  async recover(): Promise<void> {
    await this.store.transaction(state => {
      for (const [id, lease] of Object.entries(state.leases)) if (new Date(lease.until).getTime() <= Date.now()) delete state.leases[id];
      for (const call of Object.values(state.modelCalls)) if (call.status === 'running' && !state.leases[call.jobId]) { call.status = 'uncertain'; call.completedAt = new Date().toISOString(); call.error = 'The worker ended before completion metadata was recorded. Provider billing and held reservations require reconciliation.'; }
      for (const job of Object.values(state.jobs)) if (!state.leases[job.id]) {
        if (!['completed', 'failed', 'cancelled', 'awaiting_approval', 'deployment', 'observation'].includes(job.stage) && modelBillingReviewRequired(state, job.id)) holdModelBilling(state, job);
        else if (!terminal.has(job.stage)) enqueue(state, job.id);
      }
      const cutoff = Date.now() - 7 * 86400000; state.events = state.events.filter(item => new Date(item.createdAt).getTime() >= cutoff);
      for (const [id, session] of Object.entries(state.sessions)) if (new Date(session.expiresAt).getTime() <= Date.now()) delete state.sessions[id];
      for (const [id, stateValue] of Object.entries(state.authStates)) if (new Date(stateValue.expiresAt).getTime() <= Date.now()) delete state.authStates[id];
      for (const collection of [state.previewTickets, state.previewSessions]) for (const [id, value] of Object.entries(collection)) if (Date.parse(value.expiresAt) <= Date.now() || !state.sessions[value.sessionId]) delete collection[id];
      for (const [id, entry] of Object.entries(state.outbox)) if (entry.publishedAt && new Date(entry.publishedAt).getTime() < cutoff) delete state.outbox[id];
      preserveSecurityFindings(state);
      const retainedReports = new Set(latestSecurityReports(state).map(report => report.id));
      for (const [id, report] of Object.entries(state.securityReports)) if (!retainedReports.has(id) && Date.parse(report.receivedAt) < cutoff) delete state.securityReports[id];
      for (const [id, lease] of Object.entries(state.observationLeases)) if (Date.parse(lease.until) <= Date.now()) delete state.observationLeases[id];
      const retainedObservations = new Set([...Object.values(state.observations).flatMap(item => item.consecutiveFailures), ...Object.values(state.recoveryIntents).flatMap(item => item.request.observationIds)]);
      for (const [id, attempt] of Object.entries(state.observationAttempts)) if (!retainedObservations.has(id) && Date.parse(attempt.startedAt) < cutoff) delete state.observationAttempts[id];
    });
  }
}
