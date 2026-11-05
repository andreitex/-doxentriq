import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import { generationBusinessApp, type Completion, type CompletionRequest, type GenerationInputContext, type ModelCallSlot } from '../../../packages/core/src/models.ts';
import { validatedGenerationConnections } from '../../../packages/core/src/connection-context.ts';
import { validatedIntegrationResearch } from '../../../packages/core/src/research-context.ts';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';
import type { ModelCallRecord } from './model-records.ts';
import type { State, Store } from './store.ts';
import { validatedPreviousSourceSelection, type PreviousSourceSelection } from '../../../packages/core/src/source-selection.ts';

export class ModelCheckpointError extends Error { readonly statusCode = 409; }
const unavailable = () => new ModelCheckpointError('The paid model checkpoint or frozen development context changed or is unavailable. Company reconciliation is required before another provider call.');
const outputLimit = 8 * 1024 * 1024, contextLimit = 12 * 1024 * 1024;
export type ModelCheckpointRecord = { version: 1; appId: string; jobId: string; attempt: number; slot: ModelCallSlot; callId: string; baseReleaseId: string | null; requestHash: string; encrypted: string };
export type GenerationContextRecord = { version: 1; appId: string; jobId: string; attempt: number; baseReleaseId: string | null; intentHash: string; businessHash: string; encrypted: string; selectionEncrypted?: string };
export const attemptKey = (jobId: string, attempt: number) => hashArtifact({ jobId, attempt });
export const outputKey = (jobId: string, attempt: number, slot: ModelCallSlot) => hashArtifact({ jobId, attempt, slot });

export function encryptPrivate(key: Buffer, binding: unknown, value: unknown, maximum: number): string {
  if (key.length !== 32) throw unavailable();
  const text = JSON.stringify(value); if (Buffer.byteLength(text) > maximum) throw unavailable();
  const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(Buffer.from(hashArtifact(binding)));
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return [nonce, cipher.getAuthTag(), encrypted].map(part => part.toString('base64')).join('.');
}
function decryptPrivate(key: Buffer, binding: unknown, encrypted: string, maximum: number): unknown {
  try {
    if (key.length !== 32 || typeof encrypted !== 'string' || encrypted.length > Math.ceil(maximum / 3) * 4 + 64) throw unavailable();
    const parts = encrypted.split('.'); if (parts.length !== 3 || parts.some(part => !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(part))) throw unavailable();
    const [nonce, tag, data] = parts.map(part => Buffer.from(part, 'base64'));
    if (!nonce || nonce.length !== 12 || !tag || tag.length !== 16 || !data || data.length > maximum) throw unavailable();
    const decipher = createDecipheriv('aes-256-gcm', key, nonce); decipher.setAAD(Buffer.from(hashArtifact(binding))); decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
  } catch { throw unavailable(); }
}
const inactive = new Set(['cancelled', 'failed', 'completed', 'needs_attention', 'awaiting_approval', 'clarification', 'deployment', 'observation']);
/** Check the current caller, rather than requiring a recovered worker to retain the old fence. */
export function authorizeModelWork(state: State, jobId: string, attempt: number | undefined, runtimeFence: number | undefined) {
  const job = state.jobs[jobId], app = job && state.apps[job.appId], lease = state.leases[jobId];
  if (!job || !app || inactive.has(job.stage) || app.status === 'archived' || !Number.isSafeInteger(attempt) || attempt! < 0 || job.attempts !== attempt || !Number.isSafeInteger(runtimeFence) || runtimeFence! < 1 || job.runtimeFence !== runtimeFence || app.runtimeFence !== runtimeFence || !lease?.owner || !Number.isFinite(Date.parse(lease.until)) || Date.parse(lease.until) <= Date.now() || app.activeReleaseId !== job.baseReleaseId) throw unavailable();
  return { job, app, lease };
}
export function modelRequestHash(input: CompletionRequest): string {
  return hashArtifact({ stage: input.stage, system: input.system, prompt: input.prompt, schema: input.schema ?? null, maxOutputTokens: input.maxOutputTokens ?? null, allowUnqualified: input.allowUnqualified ?? false });
}
function outputBinding(record: ModelCheckpointRecord, call: ModelCallRecord) {
  const { encrypted: _encrypted, ...identity } = record;
  return { kind: 'paid-model-output', ...identity, model: call.model, provider: call.provider, costUsd: call.costUsd, usage: call.usage, reservationIds: call.reservationIds };
}
export function assertCompletion(value: Completion): void {
  if (!value || typeof value.text !== 'string' || !value.text.trim() || !['openai', 'anthropic'].includes(value.provider) || typeof value.model !== 'string' || !value.model.length || value.model.length > 200 || !Number.isFinite(value.costUsd) || value.costUsd < 0 || !value.usage || [value.usage.inputTokens, value.usage.outputTokens, value.usage.cachedTokens, value.usage.cacheWriteTokens].some(number => !Number.isSafeInteger(number) || number < 0)) throw new Error('Model routing or billing metadata is malformed; no completion evidence was recorded.');
}
export function saveModelOutput(state: State, key: Buffer, call: ModelCallRecord, result: Completion): void {
  const job = state.jobs[call.jobId]; if (!job || call.attempt === undefined || !call.callSlot || !call.requestHash || !call.appId || call.baseReleaseId === undefined) throw unavailable();
  const id = outputKey(call.jobId, call.attempt, call.callSlot);
  if (state.modelCheckpoints[id]) throw unavailable();
  const reservations = call.reservationIds.map(id => state.reservations[id]);
  if (!reservations.length || new Set(call.reservationIds).size !== call.reservationIds.length || reservations.some(item => !item || item.jobId !== call.jobId || item.actualUsd === null || !Number.isFinite(item.actualUsd) || item.actualUsd < 0) || Math.abs(reservations.reduce((sum, item) => sum + (item?.actualUsd ?? 0), 0) - result.costUsd) > 1e-9) throw unavailable();
  const record: ModelCheckpointRecord = { version: 1, appId: call.appId, jobId: call.jobId, attempt: call.attempt, slot: call.callSlot, callId: call.id, baseReleaseId: call.baseReleaseId, requestHash: call.requestHash, encrypted: '' };
  record.encrypted = encryptPrivate(key, outputBinding(record, call), result, outputLimit); state.modelCheckpoints[id] = record;
}
export function replayModelOutput(state: State, key: Buffer, input: CompletionRequest): Completion | undefined {
  const { job, app } = authorizeModelWork(state, input.jobId, input.attempt, input.runtimeFence);
  const frozen = state.generationContexts[attemptKey(job.id, job.attempts)];
  if (frozen && (frozen.version !== 1 || frozen.appId !== app.id || frozen.jobId !== job.id || frozen.attempt !== job.attempts || frozen.baseReleaseId !== job.baseReleaseId || frozen.intentHash !== intentHash(job) || frozen.businessHash !== hashArtifact(generationBusinessApp(app)))) throw unavailable();
  if (!input.callSlot || !['specification', 'implementation', 'review'].includes(input.callSlot)) throw unavailable();
  // Older completed records have no reconstructible output. Do not silently charge to replace them.
  if (Object.values(state.modelCalls).some(call => call.jobId === job.id && call.status === 'completed' && (!call.callSlot || call.attempt === undefined || !call.requestHash))) throw unavailable();
  const hash = modelRequestHash(input), calls = Object.values(state.modelCalls).filter(call => call.jobId === job.id && call.attempt === input.attempt && call.callSlot === input.callSlot);
  if (calls.some(call => call.requestHash !== hash)) throw unavailable();
  const record = state.modelCheckpoints[outputKey(job.id, input.attempt!, input.callSlot)];
  if (!record) { if (calls.some(call => call.status === 'completed' || call.status === 'failed' && (call.costUsd ?? 0) > 0)) throw unavailable(); return undefined; }
  const call = state.modelCalls[record.callId];
  if (!call || calls.filter(item => item.status === 'completed').length !== 1 || !calls.some(item => item.id === call.id) || call.status !== 'completed' || record.version !== 1 || record.appId !== app.id || record.jobId !== job.id || record.attempt !== input.attempt || record.slot !== input.callSlot || record.requestHash !== hash || record.baseReleaseId !== job.baseReleaseId || call.appId !== app.id || call.baseReleaseId !== job.baseReleaseId || !call.reservationIds.length) throw unavailable();
  const reservations = call.reservationIds.map(id => state.reservations[id]);
  if (new Set(call.reservationIds).size !== call.reservationIds.length || reservations.some(item => !item || item.jobId !== job.id || item.actualUsd === null || !Number.isFinite(item.actualUsd) || item.actualUsd < 0) || call.costUsd === null || Math.abs(reservations.reduce((sum, item) => sum + (item?.actualUsd ?? 0), 0) - call.costUsd) > 1e-9) throw unavailable();
  const result = decryptPrivate(key, outputBinding(record, call), record.encrypted, outputLimit) as Completion;
  try { assertCompletion(result); } catch { throw unavailable(); }
  if (hashArtifact({ model: result.model, provider: result.provider, usage: result.usage, costUsd: result.costUsd }) !== hashArtifact({ model: call.model, provider: call.provider, usage: call.usage, costUsd: call.costUsd })) throw unavailable();
  return result;
}
function intentHash(job: JobRecord) { return hashArtifact({ request: job.request, answer: job.result?.answer ?? null, failureEvidence: job.result?.failureEvidence ?? null }); }
function contextBinding(record: GenerationContextRecord) { const { encrypted: _encrypted, selectionEncrypted: _selectionEncrypted, ...identity } = record; return { kind: 'frozen-generation-context', ...identity }; }
export async function frozenGenerationContext(store: Store, key: Buffer, input: { app: AppRecord; job: JobRecord }, owner: string, context?: GenerationInputContext): Promise<GenerationInputContext | undefined> {
  return store.transaction(state => {
    const { job, app, lease } = authorizeModelWork(state, input.job.id, input.job.attempts, input.job.runtimeFence); if (lease.owner !== owner) throw unavailable();
    const id = attemptKey(job.id, job.attempts), intent = intentHash(job), business = hashArtifact(generationBusinessApp(app));
    const existing = state.generationContexts[id];
    if (existing) {
      if (existing.version !== 1 || existing.appId !== app.id || existing.jobId !== job.id || existing.attempt !== job.attempts || existing.baseReleaseId !== job.baseReleaseId || existing.intentHash !== intent || existing.businessHash !== business) throw unavailable();
      const decoded = decryptPrivate(key, contextBinding(existing), existing.encrypted, contextLimit) as GenerationInputContext;
      if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) throw unavailable();
      validatedGenerationConnections(decoded.connectionInventory, app.id); validatedIntegrationResearch(decoded.integrationResearch, app.id, job.id);
      if (existing.selectionEncrypted !== undefined) decoded.previousSourceSelection = readSourceSelection(key, existing, decoded, job);
      return decoded;
    }
    if (!context) return undefined;
    validatedGenerationConnections(context.connectionInventory, app.id); validatedIntegrationResearch(context.integrationResearch, app.id, job.id);
    const record: GenerationContextRecord = { version: 1, appId: app.id, jobId: job.id, attempt: job.attempts, baseReleaseId: job.baseReleaseId, intentHash: intent, businessHash: business, encrypted: '' };
    record.encrypted = encryptPrivate(key, contextBinding(record), context, contextLimit); state.generationContexts[id] = record; return context;
  });
}

function selectionBinding(record: GenerationContextRecord) { return { ...contextBinding(record), kind: 'frozen-previous-source-selection' }; }
function checkedSourceSelection(value: unknown, context: GenerationInputContext, job: JobRecord): PreviousSourceSelection {
  try {
    const criteria = (value as PreviousSourceSelection)?.acceptanceCriteria;
    return validatedPreviousSourceSelection(value, { appId: job.appId, jobId: job.id, attempt: job.attempts, baseReleaseId: job.baseReleaseId, request: job.request, answer: context.answer, files: context.previousFiles, acceptanceCriteria: criteria });
  } catch { throw unavailable(); }
}
function readSourceSelection(key: Buffer, record: GenerationContextRecord, context: GenerationInputContext, job: JobRecord): PreviousSourceSelection {
  return checkedSourceSelection(decryptPrivate(key, selectionBinding(record), record.selectionEncrypted!, 512 * 1024), context, job);
}
/** Append one immutable selection without changing the encrypted starting source or paid requirements output. */
export async function frozenPreviousSourceSelection(store: Store, key: Buffer, input: { app: AppRecord; job: JobRecord }, owner: string, proposed: PreviousSourceSelection): Promise<PreviousSourceSelection> {
  return store.transaction(state => {
    const { job, app, lease } = authorizeModelWork(state, input.job.id, input.job.attempts, input.job.runtimeFence);
    if (lease.owner !== owner) throw unavailable();
    const record = state.generationContexts[attemptKey(job.id, job.attempts)];
    if (!record || record.version !== 1 || record.appId !== app.id || record.jobId !== job.id || record.attempt !== job.attempts || record.baseReleaseId !== job.baseReleaseId || record.intentHash !== intentHash(job) || record.businessHash !== hashArtifact(generationBusinessApp(app))) throw unavailable();
    const context = decryptPrivate(key, contextBinding(record), record.encrypted, contextLimit) as GenerationInputContext;
    if (!context || typeof context !== 'object' || Array.isArray(context)) throw unavailable();
    const checked = checkedSourceSelection(proposed, context, job);
    if (record.selectionEncrypted !== undefined) {
      const existing = readSourceSelection(key, record, context, job);
      if (hashArtifact(existing) !== hashArtifact(checked)) throw unavailable();
      return existing;
    }
    record.selectionEncrypted = encryptPrivate(key, selectionBinding(record), checked, 512 * 1024);
    return checked;
  });
}
