import { randomUUID } from 'node:crypto';
import type { ModelGateway } from '../../../packages/core/src/models.ts';
import { redact } from '../../../packages/core/src/index.ts';
import type { Store } from './store.ts';
import { event } from './store.ts';
import { assertCompletion, modelRequestHash, replayModelOutput, saveModelOutput, ModelCheckpointError } from './model-checkpoints.ts';
import { modelBillingReviewRequired, ModelBillingHoldError } from './budget.ts';
import type { ModelCallSlot } from '../../../packages/core/src/models.ts';

export type ModelCallRecord = {
  id: string; jobId: string; stage: string; status: 'running' | 'completed' | 'failed' | 'uncertain';
  model: string | null; provider: string | null; costUsd: number | null;
  usage: { inputTokens: number; outputTokens: number; cachedTokens: number; cacheWriteTokens: number } | null;
  reservationIds: string[]; startedAt: string; completedAt: string | null; error?: string;
  runtimeFence?: number;
  appId?: string; baseReleaseId?: string | null; attempt?: number; callSlot?: ModelCallSlot; requestHash?: string;
};

/** Persist billing/routing evidence only. Provider prompts, output and credentials never enter this record. */
export function recordModelCalls<T extends Pick<ModelGateway, 'complete'>>(gateway: T, store: Store, checkpointKey?: Buffer): T {
  if (checkpointKey && checkpointKey.length !== 32) throw new Error('Model checkpoints require a 32-byte encryption key.');
  const complete = gateway.complete.bind(gateway);
  gateway.complete = async (input, hooks) => {
    const id = randomUUID(); const reservationIds: string[] = [];
    const admission = await store.transaction(state => {
      const job = state.jobs[input.jobId]; if (!job) throw new Error('Model calls require a durable authorized job.');
      if (checkpointKey) {
        if (!hooks.worker || hooks.worker.runtimeFence !== input.runtimeFence || state.leases[input.jobId]?.owner !== hooks.worker.owner) throw new ModelCheckpointError('The model caller owner or fence changed; no cached output or provider spending is authorized.');
        const cached = replayModelOutput(state, checkpointKey, input);
        if (modelBillingReviewRequired(state, input.jobId)) throw new ModelBillingHoldError();
        if (cached) return { cached };
      }
      const owner = state.leases[input.jobId]?.owner; const runtimeFence = job.runtimeFence;
      state.modelCalls[id] = { id, jobId: input.jobId, stage: input.stage, status: 'running', model: null, provider: null, costUsd: null, usage: null, reservationIds: [], startedAt: new Date().toISOString(), completedAt: null, ...(runtimeFence ? { runtimeFence } : {}), ...(checkpointKey ? { appId: job.appId, baseReleaseId: job.baseReleaseId, attempt: input.attempt!, callSlot: input.callSlot!, requestHash: modelRequestHash(input) } : {}) };
      return { owner, runtimeFence };
    });
    if ('cached' in admission && admission.cached) return admission.cached;
    const worker = admission as { owner: string | undefined; runtimeFence: number | undefined };
    const recordedHooks = {
      reserve: async (amount: number) => {
        const reservationId = await hooks.reserve(amount); reservationIds.push(reservationId);
        await store.transaction(state => { const call = state.modelCalls[id]; if (call) call.reservationIds = [...reservationIds]; }); return reservationId;
      }, settle: hooks.settle
    };
    let completionReceived = false;
    try {
      const result = await complete(input, recordedHooks);
      completionReceived = true; assertCompletion(result);
      await store.transaction(state => {
        const call = state.modelCalls[id]!; Object.assign(call, { status: 'completed', model: result.model, provider: result.provider, costUsd: result.costUsd, usage: { inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, cachedTokens: result.usage.cachedTokens, cacheWriteTokens: result.usage.cacheWriteTokens }, completedAt: new Date().toISOString() });
        if (checkpointKey) saveModelOutput(state, checkpointKey, call, result);
        const job = state.jobs[input.jobId]; const lease = state.leases[input.jobId];
        const currentWorker = worker.owner ? lease?.owner === worker.owner && job?.runtimeFence === worker.runtimeFence && Date.parse(lease.until) > Date.now() : !lease;
        if (job && currentWorker && !['cancelled', 'completed', 'deployment', 'observation'].includes(job.stage)) event(state, job, job.stage, `Model step completed using ${result.provider} ${result.model}.`, 'status', { model: result.model, provider: result.provider, stage: input.stage, costUsd: result.costUsd, usage: result.usage });
      }); return result;
    } catch (failure) {
      await store.transaction(state => {
        const call = state.modelCalls[id]; if (!call || call.status === 'completed') return;
        const reservations = reservationIds.map(id => state.reservations[id]).filter(item => !!item);
        const uncertain = reservations.some(item => item.actualUsd === null) || !!checkpointKey && completionReceived;
        call.status = uncertain ? 'uncertain' : 'failed'; call.costUsd = uncertain ? null : reservations.reduce((sum, item) => sum + (item.actualUsd ?? 0), 0); call.completedAt = new Date().toISOString(); call.error = String(redact(failure instanceof Error ? failure.message : 'Model step did not complete.')).slice(0, 1000);
      }); throw failure;
    }
  };
  return gateway;
}
