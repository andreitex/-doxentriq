import { activeAuthority, assertAuthority, authorityMonth, adoptAuthority, type SpendingAuthority } from './spending-authority.ts';
import { randomUUID } from 'node:crypto';
import type { Store, State } from './store.ts';
import { notify } from './store.ts';
import { hashArtifact } from '../../../packages/core/src/index.ts';
export type BudgetChange = { kind: 'job' | 'monthly'; jobId: string | null; oldLimitUsd: number; newLimitUsd: number; month: string; appliedAt: string | null };
export const budgetChangeHash = (change: BudgetChange) => hashArtifact({ kind: change.kind, jobId: change.jobId, oldLimitUsd: change.oldLimitUsd, newLimitUsd: change.newLimitUsd, month: change.month });
export class BudgetLimitError extends Error { readonly statusCode = 409; }
export const modelBillingHoldMessage = 'An interrupted model call requires company reconciliation before this request can make another provider call. Held reservations remain reserved.';
export const modelBillingHoldHint = 'Ask the company operator to reconcile the interrupted provider outcome and its billing evidence. Retrying or increasing the budget cannot resolve this hold; existing reservations remain reserved.';
export class ModelBillingHoldError extends Error { readonly statusCode = 409; constructor() { super(modelBillingHoldMessage); } }
export function modelBillingReviewRequired(state: Pick<State, 'modelCalls'>, jobId: string): boolean {
  return Object.values(state.modelCalls).some(call => call.jobId === jobId && (call.status === 'running' || call.status === 'uncertain'));
}
export const currentMonth = authorityMonth;
export function budgetSummary(state: State, requestLimitUsd: number, monthlyLimitUsd: number) {
  const authority = activeAuthority(state);
  monthlyLimitUsd = Math.min(state.settings.budget?.monthlyLimitUsd ?? monthlyLimitUsd, authority ? authority.monthlyLimitMicrousd / 1e6 : Infinity);
  const month = currentMonth(authority?.timezone); const reservations = Object.values(state.reservations);
  const cost = (value: number) => authority ? Math.ceil(value * 1e6) : value;
  const divisor = authority ? 1e6 : 1;
  const workflowSpentUsd = reservations.filter(item => item.month === month).reduce((sum, item) => sum + cost(item.actualUsd ?? 0), 0) / divisor;
  const externalConfirmedUsd = authority?.month === month ? authority.confirmedExternalMicrousd / 1e6 : 0;
  const externalConservativeUsd = authority?.month === month ? authority.conservativeExternalMicrousd / 1e6 : 0;
  const spentUsd = workflowSpentUsd + externalConfirmedUsd + externalConservativeUsd;
  // An unresolved older call cannot be forgotten at a calendar boundary.
  const reservedUsd = reservations.reduce((sum, item) => sum + cost(item.actualUsd === null ? item.amountUsd : 0), 0) / divisor;
  const authorityExpired = !!authority && authority.month !== month;
  const remainingUsd = authorityExpired ? 0 : authority ? Math.max(0, Math.floor(monthlyLimitUsd * 1e6) - Math.round(spentUsd * 1e6) - Math.round(reservedUsd * 1e6)) / 1e6 : Math.max(0, monthlyLimitUsd - spentUsd - reservedUsd);
  return { currency: 'USD', month, requestLimitUsd, monthlyLimitUsd, spentUsd, reservedUsd, remainingUsd, workflowSpentUsd, externalConfirmedUsd, externalConservativeUsd, authorityId: authority?.id ?? null, authorityLimitUsd: authority ? authority.monthlyLimitMicrousd / 1e6 : null, authorityExpired };
}
export class BudgetManager {
  constructor(private store: Store, private requestLimitUsd: number, private monthlyLimitUsd: number, private authority?: SpendingAuthority) {}
  async initialize(): Promise<void> { await adoptAuthority(this.store, this.authority); }
  hooks(jobId: string, worker?: { owner: string; runtimeFence: number }) {
    const authorizedWorker = worker ? Object.freeze({ owner: worker.owner, runtimeFence: worker.runtimeFence }) : undefined;
    return Object.freeze({ ...(authorizedWorker ? { worker: authorizedWorker } : {}), reserve: async (amountUsd: number) => {
      if (!Number.isFinite(amountUsd) || amountUsd < 0) throw new Error('Invalid model cost reservation.');
      if (this.authority) amountUsd = Math.ceil(amountUsd * 1e6) / 1e6;
      return this.store.transaction(state => {
        assertAuthority(state, this.authority);
        const job = state.jobs[jobId]; if (!job) throw new Error('Job no longer exists.');
        if (authorizedWorker) {
          const lease = state.leases[jobId];
          if (!lease || lease.owner !== authorizedWorker.owner || !Number.isFinite(Date.parse(lease.until)) || Date.parse(lease.until) <= Date.now() || job.runtimeFence !== authorizedWorker.runtimeFence) throw new Error('Worker lease or application fence changed; no further model spending is authorized for this worker.');
        }
        // A current running record belongs to this call; older or uncertain calls cannot authorize new spending.
        if (Object.values(state.modelCalls).some(call => call.jobId === jobId && (call.status === 'uncertain' || call.status === 'running' && authorizedWorker && call.runtimeFence !== authorizedWorker.runtimeFence))) throw new ModelBillingHoldError();
        if (['cancelled', 'failed', 'completed', 'awaiting_approval'].includes(job.stage)) throw new Error('This job cannot make further model calls.');
        const summary = budgetSummary(state, this.requestLimitUsd, this.monthlyLimitUsd);
        const reservedForJob = Object.values(state.reservations).filter(item => item.jobId === jobId && item.actualUsd === null).reduce((sum, item) => sum + item.amountUsd, 0);
        if (job.costUsd + reservedForJob + amountUsd > job.budgetUsd + 1e-9 || amountUsd > summary.remainingUsd + 1e-9) throw new BudgetLimitError('The estimated model call exceeds the request or monthly spending limit.');
        const id = randomUUID(); state.reservations[id] = { id, jobId, amountUsd, actualUsd: null, month: summary.month, createdAt: new Date().toISOString() }; return id;
      });
    }, settle: async (id: string, actualUsd: number) => {
      if (!Number.isFinite(actualUsd) || actualUsd < 0) throw new Error('Invalid settled model cost.');
      await this.store.transaction(state => {
        const item = state.reservations[id]; if (!item || item.jobId !== jobId) throw new Error('Unknown model reservation.');
        if (item.actualUsd !== null) return;
        item.actualUsd = actualUsd; const job = state.jobs[jobId]; if (job) job.costUsd += actualUsd;
        if (actualUsd > item.amountUsd) notify(state, 'warning', 'Model estimate exceeded', `Job ${jobId}: actual cost exceeded its reserved estimate. Further model calls remain subject to limits.`);
      });
    } });
  }
}
