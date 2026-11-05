import { randomUUID } from 'node:crypto';
import type { BudgetHooks } from '../packages/core/src/models.ts';

export class QualificationBudget {
  private reservations = new Map<string, { suite: string; amount: number }>();
  private spent = new Map<string, number>();
  private history = new Map<string, { reservationId: string; suite: string; reservedUsd: number; actualUsd: number | null }>();
  constructor(public readonly aggregateLimitUsd: number, public readonly suiteLimitUsd: number, public readonly requestLimitUsd = Math.min(aggregateLimitUsd, suiteLimitUsd)) {
    if (![aggregateLimitUsd, suiteLimitUsd, requestLimitUsd].every(value => Number.isFinite(value) && value > 0)) throw new Error('Explicit positive aggregate, per-suite and per-request dollar limits are required.');
  }
  totals(suite?: string) {
    const spentUsd = suite ? this.spent.get(suite) ?? 0 : [...this.spent.values()].reduce((a, b) => a + b, 0);
    const heldUsd = [...this.reservations.values()].filter(value => !suite || value.suite === suite).reduce((sum, value) => sum + value.amount, 0);
    return { spentUsd, heldUsd };
  }
  requestRecords() { return [...this.history.values()].map(record => ({ ...record })); }
  hooks(suite: string): BudgetHooks {
    return {
      reserve: async amount => {
        if (!Number.isFinite(amount) || amount < 0) throw new Error('Invalid budget reservation.');
        if (amount > this.requestLimitUsd + 1e-9) throw new Error('Per-request qualification limit cannot reserve this request; no provider request was sent.');
        const total = this.totals(), current = this.totals(suite);
        if (total.spentUsd + total.heldUsd + amount > this.aggregateLimitUsd + 1e-9) throw new Error('Aggregate qualification budget cannot reserve this request.');
        if (current.spentUsd + current.heldUsd + amount > this.suiteLimitUsd + 1e-9) throw new Error('Per-suite qualification budget cannot reserve this request.');
        const id = randomUUID(); this.reservations.set(id, { suite, amount });
        this.history.set(id, { reservationId: id, suite, reservedUsd: amount, actualUsd: null }); return id;
      },
      settle: async (id, actual) => {
        const reservation = this.reservations.get(id);
        if (!reservation || reservation.suite !== suite || !Number.isFinite(actual) || actual < 0) throw new Error('Invalid provider billing settlement.');
        this.history.get(id)!.actualUsd = actual;
        this.reservations.delete(id); this.spent.set(suite, (this.spent.get(suite) ?? 0) + actual);
        const total = this.totals(), current = this.totals(suite);
        if (total.spentUsd + total.heldUsd > this.aggregateLimitUsd + 1e-9 || current.spentUsd + current.heldUsd > this.suiteLimitUsd + 1e-9) throw new Error('Confirmed provider billing exceeded a qualification budget; further requests must stop.');
      }
    };
  }
}

