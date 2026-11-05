import { z } from 'zod';
import { hashArtifact } from '../../../packages/core/src/index.ts';
import type { State, Store } from './store.ts';

const microusd = z.number().int().nonnegative().max(1_000_000_000_000);
export const spendingAuthoritySchema = z.object({
  schemaVersion: z.literal(1), id: z.string().regex(/^[a-f0-9]{32}$/),
  month: z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/), timezone: z.string().max(100),
  adminOrigin: z.string().url(), beforeLedgerSha256: z.string().regex(/^[a-f0-9]{64}$/),
  monthlyLimitMicrousd: microusd.positive(), confirmedExternalMicrousd: microusd,
  conservativeExternalMicrousd: microusd, allocationMicrousd: microusd.positive()
}).strict().superRefine((value, ctx) => {
  try { new Intl.DateTimeFormat('en', { timeZone: value.timezone }); } catch { ctx.addIssue({ code: 'custom', message: 'Invalid budget timezone.' }); }
  try {
    const origin = new URL(value.adminOrigin);
    if (origin.protocol !== 'https:' || origin.origin !== value.adminOrigin) throw new Error();
  } catch { ctx.addIssue({ code: 'custom', message: 'An exact HTTPS administrator origin is required.' }); }
  if (value.confirmedExternalMicrousd + value.conservativeExternalMicrousd + value.allocationMicrousd !== value.monthlyLimitMicrousd) ctx.addIssue({ code: 'custom', message: 'The handover must account for the complete allowance.' });
});
export type SpendingAuthority = z.infer<typeof spendingAuthoritySchema>;
export type SpendingAuthorityRecord = { authority: SpendingAuthority; activatedAt: string };
export function authorityMonth(timezone = 'UTC', now = new Date()): string {
  const parts = new Intl.DateTimeFormat('en', { timeZone: timezone, year: 'numeric', month: '2-digit' }).formatToParts(now);
  return `${parts.find(part => part.type === 'year')!.value}-${parts.find(part => part.type === 'month')!.value}`;
}
export function activeAuthority(state: State): SpendingAuthority | undefined {
  const records = Object.values(state.spendingAuthorities);
  if (records.length > 1) throw new Error('Multiple spending authorities require company reconciliation.');
  return records[0]?.authority;
}
export function assertAuthority(state: State, configured?: SpendingAuthority): void {
  const stored = activeAuthority(state);
  if (!!stored !== !!configured || stored && configured && hashArtifact(stored) !== hashArtifact(configured)) throw new Error('The protected spending authority is missing or changed; model spending is disabled.');
}
/** Idempotent adoption only into a ledger that has never made a model call. */
export async function adoptAuthority(store: Store, configured?: SpendingAuthority): Promise<void> {
  await store.transaction(state => {
    const stored = activeAuthority(state);
    if (stored || !configured) { assertAuthority(state, configured); return; }
    spendingAuthoritySchema.parse(configured);
    if (authorityMonth(configured.timezone) !== configured.month) throw new Error('The company spending handover has expired.');
    if (Object.keys(state.reservations).length || Object.keys(state.modelCalls).length) throw new Error('Existing platform model accounting requires reconciliation before a handover.');
    state.spendingAuthorities[configured.id] = { authority: structuredClone(configured), activatedAt: new Date().toISOString() };
  });
}
export function assertAuthorityCeiling(state: State, proposedUsd: number): void {
  const authority = activeAuthority(state);
  if (authority && (authorityMonth(authority.timezone) !== authority.month || proposedUsd * 1e6 > authority.monthlyLimitMicrousd)) {
    const failure = new Error('This exceeds the company-authorized shared allowance or its validity. Company reconciliation is required.');
    Object.assign(failure, { statusCode: 409 }); throw failure;
  }
}
