import type { AppRecord, ReleaseRecord } from '../../../packages/core/src/types.ts';
import type { State } from './store.ts';

export function currentDatabaseSchema(state: State, app: AppRecord): number {
  const value = app.databaseSchemaVersion ?? (app.activeReleaseId ? state.releases[app.activeReleaseId]?.schemaVersion : undefined) ?? 1;
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('The recorded live database schema is invalid; company reconciliation is required.');
  return value;
}
/** A code rollback preserves the live database schema; the runtime must report the approved additive epoch exactly. */
export function recordDatabaseSchema(state: State, app: AppRecord, release: ReleaseRecord, reported: number | undefined, requireReported = false): void {
  const expected = Math.max(currentDatabaseSchema(state, app), release.schemaVersion);
  if (requireReported && reported === undefined || reported !== undefined && (!Number.isSafeInteger(reported) || reported !== expected)) throw new Error('The runtime did not confirm the expected preserved database schema; reconcile the exact operation before recording success.');
  app.databaseSchemaVersion = reported ?? expected;
}
