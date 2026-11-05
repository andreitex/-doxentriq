import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { emptyState } from '../src/store.ts';
import { currentDatabaseSchema, recordDatabaseSchema } from '../src/schema-state.ts';
import type { AppRecord, ReleaseRecord } from '../../../packages/core/src/types.ts';

test('code rollback preserves the actual schema and missing, lower or unexplained runtime epochs fail closed', () => {
  const state = emptyState(); const now = new Date().toISOString();
  const app: AppRecord = { id: randomUUID(), slug: 'test-app', name: 'Test', description: '', kind: 'web', status: 'published', activeReleaseId: null, databaseSchemaVersion: 2, url: 'https://test-app.apps.test', previewUrl: null, createdAt: now, updatedAt: now };
  const target = { id: randomUUID(), appId: app.id, schemaVersion: 1 } as ReleaseRecord;
  state.apps[app.id] = app; recordDatabaseSchema(state, app, target, 2, true); assert.equal(app.databaseSchemaVersion, 2); assert.equal(currentDatabaseSchema(state, app), 2);
  for (const invalid of [undefined, 1, 3, NaN, 1.5]) assert.throws(() => recordDatabaseSchema(state, app, target, invalid, true), /expected preserved database schema/);
  assert.equal(app.databaseSchemaVersion, 2); recordDatabaseSchema(state, app, { ...target, schemaVersion: 3 }, 3, true); assert.equal(app.databaseSchemaVersion, 3);
  app.databaseSchemaVersion = NaN; assert.throws(() => currentDatabaseSchema(state, app), /recorded live database schema is invalid/);
});
