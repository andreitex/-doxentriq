import { z } from 'zod';
import { idSchema, imageSchema } from './schemas.js';
import { hashArtifact } from './security.js';

const hex = z.string().regex(/^[a-f0-9]{64}$/), zero = '0'.repeat(64);
export const migrationSnapshotRequestSchema = z.object({
  schemaVersion: z.literal(1), appId: idSchema, jobId: idSchema, attemptId: idSchema,
  fence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER), baseReleaseId: idSchema.nullable(),
  baseArtifactHash: z.union([hex, z.literal('')]), baseImage: z.union([imageSchema, z.literal('')]),
  sourceHash: hex, migrationSetHash: hex
}).strict().superRefine((value, ctx) => {
  if (value.baseReleaseId === null ? value.baseArtifactHash !== '' || value.baseImage !== '' : value.baseArtifactHash === '' || value.baseImage === '') ctx.addIssue({ code: 'custom', message: 'Exact previous release identity is required.' });
});
export type MigrationSnapshotRequest = z.infer<typeof migrationSnapshotRequestSchema>;
export const migrationSetHash = (migrations: { id: string; checksum: string }[]): string => hashArtifact(migrations.map(({ id, checksum }) => ({ id, checksum })));
export const migrationSnapshotSchema = z.object({
  schemaVersion: z.literal(1), binding: migrationSnapshotRequestSchema, requestHash: hex,
  status: z.enum(['pending', 'unavailable', 'captured', 'no_previous_release']), checkedAt: z.string().datetime(),
  schemaEpoch: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), schemaFingerprintHash: hex,
  migrationLedgerHash: hex, streamHash: hex, rowDigest: hex,
  tableCount: z.number().int().min(0).max(64), rowCount: z.number().int().min(0).max(100000), byteCount: z.number().int().min(0).max(256 * 1024 ** 2),
  unappliedMigrationIds: z.array(idSchema).max(1000), dataPreservation: z.enum(['captured_only', 'no_previous_release', 'not_captured']),
  previousReleaseCompatibility: z.enum(['not_run', 'no_previous_release']), publicationEligible: z.literal(false),
  reason: z.enum(['none', 'snapshot_unavailable', 'migration_contract_required'])
}).strict().superRefine((value, ctx) => {
  const bad = () => ctx.addIssue({ code: 'custom', message: 'Capture is not a preservation or application compatibility certificate.' });
  if (value.requestHash !== hashArtifact(value.binding) || new Set(value.unappliedMigrationIds).size !== value.unappliedMigrationIds.length) bad();
  if (value.status === 'captured') {
    if (value.dataPreservation !== 'captured_only' || value.previousReleaseCompatibility !== 'not_run' || value.byteCount < 1 || value.reason !== (value.unappliedMigrationIds.length ? 'migration_contract_required' : 'none') || [value.schemaFingerprintHash, value.migrationLedgerHash, value.streamHash, value.rowDigest].includes(zero)) bad();
  } else {
    if (value.tableCount || value.rowCount || value.byteCount || value.unappliedMigrationIds.length || [value.schemaFingerprintHash, value.migrationLedgerHash, value.streamHash, value.rowDigest].some(hash => hash !== zero)) bad();
    if (value.status === 'no_previous_release') {
      if (value.binding.baseReleaseId !== null || value.schemaEpoch !== 1 || value.dataPreservation !== 'no_previous_release' || value.previousReleaseCompatibility !== 'no_previous_release' || value.reason !== 'none') bad();
    } else if (value.dataPreservation !== 'not_captured' || value.previousReleaseCompatibility !== 'not_run' || value.reason !== 'snapshot_unavailable') bad();
  }
});
export type MigrationSnapshotReceipt = z.infer<typeof migrationSnapshotSchema>;
export function validatedMigrationSnapshot(value: unknown, expected: { appId: string; jobId: string; attemptId: string; fence: number; baseReleaseId: string | null; baseArtifactHash:string;baseImage:string; sourceHash: string; migrations: { id: string; checksum: string }[] }, now = Date.now()): MigrationSnapshotReceipt {
  const parsed = migrationSnapshotSchema.safeParse(value);
  if (!parsed.success) throw new Error('Migration capture evidence is unavailable or malformed; compatibility remains unproven.');
  const receipt = parsed.data, binding = receipt.binding, checked = Date.parse(receipt.checkedAt);
  if (binding.appId !== expected.appId || binding.jobId !== expected.jobId || binding.attemptId !== expected.attemptId || binding.fence !== expected.fence || binding.baseReleaseId !== expected.baseReleaseId || binding.baseArtifactHash!==expected.baseArtifactHash||binding.baseImage!==expected.baseImage||binding.sourceHash !== expected.sourceHash || binding.migrationSetHash !== migrationSetHash(expected.migrations) || checked > now + 60000 || now - checked > 86400000) throw new Error('Migration capture context changed or is stale; compatibility remains unproven.');
  return receipt;
}
