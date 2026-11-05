import { z } from 'zod';
import { imageSchema, stages } from '../../../packages/core/src/schemas.ts';
import type { VerificationResult } from './engine.ts';
import { migrationSnapshotSchema,validatedMigrationSnapshot } from '../../../packages/core/src/migration-snapshot.ts';

const finding = z.object({ id: z.string().min(1).max(200), severity: z.enum(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']), package: z.string().max(300), installedVersion: z.string().max(200), fixedVersion: z.string().max(200).optional(), source: z.string().max(500), description: z.string().max(5000), appId: z.string().optional() }).strict();
const schema = z.object({
  evidence: z.object({ status: z.enum(['passed', 'failed', 'unavailable']), checkedAt: z.string(), feedUpdatedAt: z.string(), findings: z.array(finding).max(10000), checks: z.array(z.object({ name: z.string().min(1).max(100), passed: z.boolean(), detail: z.string().max(10000) }).strict()).max(100) }).strict(),
  images: z.array(z.string()).max(32), commit: z.string(), previewUrl: z.string().url().nullable(),
  schemaVersion: z.number().int().positive().optional(), compatibleSchemaMin: z.number().int().nonnegative().optional(), compatibleSchemaMax: z.number().int().positive().optional(),
  migrations: z.array(z.object({ id: z.string().min(1).max(100), destructive: z.boolean(), impact: z.string().max(10000), checksum: z.string().regex(/^[a-f0-9]{64}$/), sql:z.string().max(100000).optional() }).strict()).max(1000).optional(),
  appId:z.string().optional(),attemptId:z.string().optional(),filesHash:z.string().regex(/^[a-f0-9]{64}$/).optional(),sourceHash:z.string().regex(/^[a-f0-9]{64}$/).optional(),template:z.string().optional(),migrationSnapshot:migrationSnapshotSchema.optional(),
  sourceBindingVersion:z.literal(1).optional(),inputSourceHash:z.string().regex(/^[a-f0-9]{64}$/).optional(),pipelineHash:z.string().regex(/^[a-f0-9]{64}$/).optional()
}).strict();

/** The trusted broker still needs complete, unambiguous evidence before a preview is called ready. */
export function validatedVerification(value: unknown, appId: string, expected?: {jobId:string;attemptId:string;fence:number;baseReleaseId:string|null;baseArtifactHash:string;baseImage:string;filesHash:string;pipelineHash:string}): VerificationResult {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new Error('Verification broker returned malformed evidence; no ready release was created.');
  const result = parsed.data; const evidence = result.evidence;
  if (new Set(evidence.checks.map(check => check.name)).size !== evidence.checks.length || evidence.findings.some(item => item.appId && item.appId !== appId)) throw new Error('Verification broker returned ambiguous or cross-application evidence; no ready release was created.');
  if (evidence.status === 'passed') {
    if (!expected || result.sourceBindingVersion!==1 || result.inputSourceHash!==expected.filesHash || result.pipelineHash!==expected.pipelineHash || !result.migrationSnapshot || result.appId!==appId || result.attemptId!==expected.attemptId || result.filesHash!==expected.filesHash || !result.sourceHash) throw new Error('Verification lacks exact versioned source and protected migration capture evidence; no ready release was created.');
    const snapshot=validatedMigrationSnapshot(result.migrationSnapshot,{appId,...expected,sourceHash:result.sourceHash,migrations:result.migrations??[]});
    if (!['captured','no_previous_release'].includes(snapshot.status)||snapshot.unappliedMigrationIds.length||result.schemaVersion!==snapshot.schemaEpoch||result.compatibleSchemaMin!==snapshot.schemaEpoch||result.compatibleSchemaMax!==snapshot.schemaEpoch) throw new Error('Existing unapplied migrations require complete preservation and old/new release compatibility proof; capture alone cannot approve them.');
    const fresh = [evidence.checkedAt, evidence.feedUpdatedAt].every(date => Number.isFinite(Date.parse(date)) && Date.parse(date) <= Date.now() + 60000 && Date.now() - Date.parse(date) <= 86400000);
    if (!fresh || !stages.every(stage => evidence.checks.some(check => check.name === stage && check.passed)) || evidence.checks.some(check => !check.passed) || evidence.findings.some(item => ['UNKNOWN', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(item.severity))) throw new Error('Verification passed status lacks complete successful gates, fresh security coverage or eligible findings; no ready release was created.');
    if (!/^[a-f0-9]{40,64}$/.test(result.commit) || !result.images.length || result.images.some(image => !imageSchema.safeParse(image).success)) throw new Error('Verification lacks a verified source commit or digest-pinned runtime images; no ready release was created.');
  }
  return {...result,...(result.migrations?{migrations:result.migrations.map(({sql: _sql,...migration})=>migration)}:{})};
}
