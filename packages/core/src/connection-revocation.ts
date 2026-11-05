import { TrustedBrokerHttp } from './trusted-broker-http.ts';
import { createHmac } from 'node:crypto';
import { z } from 'zod';
import { hashArtifact } from './security.ts';

const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/), hex = z.string().regex(/^[a-f0-9]{64}$/);
export const withdrawalTargetSchema = z.object({ containerId: hex, resourceId: id, profileHash: hex }).strict();
export const withdrawalSnapshotSchema = z.object({ schemaVersion: z.literal(1), type: z.literal('filesystem'), appId: id, connectionId: id, scopeHash: hex, grantApprovalId: id, targets: z.array(withdrawalTargetSchema).max(256), observedAt: z.string().datetime(), snapshotHash: hex }).strict().superRefine((value, ctx) => {
  if (new Set(value.targets.map(item => item.containerId)).size !== value.targets.length || value.targets.some((item, index) => index > 0 && item.containerId <= value.targets[index - 1]!.containerId)) ctx.addIssue({ code: 'custom', message: 'Withdrawal targets must be unique and sorted by immutable container ID.' });
});
export type WithdrawalSnapshot = z.infer<typeof withdrawalSnapshotSchema>;
export const withdrawalSnapshotHash = (snapshot: Omit<WithdrawalSnapshot, 'observedAt' | 'snapshotHash'>): string => hashArtifact(snapshot);
export const withdrawalChangeSchema = z.object({ snapshot: withdrawalSnapshotSchema, registryHash: hex, impactHash: hex }).strict();
export type WithdrawalChange = z.infer<typeof withdrawalChangeSchema>;
export const withdrawalArtifactHash = (change: WithdrawalChange): string => hashArtifact({ schemaVersion: 1, action: 'revoke_readonly_filesystem', change });
export const withdrawalRequestSchema = z.object({ schemaVersion: z.literal(1), action: z.literal('revoke_readonly_filesystem'), operationId: id, approvalId: id, artifactHash: hex, change: withdrawalChangeSchema, approvedAt: z.string().datetime(), expiresAt: z.string().datetime(), principal: z.object({ id, mfa: z.literal(true), localOwner: z.literal(true) }).strict() }).strict();
export type WithdrawalRequest = z.infer<typeof withdrawalRequestSchema>;
export const withdrawalIdentitySchema = z.object({ operationId: id, approvalId: id, appId: id, connectionId: id, artifactHash: hex }).strict();
export type WithdrawalIdentity = z.infer<typeof withdrawalIdentitySchema>;
export const withdrawalStatusSchema = withdrawalIdentitySchema.extend({ schemaVersion: z.literal(1), type: z.literal('filesystem'), status: z.enum(['unknown', 'pending', 'revoked']), tombstone: z.boolean(), snapshotHash: hex, stoppedContainerIds: z.array(hex).max(256), checkedAt: z.string().datetime() }).strict().superRefine((value, ctx) => {
  if (new Set(value.stoppedContainerIds).size !== value.stoppedContainerIds.length || value.status === 'unknown' && (value.tombstone || value.snapshotHash !== '0'.repeat(64) || value.stoppedContainerIds.length !== 0) || value.status !== 'unknown' && !value.tombstone) ctx.addIssue({ code: 'custom', message: 'Withdrawal status is inconsistent.' });
});
export type WithdrawalStatus = z.infer<typeof withdrawalStatusSchema>;

/** Only independently proven filesystem sidecars support explicit withdrawal.
 * No credential, source path, removal or regrant operation exists here. */
export class ConnectionRevocationClient {
  private readonly transport: TrustedBrokerHttp;
  constructor(private readonly config: { url: string; token: string; approvalKey: Buffer | string; fetch?: typeof fetch }) {
    this.transport = new TrustedBrokerHttp(config);
  }
  private async call(route: string, value: unknown, signed = false): Promise<unknown> {
    const body = JSON.stringify(value), key = typeof this.config.approvalKey === 'string' ? Buffer.from(this.config.approvalKey, 'base64') : this.config.approvalKey;
    if (signed && key.length !== 32) throw new Error('Withdrawal proof key must contain 32 bytes.');
    return this.transport.post(route, body, signed ? { 'x-autosoft-proof': createHmac('sha256', key).update(body).digest('hex') } : {}, 120000, 65536);
  }
  async snapshot(input: { appId: string; connectionId: string }): Promise<WithdrawalSnapshot> { const parsed = z.object({ appId: id, connectionId: id }).strict().parse(input), value = withdrawalSnapshotSchema.parse(await this.call('/v1/connectors/revocation/snapshot', parsed)); if (value.appId !== input.appId || value.connectionId !== input.connectionId) throw new Error('Withdrawal inventory belongs to another app or connection.'); return value; }
  async revoke(input: WithdrawalRequest): Promise<WithdrawalStatus> { withdrawalRequestSchema.parse(input); return withdrawalStatusSchema.parse(await this.call('/v1/connectors/revoke', input, true)); }
  async status(input: WithdrawalIdentity): Promise<WithdrawalStatus> { withdrawalIdentitySchema.parse(input); return withdrawalStatusSchema.parse(await this.call('/v1/connectors/revocation/status', input)); }
}
