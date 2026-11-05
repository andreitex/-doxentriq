import { createHmac } from 'node:crypto';
import { z } from 'zod';
import { hashArtifact } from './security.ts';

const uuid = z.string().uuid(), hex = z.string().regex(/^[a-f0-9]{64}$/);
export const appAccountTargetSchema = z.object({ appId: uuid, invitationId: uuid, userId: uuid, creationOperationId: uuid }).strict();
export const appAccountSnapshotSchema = appAccountTargetSchema.extend({ schemaVersion: z.literal(1), releaseId: uuid, identityHash: hex, policyHash: hex, realm: z.string().regex(/^app-[a-f0-9]{24}$/), clientId: z.string().regex(/^[A-Za-z0-9_-]{1,80}$/), username: z.string().email().max(254), email: z.string().email().max(254), enabled: z.boolean(), userEvidenceHash: hex, tokenPolicyHash: hex, accessTokenLifespanSeconds: z.number().int().min(1).max(86400), checkedAt: z.string().datetime() }).strict();
export type AppAccountTarget = z.infer<typeof appAccountTargetSchema>;
export type AppAccountSnapshot = z.infer<typeof appAccountSnapshotSchema>;
export type AppAccountApproval = { id: string; appId: string; action: 'disable_app_account'; artifactHash: string; snapshot: AppAccountSnapshot; impact: string[]; createdAt: string; expiresAt: string; approvedBy: string | null; approvedAt: string | null; consumedAt: string | null };
export type AppAccountActor = { id: string; mfa: boolean; localOwner: boolean };
export type DisableAppAccountRequest = { operationId: string; approval: AppAccountApproval; principal: AppAccountActor };
export const appAccountStatusSchema = z.object({ operationId: uuid, approvalId: uuid, appId: uuid, invitationId: uuid, userId: uuid, artifactHash: hex, status: z.enum(['pending', 'disabled', 'unknown']), checkedAt: z.string().datetime(), detail: z.string().max(1000) }).strict();
export type AppAccountStatus = z.infer<typeof appAccountStatusSchema>;
export type AppAccountOperationIdentity = Pick<AppAccountStatus, 'operationId' | 'approvalId' | 'appId' | 'invitationId' | 'userId' | 'artifactHash'>;
export type AppAccountDependencies = { appAccountSnapshot?: (input: AppAccountTarget) => Promise<AppAccountSnapshot>; disableAppAccount?: (input: DisableAppAccountRequest) => Promise<AppAccountStatus>; appAccountOperation?: (input: AppAccountOperationIdentity) => Promise<AppAccountStatus> };
export const appAccountBinding = ({ checkedAt: _time, ...snapshot }: AppAccountSnapshot) => snapshot;
export const appAccountArtifactHash = (snapshot: AppAccountSnapshot) => hashArtifact({ action: 'disable_app_account', account: appAccountBinding(snapshot) });

export class AppAccountBrokerClient {
  private readonly origin: string;
  constructor(private readonly config: { url: string; token: string; approvalKey: Buffer | string; fetch?: typeof fetch }) {
    let url: URL; try { url = new URL(config.url); } catch { throw new Error('An exact trusted HTTPS account broker authority is required.'); }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname)) || url.username || url.password || url.pathname !== '/' || url.search || url.hash || !config.token) throw new Error('An exact trusted HTTPS account broker authority is required.'); this.origin = url.origin;
  }
  private async call<T>(path: string, input: unknown, signed = false): Promise<T> {
    const body = JSON.stringify(input), key = typeof this.config.approvalKey === 'string' ? Buffer.from(this.config.approvalKey, 'base64') : this.config.approvalKey;
    if (signed && key.length !== 32) throw new Error('An exact account approval proof key is required.');
    let confirmedRejected = false;
    try {
      const response = await (this.config.fetch ?? fetch)(new URL(path, this.origin), { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(90000), headers: { 'content-type': 'application/json', authorization: `Bearer ${this.config.token}`, ...(signed ? { 'x-autosoft-proof': createHmac('sha256', key).update(body).digest('hex') } : {}) }, body });
      if (response.redirected || response.url && new URL(response.url).origin !== this.origin) throw new Error();
      const reader = response.body?.getReader(); if (!reader) throw new Error(); const chunks: Uint8Array[] = []; let size = 0;
      try {
        if (response.ok && response.status !== 200) throw new Error();
        const length = response.headers.get('content-length');
        if (length !== null && (!/^(0|[1-9][0-9]*)$/.test(length) || !Number.isSafeInteger(Number(length)) || Number(length) > 65536)) throw new Error();
        for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > 65536 || length !== null && size > Number(length)) throw new Error(); chunks.push(part.value); }
        if (length !== null && size !== Number(length)) throw new Error();
        const reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))) as T & { rejectedBeforeExecution?: boolean };
        if (!response.ok) { confirmedRejected = !!reply && typeof reply === 'object' && !Array.isArray(reply) && Object.hasOwn(reply, 'rejectedBeforeExecution') && reply.rejectedBeforeExecution === true; throw new Error(); }
        return reply;
      } catch (error) { try { await reader.cancel(); } catch {} throw error; } finally { reader.releaseLock(); }
    } catch { throw Object.assign(new Error('Protected account confirmation is unavailable. Inspect the original operation before another action.'), { confirmedRejected }); }
  }
  snapshot(input: AppAccountTarget): Promise<AppAccountSnapshot> { return this.call('/v1/accounts/snapshot', input); }
  disable(input: DisableAppAccountRequest): Promise<AppAccountStatus> { return this.call('/v1/accounts/disable', input, true); }
  operation(input: AppAccountOperationIdentity): Promise<AppAccountStatus> { return this.call('/v1/accounts/operation', input); }
}
