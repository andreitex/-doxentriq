import { TrustedBrokerHttp } from './trusted-broker-http.ts';
import { createHmac } from 'node:crypto';

export type AppAccessRole = { id: string; name: string; permissions: string[] };
export type AppGroupMapping = { provider: 'microsoft' | 'google'; tenantId: string; groupId: string; connectionId: string; roleIds: string[]; status: 'pending_validation' };
export type AppAccessPolicy = { schemaVersion: 1; appId: string; invitationsEnabled: boolean; requireTotp: true; roles: AppAccessRole[]; groupMappings: AppGroupMapping[] };
export type AppAccessSnapshot = { appId: string; releaseId: string; identityHash: string; policyHash: string; permissions: string[]; policy: AppAccessPolicy; checkedAt: string };
export type AccessApproval = { id: string; appId: string; action: 'access_policy' | 'invitation'; artifactHash: string; basePolicyHash: string; impact: string[]; expiresAt: string; approvedBy: string | null; approvedAt: string | null; consumedAt: string | null };
export type AppInvitation = { id: string; appId: string; email: string; roleIds: string[]; policyHash: string; expiresAt: string; createdBy: string; createdAt: string; approvalId: string };
export type AccessOperationResult = { operationId: string; appId: string; status: 'running' | 'succeeded' | 'failed' | 'unknown'; action?: 'access_policy' | 'invitation'; artifactHash?: string; policyHash?: string; invitationId?: string; userId?: string; detail?: string };
export type AccessActor = { id: string; mfa: boolean };
export type AccessPolicyRequest = { operationId: string; appId: string; basePolicyHash: string; policy: AppAccessPolicy; approval: AccessApproval; principal: AccessActor };
export type AcceptInvitationRequest = { operationId: string; invitation: AppInvitation; approval: AccessApproval; principal: AccessActor; password: string };

/** Transient signed bodies may contain an invitation password. They are never recorded. */
export class AccessBrokerClient {
  private readonly transport: TrustedBrokerHttp;
  constructor(private readonly config: { url: string; token: string; approvalKey: Buffer | string; fetch?: typeof fetch }) {
    this.transport = new TrustedBrokerHttp(config);
  }
  private async call<T>(route: string, value: unknown, signed = false): Promise<T> {
    const body = JSON.stringify(value), key = typeof this.config.approvalKey === 'string' ? Buffer.from(this.config.approvalKey, 'base64') : this.config.approvalKey;
    if (signed && key.length !== 32) throw new Error('Access approval proof key must contain 32 bytes.');
    return this.transport.post<T>(route, body, signed ? { 'x-autosoft-proof': createHmac('sha256', key).update(body).digest('hex') } : {}, 120000, 1048576);
  }
  snapshot(input: { appId: string }): Promise<AppAccessSnapshot> { return this.call('/v1/access/snapshot', input); }
  applyPolicy(input: AccessPolicyRequest): Promise<AccessOperationResult> { return this.call('/v1/access/policy', input, true); }
  acceptInvitation(input: AcceptInvitationRequest): Promise<AccessOperationResult> { return this.call('/v1/access/invite', input, true); }
  operation(input: { appId: string; operationId: string }): Promise<AccessOperationResult> { return this.call('/v1/access/operation', input); }
}
