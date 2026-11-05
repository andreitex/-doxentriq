import { TrustedBrokerHttp } from './trusted-broker-http.ts';
import { createHmac } from 'node:crypto';
import type { AppAccessSnapshot } from './access.ts';

export type DirectoryProvider = 'microsoft' | 'google';
export type DirectoryScope = { schemaVersion: 1; appId: string; connectionId: string; provider: DirectoryProvider; tenantId: string; workspaceDomain: string | null; identityBindingHash: string; policyHash: string; registryHash: string; credentialRef: string; credentialCiphertextSha256: string; groupIds: string[]; evidenceTtlSeconds: number; accessExpiresAt: string };
export type DirectoryApproval = { id: string; action: 'activate_directory'; appId: string; artifactHash: string; scope: DirectoryScope; impact: string[]; expiresAt: string; approvedAt: string | null; approvedBy: string | null; consumedAt: string | null };
export type DirectoryActivation = { id: string; appId: string; approvalId: string; artifactHash: string; scope: DirectoryScope; checkedAt: string; activatedAt: string; disabledAt: string | null };
export type DirectoryEvidenceRecord = { id: string; appId: string; activationId: string; expiresAt: string; encrypted: string };
export type DirectorySubjectRequest = { appId: string; appSubject: string; provider: DirectoryProvider; tenantId: string; workspaceDomain: string | null };
export type DirectorySubject = DirectorySubjectRequest & { upstreamUserId: string; bindingHash: string; policyHash: string; releaseId: string; checkedAt: string };
export type DirectoryIdentityKeys = { appId: string; releaseId: string; policyHash: string; issuer: string; audience: string; checkedAt: string; jwks: { keys: Record<string, string>[] } };
export type DirectoryIdentityConfiguration = { appId: string; provider: DirectoryProvider; tenantId: string; workspaceDomain: string | null; bindingHash: string; checkedAt: string };
export type DirectoryDependencies = {
  accessSnapshot?: (input: { appId: string }) => Promise<AppAccessSnapshot>;
  directoryIdentityKeys?: (input: { appId: string }) => Promise<DirectoryIdentityKeys>;
  directoryIdentitySubject?: (input: DirectorySubjectRequest) => Promise<DirectorySubject>;
  directoryIdentityConfiguration?: (input: Omit<DirectorySubjectRequest, 'appSubject'>) => Promise<DirectoryIdentityConfiguration>;
};
/** Company-only read endpoints. Directory credentials are never sent to the broker. */
export class DirectoryBrokerClient {
  private readonly transport: TrustedBrokerHttp;
  constructor(private readonly config: { url: string; token: string; approvalKey: Buffer | string; fetch?: typeof fetch }) {
    this.transport = new TrustedBrokerHttp(config);
  }
  private async call<T>(route: string, value: unknown): Promise<T> {
    const body = JSON.stringify(value), key = typeof this.config.approvalKey === 'string' ? Buffer.from(this.config.approvalKey, 'base64') : this.config.approvalKey;
    if (key.length !== 32) throw new Error('Directory identity proof key must contain 32 bytes.');
    return this.transport.post<T>(route, body, { 'x-autosoft-proof': createHmac('sha256', key).update(body).digest('hex') }, 30000, 1048576);
  }
  keys(input: { appId: string }): Promise<DirectoryIdentityKeys> { return this.call('/v1/access/directory-keys', input); }
  subject(input: DirectorySubjectRequest): Promise<DirectorySubject> { return this.call('/v1/access/directory-subject', input); }
  configuration(input: Omit<DirectorySubjectRequest, 'appSubject'>): Promise<DirectoryIdentityConfiguration> { return this.call('/v1/access/directory-configuration', input); }
}
