import { TrustedBrokerHttp } from './trusted-broker-http.ts';
import { createHmac } from 'node:crypto';
import { z } from 'zod';
import { hashArtifact } from './security.ts';

const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/), hex = z.string().regex(/^[a-f0-9]{64}$/);
const alias = z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,79}$/);
export const filesystemSourceSchema = z.object({ sourceRootId: id, sourceEvidenceHash: hex, sourceExpiresAt: z.string().datetime(), templateSourceHash: hex, templateImage: z.string().regex(/^registry:5000\/connectors\/filesystem@sha256:[a-f0-9]{64}$/), qualificationReportHash: hex }).strict();
export type FilesystemSource = z.infer<typeof filesystemSourceSchema>;
export const filesystemSourcesSchema = z.object({ schemaVersion: z.literal(1), appId: id, sources: z.array(filesystemSourceSchema).max(32) }).strict();
export const filesystemScopeSchema = filesystemSourceSchema.extend({ appId: id, connectionId: id, type: z.literal('filesystem'), root: alias, accessExpiresAt: z.string().datetime(), registryHash: hex }).strict();
export type FilesystemScope = z.infer<typeof filesystemScopeSchema>;
export const filesystemArtifactHash = (scope: FilesystemScope): string => hashArtifact({ schemaVersion: 1, action: 'approve_readonly_filesystem', scope });
export type FilesystemProvisionRequest = { schemaVersion: 1; action: 'approve_readonly_filesystem'; operationId: string; approvalId: string; artifactHash: string; scope: FilesystemScope; approvedAt: string; principal: { id: string; mfa: boolean; localOwner: boolean } };
const provisionSchema = z.object({ schemaVersion: z.literal(1), action: z.literal('approve_readonly_filesystem'), operationId: id, approvalId: id, artifactHash: hex, scope: filesystemScopeSchema, approvedAt: z.string().datetime(), principal: z.object({ id, mfa: z.boolean(), localOwner: z.boolean() }).strict() }).strict();
export const filesystemStatusSchema = z.object({ schemaVersion: z.literal(1), type: z.literal('filesystem'), status: z.enum(['configured', 'unknown']), operationId: id, approvalId: id, appId: id, connectionId: id, artifactHash: hex, scopeHash: hex.optional(), liveRootVerified: z.literal(false) }).strict();
export type FilesystemStatus = z.infer<typeof filesystemStatusSchema>;
export type FilesystemOperationIdentity = { operationId: string; approvalId: string; appId: string; connectionId: string; artifactHash: string };
/** Company-scoped execution contract. Metadata never authorizes an adapter. */
export class AdapterBrokerClient {
  private readonly transport: TrustedBrokerHttp;
  constructor(private readonly config: { url: string; token: string; approvalKey: Buffer | string; fetch?: typeof fetch }) {
    this.transport = new TrustedBrokerHttp(config);
  }
  private async call(route: string, value: unknown, signed = false): Promise<unknown> {
    const body = JSON.stringify(value), key = typeof this.config.approvalKey === 'string' ? Buffer.from(this.config.approvalKey, 'base64') : this.config.approvalKey;
    if (signed && key.length !== 32) throw new Error('Adapter proof key must contain 32 bytes.');
    return this.transport.post(route, body, signed ? { 'x-autosoft-proof': createHmac('sha256', key).update(body).digest('hex') } : {}, 300000, 65536);
  }
  async filesystemSources(appId: string): Promise<z.infer<typeof filesystemSourcesSchema>> { id.parse(appId); const value = filesystemSourcesSchema.parse(await this.call('/v1/connectors/filesystem/sources', { appId })); if (value.appId !== appId || new Set(value.sources.map(item => item.sourceRootId)).size !== value.sources.length) throw new Error('Filesystem source evidence belongs to another scope or is duplicated.'); return value; }
  async provisionFilesystem(input: FilesystemProvisionRequest): Promise<FilesystemStatus> { provisionSchema.parse(input); return filesystemStatusSchema.parse(await this.call('/v1/connectors/filesystem/provision', input, true)); }
  async filesystemStatus(input: FilesystemOperationIdentity): Promise<FilesystemStatus> { return filesystemStatusSchema.parse(await this.call('/v1/connectors/filesystem/status', input)); }
}
