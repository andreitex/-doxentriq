import { TrustedBrokerHttp } from './trusted-broker-http.ts';
import { createHmac } from 'node:crypto';
export type SambaProvisionRequest = { schemaVersion: 1; action: 'approve_readonly_samba'; approvalId: string; appId: string; connectionId: string; type: 'samba'; serverIp: string; share: string; root: string; readonlyAclEvidenceSha256: string; approvedAt: string; expiresAt: string; principal: { id: string; mfa: boolean; localOwner: boolean }; credentials: { username: string; password: string } };
export type ConnectorStatus = { status: 'configured' | 'unknown'; appId: string; connectionId: string; approvalId: string; scopeHash?: string; liveShareVerified: false };
export class ConnectorBrokerClient {
  private readonly transport: TrustedBrokerHttp;
  constructor(private readonly config: { url: string; token: string; approvalKey: Buffer | string; fetch?: typeof fetch }) {
    this.transport = new TrustedBrokerHttp(config);
  }
  private async call<T>(route: string, value: unknown, signed = false): Promise<T> {
    const body = JSON.stringify(value), key = typeof this.config.approvalKey === 'string' ? Buffer.from(this.config.approvalKey, 'base64') : this.config.approvalKey;
    if (signed && key.length !== 32) throw new Error('Connector approval proof key must contain 32 bytes.');
    return this.transport.post<T>(route, body, signed ? { 'x-autosoft-proof': createHmac('sha256', key).update(body).digest('hex') } : {}, 300000, 65536);
  }
  provision(input: SambaProvisionRequest): Promise<ConnectorStatus> { return this.call('/v1/connectors/provision', input, true); }
  status(input: { appId: string; connectionId: string; approvalId: string }): Promise<ConnectorStatus> { return this.call('/v1/connectors/status', input); }
}
