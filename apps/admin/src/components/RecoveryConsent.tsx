import { History, ShieldCheck } from 'lucide-react';
import type { RecoveryGrant } from '../types';
import { formatDate } from './ui';

export type RecoveryGrantDraft = Omit<RecoveryGrant, 'approvedBy' | 'approvedAt' | 'publicationOperationId'> & {
  approvedBy: string | null; approvedAt: string | null; publicationOperationId: string | null;
};

export function RecoveryOptIn({ checked, disabled, onChange }: { checked: boolean; disabled: boolean; onChange: (value: boolean) => void }) {
  return <div className="recovery-consent"><label className="checkbox-label"><input type="checkbox" checked={checked} onChange={event => onChange(event.target.checked)} disabled={disabled} /><span><strong>Allow automatic recovery to the exact previous eligible release</strong><small>Optional permission for 30 days after this review. A later health failure may trigger recovery only after fresh security, tests, and database compatibility checks. Business data is preserved.</small></span></label></div>;
}

export function RecoveryDisclosure({ grant, targetVersion }: { grant: RecoveryGrantDraft; targetVersion?: string }) {
  return <section className="recovery-disclosure" aria-label="Exact automatic recovery authorization"><div className="recovery-disclosure-heading"><History size={18} /><h3>Review automatic recovery permission</h3></div><p>If this published release becomes unhealthy, AutoSoft may return to <strong>{targetVersion ?? grant.targetReleaseId}</strong> using only the exact artifacts below. This permission does not authorize a database restore, identity-policy change, or another release.</p><dl className="detail-grid approval-details"><div><dt>Exact recovery release</dt><dd><code>{grant.targetReleaseId}</code></dd></div><div><dt>Recovery permission expires</dt><dd>{formatDate(grant.expiresAt, true)}</dd></div><div><dt>Recovery artifact</dt><dd><code>{grant.targetArtifactHash}</code></dd></div><div><dt>Reviewed database schema</dt><dd>{grant.currentSchemaVersion}</dd></div><div><dt>Exact recovery image</dt><dd>{grant.targetImages.map(image => <code key={image}>{image}</code>)}</dd></div><div><dt>Reviewed authorization</dt><dd><code>{grant.authorizationHash}</code></dd></div></dl><p className="recovery-boundary"><ShieldCheck size={16} />Current tests, fresh security evidence, and schema compatibility are checked again when recovery runs. Unknown findings, blocked security evidence, or failed health checks prevent recovery. Business data is kept.</p></section>;
}

export function recoveryApprovalBody(artifactHash: string, enabled: boolean, grant?: RecoveryGrantDraft) {
  if (!enabled) {
    if (grant) throw new Error('An unrequested recovery grant was returned. Generate a new publication review.');
    return { artifactHash };
  }
  if (!grant || !/^[a-f0-9]{64}$/.test(grant.authorizationHash) || grant.failedArtifactHash !== artifactHash) throw new Error('The exact automatic recovery authorization is missing or changed. Generate a new review.');
  return { artifactHash, authorizationHash: grant.authorizationHash };
}
