import { ShieldAlert } from 'lucide-react';
import type { AppRecord, ApprovalRecord, Principal, ReleaseRecord, SecurityReport } from '../types';
import { Badge, formatDate } from './ui';

export type EmergencyReview = { allowed: boolean; reasons: string[]; findings: { severity: string; detail: string }[]; checkedAt: string; feedUpdatedAt: string };
export function canRequestEmergencyRollback(principal?: Principal | null): boolean {
  return principal?.localOwner === true && principal.mfa === true && principal.roles.includes('platform-owner');
}

// The approval's server-generated impact is release-specific. The ordinary
// security overview aggregates findings by app, so never use it to assign a
// different historical release's findings to this exact emergency action.
export function reviewEmergencyRollback(input: { principal?: Principal | null; app: AppRecord; release: ReleaseRecord; approval: ApprovalRecord; security: SecurityReport; now?: number }): EmergencyReview {
  const { principal, app, release, approval, security } = input, now = input.now ?? Date.now();
  const reasons: string[] = [];
  if (!canRequestEmergencyRollback(principal)) reasons.push('The permanent local platform owner must sign in with MFA.');
  if (app.id !== release.appId || app.activeReleaseId === release.id || !['published', 'superseded'].includes(release.status)) reasons.push('Emergency rollback requires an exact previously published release of this application.');
  if (approval.action !== 'emergency_rollback' || approval.appId !== app.id || approval.releaseId !== release.id || approval.artifactHash !== release.artifactHash || !/^[a-f0-9]{64}$/.test(approval.artifactHash)) reasons.push('The emergency approval does not match this exact action and release artifact.');
  if (!Number.isFinite(Date.parse(approval.expiresAt)) || Date.parse(approval.expiresAt) <= now || approval.consumedAt || approval.approvedAt) reasons.push('This emergency review is expired or already used. Prepare a new review.');
  if (release.evidence.status !== 'passed') reasons.push('Original application verification must have passed.');
  const validOverview = Array.isArray(security?.scans);
  if (!validOverview) reasons.push('The security overview is unavailable or malformed.');
  const scans = validOverview ? security.scans.filter(scan => scan && scan.releaseId === release.id) : [];
  const scan = scans[0];
  if (scans.length > 1 || scan && scan.appId !== app.id) reasons.push('Current security evidence belongs to an ambiguous or different application scope.');
  const coverage = scan ? scan.coverage : release.evidence.checks;
  if (!Array.isArray(coverage) || !coverage.length || new Set(coverage.map(check => check?.name)).size !== coverage.length || coverage.some(check => !check || typeof check.name !== 'string' || !check.name || ('status' in check ? check.status !== 'passed' : check.passed !== true))) reasons.push('Missing, failed or unavailable security coverage cannot be overridden.');
  if (scan && (!['passed', 'failed'].includes(scan.status) || scan.stale)) reasons.push('Current security scanning is unavailable or stale.');
  const checkedAt = scan?.checkedAt ?? release.evidence.checkedAt, feedUpdatedAt = scan?.feedUpdatedAt ?? release.evidence.feedUpdatedAt;
  for (const [label, value] of [['security scan', checkedAt], ['vulnerability feed', feedUpdatedAt]] as const) {
    const time = Date.parse(value);
    if (!Number.isFinite(time) || time > now + 60000 || now - time > 86400000) reasons.push(`The ${label} must be fresh before emergency approval.`);
  }
  const findings = (Array.isArray(approval.impact) ? approval.impact : []).flatMap(impact => {
    if (typeof impact !== 'string') return [];
    const match = /^Known (UNKNOWN|MEDIUM|HIGH|CRITICAL) vulnerability: (.+)$/.exec(impact);
    return match ? [{ severity: match[1]!, detail: match[2]! }] : [];
  });
  if (!findings.length || !findings.some(finding => ['MEDIUM', 'HIGH', 'CRITICAL'].includes(finding.severity))) reasons.push('The server must identify the exact known Medium-or-higher findings for this emergency review.');
  if (findings.some(finding => finding.severity === 'UNKNOWN')) reasons.push('Unclassified findings cannot be overridden by emergency rollback.');
  return { allowed: reasons.length === 0, reasons, findings, checkedAt, feedUpdatedAt };
}

export function EmergencyRollbackDisclosure({ review }: { review: EmergencyReview }) {
  return <section className="destructive-review" aria-label="Emergency rollback security review"><h3><ShieldAlert size={18} />Known security risk</h3><p>This action restores application code with known security vulnerabilities. Review each exact finding below. Existing business data and access policy are preserved; this does not restore a database backup.</p>
    {review.findings.length ? <ul className="impact-list">{review.findings.map((finding, index) => <li key={index}><Badge tone="red">{finding.severity}</Badge><span>{finding.detail}</span></li>)}</ul> : <p>No release-specific vulnerability findings were supplied. Approval is blocked.</p>}
    <dl className="detail-grid"><div><dt>Current security scan</dt><dd>{formatDate(review.checkedAt, true)}</dd></div><div><dt>Current vulnerability feed</dt><dd>{formatDate(review.feedUpdatedAt, true)}</dd></div></dl>
    <p>The runtime scans the exact image again. Changed findings require a new owner approval. Missing coverage, unknown severity and stale feeds cannot be bypassed.</p>
    {!review.allowed && <ul className="impact-list">{review.reasons.map((reason, index) => <li key={index}>{reason}</li>)}</ul>}
  </section>;
}

export function EmergencyRiskAcknowledgment({ checked, disabled, onChange }: { checked: boolean; disabled: boolean; onChange: (value: boolean) => void }) {
  return <label className="checkbox-label approval-check"><input type="checkbox" checked={checked} onChange={event => onChange(event.target.checked)} disabled={disabled} />As the permanent local owner, I accept the exact known security findings above for this emergency rollback.</label>;
}
