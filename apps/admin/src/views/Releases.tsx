import { ArrowUpRight, CheckCircle2, ExternalLink, GitCommitHorizontal, History, Layers3, LockKeyhole, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { AppRecord, Principal, ReleaseAction, ReleaseRecord } from '../types';
import { safeUrl } from '../api';
import { Badge, EmptyState, ErrorBanner, Loading, formatDate, humanize, stageTone } from '../components/ui';
import { canRequestEmergencyRollback } from '../components/EmergencyRollback';

export default function Releases({ app, releases, loading, error, onRetry, onReview, principal }: {
  app?: AppRecord; releases: ReleaseRecord[]; loading: boolean; error?: string; onRetry: () => void; principal?: Principal | null;
  onReview: (release: ReleaseRecord, action: ReleaseAction) => void;
}) {
  if (!app) return <EmptyState icon={Layers3} title="A home for every version">Select or create an application to see its previews, verified releases, and publishing history.</EmptyState>;
  const previewUrl = safeUrl(app.previewUrl) ? `/api/v1/apps/${encodeURIComponent(app.id)}/preview-launch` : undefined;
  const appUrl = safeUrl(app.url);
  return <section className="workspace-page">
    <div className="page-heading"><div><p className="eyebrow">RELEASE MANAGEMENT</p><h1>Your software, with a history.</h1><p>Review what changed. Publish with confidence. Return to a compatible version.</p></div>{appUrl && <a href={appUrl} className="button button-secondary" target="_blank" rel="noopener noreferrer">Open application <ArrowUpRight size={16} /></a>}</div>
    <div className="info-strip"><ShieldCheck size={19} /><p>Publishing is tied to the exact release you approve. Rollback compatibility and data safety are checked before deployment.</p></div>
    <details className="release-details"><summary>How to release an app safely</summary><div className="release-detail-content"><ol><li>Open the current preview and try the tasks your team will use.</li><li>Choose <strong>Review &amp; publish</strong>, read the changes and their data impact, then approve if they match your request.</li><li>Wait for <strong>Live version</strong>. Use <strong>Open application</strong> to share the app link, and manage its users in <strong>Access</strong>.</li></ol><p>App accounts are separate from platform administration. Local users need an invitation even when you are signed in as the platform owner.</p><p>A code rollback returns to a compatible app version. Restoring older data is a separate operation and can lose newer records.</p></div></details>
    {error && <ErrorBanner message={error} onRetry={onRetry} />}
    {loading && releases.length === 0 ? <Loading label="Loading releases…" /> : releases.length === 0 ? <EmptyState icon={History} title="Your first release starts with a conversation">Describe your application in the chat. A release will appear here when the build produces a version you can review.</EmptyState> : <div className="release-list">{releases.map(release => {
      const active = app.activeReleaseId === release.id;
      const currentPreview = app.previewReleaseId === release.id;
      const passed = release.evidence.status === 'passed';
      const destructive = release.migrations.filter(migration => migration.destructive);
      const checks = release.evidence.checks;
      const canPublish = !active && currentPreview && ['preview', 'ready'].includes(release.status) && passed;
      const canRollback = !active && ['superseded', 'published'].includes(release.status);
      return <article className={`release-card ${active ? 'release-active' : ''}`} key={release.id}>
        <div className="release-top"><div className="release-version"><span className="release-symbol"><Layers3 size={20} /></span><div><h2>{release.version}</h2><span>{formatDate(release.createdAt, true)}</span></div></div><div className="badge-group">{active && <Badge tone="green" dot>Live version</Badge>}<Badge tone={stageTone(release.status)}>{humanize(release.status)}</Badge></div></div>
        <p className="release-summary">{release.summary || 'No release summary was recorded.'}</p>
        <div className="release-evidence"><span className={`evidence-label ${passed ? 'evidence-passed' : 'evidence-warning'}`}>{passed ? <ShieldCheck size={17} /> : <ShieldAlert size={17} />}{passed ? 'Verification passed' : release.evidence.status === 'unavailable' ? 'Verification unavailable' : 'Verification failed'}</span><span>{checks.filter(check => check.passed).length} / {checks.length} checks passed</span><span><GitCommitHorizontal size={15} />{release.commit ? release.commit.slice(0, 10) : 'Commit not recorded'}</span></div>
        <details className="release-details"><summary>Evidence and changes</summary><div className="release-detail-content"><dl className="detail-grid"><div><dt>Artifact digest</dt><dd><code>{release.artifactHash}</code></dd></div><div><dt>Schema compatibility</dt><dd>{release.compatibleSchemaMin}–{release.compatibleSchemaMax} · schema {release.schemaVersion}</dd></div><div><dt>Checked</dt><dd>{formatDate(release.evidence.checkedAt, true)}</dd></div><div><dt>Security feed</dt><dd>{formatDate(release.evidence.feedUpdatedAt, true)}</dd></div></dl>
          {checks.length > 0 && <ul className="check-list">{checks.map((check, index) => <li key={`${check.name}-${index}`}>{check.passed ? <CheckCircle2 size={16} className="color-green" /> : <ShieldAlert size={16} className="color-amber" />}<div><strong>{check.name}</strong><p>{check.detail}</p></div></li>)}</ul>}
          {release.evidence.findings.length > 0 && <div className="release-findings"><h3>Reported security findings</h3>{release.evidence.findings.map(finding => <p key={finding.id}><Badge tone={stageTone(finding.severity)}>{finding.severity}</Badge><strong>{finding.package}</strong><span>{finding.description}</span></p>)}</div>}
          {release.migrations.length > 0 && <div className="migration-list"><h3>Database changes</h3>{release.migrations.map(migration => <div key={migration.id}><Badge tone={migration.destructive ? 'red' : 'neutral'}>{migration.destructive ? 'Destructive' : 'Migration'}</Badge><p>{migration.impact}</p></div>)}</div>}
          {release.images.length > 0 && <div><h3>Container images</h3>{release.images.map(image => <code className="image-digest" key={image}>{image}</code>)}</div>}
        </div></details>
        {destructive.length > 0 && <div className="destructive-note"><ShieldAlert size={17} /><span>This release includes destructive database changes. Review the exact impact; publication requires a valid recovery checkpoint.</span></div>}
        <div className="release-footer"><span><LockKeyhole size={14} />{active && release.publishedAt ? `Published ${formatDate(release.publishedAt, true)}` : 'Approval required before deployment'}</span><div className="button-row">{previewUrl && currentPreview && !active && ['preview', 'ready'].includes(release.status) && <a className="button button-secondary button-small" href={`${previewUrl}?releaseId=${encodeURIComponent(release.id)}`} target="_blank" rel="noopener noreferrer"><ExternalLink size={14} />Preview</a>}{canPublish && <button className="button button-primary button-small" onClick={() => onReview(release, 'publish')}>Review & publish <ArrowUpRight size={14} /></button>}{canRollback && <button className="button button-secondary button-small" onClick={() => onReview(release, 'rollback')}><History size={14} />Review rollback</button>}{canRollback && passed && canRequestEmergencyRollback(principal) && <button className="button button-danger button-small" onClick={() => onReview(release, 'emergency_rollback')}><ShieldAlert size={14} />Review emergency rollback</button>}{!active && !canPublish && !canRollback && <Badge tone="amber">{passed && !currentPreview && ['preview', 'ready'].includes(release.status) ? 'Preview replaced by a newer candidate' : passed ? 'Release is not ready to publish' : 'Verification required'}</Badge>}</div></div>
      </article>;
    })}</div>}
  </section>;
}
