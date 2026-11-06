import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, ArrowRight, ArrowUpRight, Bell, Cable, Check, ChevronDown, ChevronRight, CircleHelp, Code2, FolderOpen, History, Layers3, LockKeyhole, Menu, MessageSquare, Plus, Search, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import type { AppRecord, ApprovalRecord, Budget, ConnectionRecord, Finding, JobRecord, NotificationRecord, Principal, ReleaseAction, ReleaseRecord, SecurityReport, Session, Telemetry as TelemetryData } from './types';
import { ApiError, api, errorMessage, releaseApprovalRequestBody, releaseDispatchRequest, safeUrl, setCsrfToken } from './api';
import { useJob, useResource } from './hooks';
import { Badge, EmptyState, ErrorBanner, Loading, Modal, formatDate, humanize, money, stageTone } from './components/ui';
import Chat from './views/Chat';
import Releases from './views/Releases';
import Connections from './views/Connections';
import Security from './views/Security';
import Telemetry from './views/Telemetry';
import BudgetApproval from './components/BudgetApproval';
import Access from './views/Access';
import { RecoveryDisclosure, RecoveryOptIn, recoveryApprovalBody, type RecoveryGrantDraft } from './components/RecoveryConsent';
import { canRequestEmergencyRollback, EmergencyRiskAcknowledgment, EmergencyRollbackDisclosure, reviewEmergencyRollback } from './components/EmergencyRollback';

type View = 'chat' | 'releases' | 'access' | 'connections' | 'security' | 'telemetry';
const views: { id: View; label: string; icon: typeof Activity }[] = [
  { id: 'chat', label: 'Conversation', icon: MessageSquare }, { id: 'releases', label: 'Releases', icon: History },
  { id: 'access', label: 'Access', icon: LockKeyhole }, { id: 'connections', label: 'Connections', icon: Cable }, { id: 'security', label: 'Security', icon: ShieldCheck }, { id: 'telemetry', label: 'Telemetry', icon: Activity }
];
const initialQuery = new URLSearchParams(window.location.search);

function Brand({ compact = false }: { compact?: boolean }) {
  return <div className={`brand ${compact ? 'brand-compact' : ''}`}><span className="brand-mark"><Layers3 size={21} strokeWidth={1.8} /></span><span>Doxentriq<span className="brand-period">.</span></span></div>;
}

function NewAppDialog({ request, busy, error, onCreate, onClose }: {
  request?: string; busy: boolean; error?: string; onCreate: (data: { name: string; description: string; kind: AppRecord['kind'] }) => Promise<void>; onClose: () => void;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState(request ?? '');
  const [kind, setKind] = useState<AppRecord['kind']>('web');
  return <Modal title="Give your idea a home" description="Create an application workspace for its code, conversations, and releases." onClose={onClose} busy={busy}><form className="form-stack" onSubmit={event => { event.preventDefault(); if (name.trim()) void onCreate({ name: name.trim(), description: description.trim(), kind }); }}>
    {error && <ErrorBanner message={error} />}<label>Application name<input data-autofocus placeholder="e.g. Team documents" value={name} onChange={event => setName(event.target.value)} required maxLength={100} disabled={busy} /></label><label>Description<textarea placeholder="What should this application help people do?" value={description} onChange={event => setDescription(event.target.value)} rows={4} maxLength={8000} disabled={busy} /></label><label>Application type<select value={kind} onChange={event => setKind(event.target.value as AppRecord['kind'])} disabled={busy}><option value="web">Web application</option><option value="api">API service</option><option value="worker">Background worker</option><option value="mcp">MCP server</option></select></label>{request && <div className="info-strip"><MessageSquare size={18} /><p>Your request will start after the workspace is created.</p></div>}<div className="modal-actions"><button className="button button-secondary" type="button" onClick={onClose} disabled={busy}>Cancel</button><button className="button button-primary" type="submit" disabled={busy || !name.trim()}>{busy ? 'Creating…' : request ? 'Create & start request' : 'Create application'}<ArrowRight size={16} /></button></div>
  </form></Modal>;
}

function ApprovalDialog({ release, action, app, releases, principal, onClose, onDone }: {
  release: ReleaseRecord; action: ReleaseAction; app: AppRecord; releases: ReleaseRecord[]; principal: Principal; onClose: () => void; onDone: (message: string) => void;
}) {
  const [approval, setApproval] = useState<ApprovalRecord>();
  const [automaticRecovery, setAutomaticRecovery] = useState(false);
  const [recoveryGrant, setRecoveryGrant] = useState<RecoveryGrantDraft>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [reviewed, setReviewed] = useState(false);
  const [approved, setApproved] = useState(false);
  const [deploymentFailed, setDeploymentFailed] = useState(false);
  const [emergencySecurity, setEmergencySecurity] = useState<SecurityReport>();
  const [riskAccepted, setRiskAccepted] = useState(false);
  const [now, setNow] = useState(Date.now());
  const reviewGeneration = useRef(0);
  const prepare = useCallback(async () => {
    const generation = ++reviewGeneration.current;
    setLoading(true); setError(undefined); setReviewed(false); setApproved(false); setDeploymentFailed(false); setApproval(undefined); setRecoveryGrant(undefined); setEmergencySecurity(undefined); setRiskAccepted(false);
    try {
      if (action === 'emergency_rollback' && !canRequestEmergencyRollback(principal)) throw new Error('Emergency rollback requires the permanent local platform owner with MFA.');
      const security = action === 'emergency_rollback' ? await api<SecurityReport>('/security') : undefined;
      const response = await api<{ approval: ApprovalRecord; recoveryGrant?: RecoveryGrantDraft }>(`/releases/${encodeURIComponent(release.id)}/approval`, { method: 'POST', body: releaseApprovalRequestBody(action, automaticRecovery) });
      if (generation !== reviewGeneration.current) return;
      releaseDispatchRequest(app, release, response.approval, action);
      recoveryApprovalBody(response.approval.artifactHash, automaticRecovery, response.recoveryGrant);
      if (response.recoveryGrant && (response.recoveryGrant.appId !== app.id || response.recoveryGrant.failedReleaseId !== release.id || response.recoveryGrant.publicationApprovalId !== response.approval.id || response.recoveryGrant.targetReleaseId !== app.activeReleaseId || !Number.isFinite(Date.parse(response.recoveryGrant.expiresAt)) || Date.parse(response.recoveryGrant.expiresAt) <= Date.now())) throw new Error('The automatic recovery grant does not match this application, publication, and previous release. Generate a new review.');
      setApproval(response.approval);
      setRecoveryGrant(response.recoveryGrant);
      setEmergencySecurity(security);
    } catch (failure) { if (generation === reviewGeneration.current) setError(errorMessage(failure)); } finally { if (generation === reviewGeneration.current) setLoading(false); }
  }, [release.id, release.artifactHash, action, automaticRecovery, app.id, app.activeReleaseId, principal.id, principal.localOwner, principal.mfa, principal.roles.join(',')]);
  useEffect(() => { void prepare(); return () => { reviewGeneration.current++; }; }, [prepare]);
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 5000); return () => clearInterval(timer); }, []);
  const expired = approval ? new Date(approval.expiresAt).getTime() <= now || (!!recoveryGrant && new Date(recoveryGrant.expiresAt).getTime() <= now) : false;
  const recoveryReady = !automaticRecovery || (!!recoveryGrant && recoveryGrant.targetReleaseId === app.activeReleaseId);
  const emergencyReview = action === 'emergency_rollback' && approval && emergencySecurity ? reviewEmergencyRollback({ principal, app, release, approval, security: emergencySecurity, now }) : undefined;
  const emergencyReady = action !== 'emergency_rollback' || !!emergencyReview?.allowed && riskAccepted;
  const perform = async () => {
    if (!approval || !reviewed || expired || busy || !recoveryReady || !emergencyReady) return;
    setBusy(true); setError(undefined);
    try {
      if (!approved) {
        const response = await api<{ approval: ApprovalRecord }>(`/approvals/${encodeURIComponent(approval.id)}/approve`, { method: 'POST', body: recoveryApprovalBody(approval.artifactHash, automaticRecovery, recoveryGrant) });
        releaseDispatchRequest(app, release, response.approval, action);
        if (response.approval.id !== approval.id || response.approval.approvedBy !== principal.id || !response.approval.approvedAt || response.approval.consumedAt) throw new Error('The server did not confirm this exact approval. Inspect release status and prepare a new review.');
        setApproved(true);
      }
      try {
        const dispatch = releaseDispatchRequest(app, release, approval, action);
        await api(dispatch.path, { method: 'POST', body: dispatch.body });
      } catch (failure) { setDeploymentFailed(true); throw failure; }
      onDone(`${action === 'publish' ? 'Publish' : action === 'emergency_rollback' ? 'Emergency rollback' : 'Rollback'} request accepted. Release status is being refreshed.`); onClose();
    } catch (failure) { setError(errorMessage(failure)); } finally { setBusy(false); }
  };
  return <Modal title={action === 'publish' ? 'Review before publishing' : action === 'emergency_rollback' ? 'Review emergency rollback' : 'Review before rolling back'} description={`${app.name} · ${release.version}`} onClose={onClose} busy={busy || loading} wide>
    {error && <ErrorBanner message={error} />}
    {action === 'publish' && app.activeReleaseId && <RecoveryOptIn checked={automaticRecovery} disabled={busy || loading || approved} onChange={setAutomaticRecovery} />}
    {loading ? <Loading label="Checking release policy and preparing an approval…" /> : approval ? <div className="approval-content">
      <div className="approval-release"><span className="neutral-icon"><Layers3 size={23} /></span><div><strong>{release.version}</strong><p>{release.summary || 'No summary was recorded.'}</p></div><Badge tone={stageTone(release.evidence.status)}>{humanize(release.evidence.status)}</Badge></div>
      <h3>What this action will change</h3>{approval.impact.length > 0 ? <ul className="impact-list">{approval.impact.map((impact, index) => <li key={index}><ChevronRight size={15} /><span>{impact}</span></li>)}</ul> : <p className="muted">The server did not report additional impact details.</p>}
      {emergencyReview && <EmergencyRollbackDisclosure review={emergencyReview} />}
      {release.migrations.some(migration => migration.destructive) && <div className="destructive-review"><h3><ShieldAlert size={18} />Destructive database changes</h3>{release.migrations.filter(migration => migration.destructive).map(migration => <p key={migration.id}>{migration.impact}</p>)}<p><strong>Recovery checkpoint:</strong> {approval.checkpointId ?? 'Not recorded. The server must allow this operation before it can proceed.'}</p></div>}
      <dl className="detail-grid approval-details"><div><dt>Approved artifact</dt><dd><code>{approval.artifactHash}</code></dd></div><div><dt>Approval expires</dt><dd>{formatDate(approval.expiresAt, true)}</dd></div><div><dt>Security checked</dt><dd>{formatDate(release.evidence.checkedAt, true)}</dd></div><div><dt>Recovery checkpoint</dt><dd>{approval.checkpointId ?? 'Not reported'}</dd></div></dl>
      {automaticRecovery && recoveryGrant && <RecoveryDisclosure grant={recoveryGrant} targetVersion={releases.find(item => item.id === recoveryGrant.targetReleaseId)?.version} />}
      {action === 'emergency_rollback' && <EmergencyRiskAcknowledgment checked={riskAccepted} onChange={setRiskAccepted} disabled={busy || !emergencyReview?.allowed} />}
      {expired || deploymentFailed || action === 'emergency_rollback' && !emergencyReview?.allowed ? <div className="info-strip info-strip-warning"><LockKeyhole size={18} /><p>{expired ? 'This review has expired. Generate a new review before continuing.' : deploymentFailed ? 'Inspect the reported deployment issue and current release status before retrying. A retry requires a new review.' : 'Emergency rollback is blocked by the evidence above. Resolve the issue and generate a new review.'}</p><button className="text-button" onClick={() => { void prepare(); }}>New review</button></div> : <label className="checkbox-label approval-check"><input type="checkbox" checked={reviewed} onChange={event => setReviewed(event.target.checked)} disabled={busy || !recoveryReady || !emergencyReady} />I reviewed the changes above and approve this {action === 'publish' ? automaticRecovery ? 'publication and its exact automatic recovery permission' : 'publication' : action === 'emergency_rollback' ? 'exact emergency rollback' : 'rollback'}.</label>}
      <div className="modal-actions"><button className="button button-secondary" onClick={onClose} disabled={busy}>Cancel</button><button className={`button ${action === 'emergency_rollback' ? 'button-danger' : 'button-primary'}`} onClick={() => { void perform(); }} disabled={!reviewed || expired || deploymentFailed || busy || !recoveryReady || !emergencyReady}>{busy ? 'Submitting…' : action === 'publish' ? 'Approve & publish' : action === 'emergency_rollback' ? 'Approve emergency rollback' : 'Approve & roll back'}<Check size={16} /></button></div>
    </div> : <div className="approval-unavailable"><p className="muted">This release cannot be approved yet. Resolve the reported issue and request another review.</p><div className="modal-actions"><button className="button button-secondary" onClick={onClose}>Close</button><button className="button button-primary" onClick={() => { void prepare(); }}>Try review again</button></div></div>}
  </Modal>;
}

export default function App() {
  const [session, setSession] = useState<Session>();
  const [sessionError, setSessionError] = useState<string>();
  const [sessionLoading, setSessionLoading] = useState(true);
  const [selectedAppId, setSelectedAppId] = useState<string | null>(initialQuery.get('app'));
  const [selectedJobId, setSelectedJobId] = useState<string | null>(initialQuery.get('job'));
  const [autoSelectJob, setAutoSelectJob] = useState(true);
  const [view, setView] = useState<View>(views.some(item => item.id === initialQuery.get('view')) ? initialQuery.get('view') as View : 'chat');
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [search, setSearch] = useState('');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [createDialog, setCreateDialog] = useState<{ request?: string; budgetUsd?: number } | null>(null);
  const [createError, setCreateError] = useState<string>();
  const [createdApp, setCreatedApp] = useState<AppRecord>();
  const [review, setReview] = useState<{ release: ReleaseRecord; action: ReleaseAction }>();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showAccount, setShowAccount] = useState(false);
  const [accountError, setAccountError] = useState<string>();
  const [showHelp, setShowHelp] = useState(false);
  const [cancelDialog, setCancelDialog] = useState(false);
  const [budgetReview, setBudgetReview] = useState<{ kind: 'job' | 'monthly'; jobId?: string; oldLimit: number; newLimit: number }>();

  const loadSession = useCallback(async () => {
    setSessionLoading(true); setSessionError(undefined);
    try { const data = await api<Session>('/session'); setCsrfToken(data.csrfToken); setSession(data); }
    catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) setSession({ principal: null, csrfToken: '', mode: 'production' });
      else setSessionError(errorMessage(failure));
    } finally { setSessionLoading(false); }
  }, []);
  useEffect(() => {
    void loadSession();
    const expired = () => { setCsrfToken(''); setSession(previous => ({ principal: null, csrfToken: '', mode: previous?.mode ?? 'production' })); };
    window.addEventListener('autosoft:session-expired', expired);
    return () => window.removeEventListener('autosoft:session-expired', expired);
  }, [loadSession]);
  const signedIn = Boolean(session?.principal);
  const appsResource = useResource<{ apps: AppRecord[] }>(signedIn ? '/apps' : null);
  const jobsResource = useResource<{ jobs: JobRecord[] }>(signedIn && selectedAppId ? `/apps/${encodeURIComponent(selectedAppId)}/jobs` : null);
  const releasesResource = useResource<{ releases: ReleaseRecord[] }>(signedIn && selectedAppId ? `/apps/${encodeURIComponent(selectedAppId)}/releases` : null);
  const connectionsResource = useResource<{ connections: ConnectionRecord[] }>(signedIn && view === 'connections' ? '/connections' : null);
  const telemetryResource = useResource<TelemetryData>(signedIn && view === 'telemetry' ? '/telemetry' : null);
  const securityResource = useResource<SecurityReport>(signedIn && view === 'security' ? '/security' : null);
  const notificationsResource = useResource<{ notifications: NotificationRecord[] }>(signedIn ? '/notifications' : null);
  const budgetResource = useResource<Budget>(signedIn ? '/budget' : null);
  const currentJob = useJob(signedIn ? selectedJobId : null);
  const apps = useMemo(() => {
    const records = [...(appsResource.data?.apps ?? [])];
    if (createdApp && !records.some(app => app.id === createdApp.id)) records.push(createdApp);
    return records;
  }, [appsResource.data, createdApp]);
  const app = apps.find(item => item.id === selectedAppId);
  const jobs = useMemo(() => (jobsResource.data?.jobs ?? []).filter(item => item.appId === selectedAppId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)), [jobsResource.data, selectedAppId]);
  const activeRequest = jobs.map(item => item.id === currentJob.job?.id ? currentJob.job : item).find(item => !['completed', 'failed', 'cancelled', 'needs_attention', 'awaiting_approval'].includes(item.stage));
  const releases = useMemo(() => (releasesResource.data?.releases ?? []).filter(item => item.appId === selectedAppId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)), [releasesResource.data, selectedAppId]);
  const draftKey = selectedAppId ?? '$new';
  const draft = drafts[draftKey] ?? '';
  const setDraft = (value: string) => setDrafts(previous => ({ ...previous, [draftKey]: value }));
  useEffect(() => {
    if (!appsResource.data || appsResource.loading) return;
    if (selectedAppId && apps.some(item => item.id === selectedAppId)) return;
    setSelectedAppId(apps[0]?.id ?? null); setSelectedJobId(null); setAutoSelectJob(true);
  }, [appsResource.data, appsResource.loading, apps, selectedAppId]);
  useEffect(() => {
    if (jobsResource.loading || !jobsResource.data) return;
    if (autoSelectJob && !selectedJobId) setSelectedJobId(jobs[0]?.id ?? null);
  }, [jobsResource.data, jobsResource.loading, jobs, autoSelectJob, selectedJobId]);
  useEffect(() => {
    const query = new URLSearchParams();
    if (selectedAppId) query.set('app', selectedAppId);
    if (selectedJobId) query.set('job', selectedJobId);
    if (view !== 'chat') query.set('view', view);
    const suffix = query.toString(); window.history.replaceState(null, '', `${window.location.pathname}${suffix ? `?${suffix}` : ''}`);
  }, [selectedAppId, selectedJobId, view]);
  useEffect(() => {
    if (!currentJob.job) return;
    appsResource.refresh(); jobsResource.refresh();
    if (['preview', 'awaiting_approval', 'completed', 'failed'].includes(currentJob.job.stage)) releasesResource.refresh();
    budgetResource.refresh(); notificationsResource.refresh();
  }, [currentJob.job?.id, currentJob.job?.stage, appsResource.refresh, jobsResource.refresh, releasesResource.refresh, budgetResource.refresh, notificationsResource.refresh]);
  useEffect(() => {
    if (!signedIn || view !== 'telemetry') return;
    const timer = setInterval(() => { telemetryResource.refresh(); budgetResource.refresh(); }, 15000);
    return () => clearInterval(timer);
  }, [signedIn, view, telemetryResource.refresh, budgetResource.refresh]);

  const selectApp = (id: string) => { setSelectedAppId(id); setSelectedJobId(null); setAutoSelectJob(true); setSidebarOpen(false); setError(undefined); };
  const startJob = async (targetApp: AppRecord, request: string, budgetUsd?: number) => {
    const response = await api<{ job: JobRecord }>(`/apps/${encodeURIComponent(targetApp.id)}/jobs`, { method: 'POST', body: { request, ...(budgetUsd !== undefined ? { budgetUsd } : {}) } });
    setSelectedAppId(targetApp.id); setSelectedJobId(response.job.id); setAutoSelectJob(false); setView('chat');
    setDrafts(previous => ({ ...previous, [targetApp.id]: '' })); jobsResource.refresh(); appsResource.refresh(); budgetResource.refresh();
  };
  const send = async (request: string, budgetUsd?: number) => {
    if (!app) { setCreateError(undefined); setCreateDialog({ request, budgetUsd }); return; }
    setBusy(true); setError(undefined);
    try { await startJob(app, request, budgetUsd); } catch (failure) { setError(errorMessage(failure)); } finally { setBusy(false); }
  };
  const create = async (data: { name: string; description: string; kind: AppRecord['kind'] }) => {
    setBusy(true); setCreateError(undefined); setError(undefined);
    try {
      const response = await api<{ app: AppRecord }>('/apps', { method: 'POST', body: data });
      const pending = createDialog;
      setCreatedApp(response.app); setSelectedAppId(response.app.id); setSelectedJobId(null); setAutoSelectJob(false); setView('chat'); setCreateDialog(null); appsResource.refresh();
      if (pending?.request) {
        setDrafts(previous => ({ ...previous, [response.app.id]: pending.request!, $new: '' }));
        try { await startJob(response.app, pending.request, pending.budgetUsd); } catch (failure) { setError(errorMessage(failure)); }
      }
    } catch (failure) { setCreateError(errorMessage(failure)); } finally { setBusy(false); }
  };
  const resume = async (answer: string) => {
    if (!selectedJobId) return false;
    setBusy(true); setError(undefined);
    try { await api(`/jobs/${encodeURIComponent(selectedJobId)}/resume`, { method: 'POST', body: { answer } }); await currentJob.refresh(); jobsResource.refresh(); return true; }
    catch (failure) { setError(errorMessage(failure)); return false; } finally { setBusy(false); }
  };
  const cancel = async () => {
    if (!selectedJobId) return;
    if (currentJob.job && ['deployment', 'observation'].includes(currentJob.job.stage)) {
      setCancelDialog(false); setError('Publication is running and cannot be cancelled. Inspect the release and recorded operation status.'); return;
    }
    setBusy(true); setError(undefined);
    try { await api(`/jobs/${encodeURIComponent(selectedJobId)}/cancel`, { method: 'POST', body: {} }); setCancelDialog(false); await currentJob.refresh(); jobsResource.refresh(); }
    catch (failure) { setError(errorMessage(failure)); } finally { setBusy(false); }
  };
  const fix = (finding: Finding) => {
    const target = apps.find(item => item.id === finding.appId);
    if (!target) return;
    const request = `Investigate security finding ${finding.id} in ${target.name}: ${finding.package} ${finding.installedVersion} (${finding.severity}). ${finding.description}${finding.fixedVersion ? ` The reported fixed version is ${finding.fixedVersion}.` : ''} Prepare a safe fix, verify it, and provide a release for review. Preserve existing application data.`;
    selectApp(target.id); setAutoSelectJob(false); setSelectedJobId(null); setDrafts(previous => ({ ...previous, [target.id]: request })); setView('chat');
  };
  const onDeployment = (message: string) => { setNotice(message); appsResource.refresh(); releasesResource.refresh(); notificationsResource.refresh(); void currentJob.refresh(); };
  const openCreate = () => { setCreateError(undefined); setCreateDialog({}); setSidebarOpen(false); };
  const unread = notificationsResource.data?.notifications.filter(notification => !notification.read).length ?? 0;
  const signOut = async () => {
    setBusy(true); setAccountError(undefined);
    try { await api('/logout', { method: 'POST', body: {} }); setCsrfToken(''); setShowAccount(false); setSession(previous => ({ principal: null, csrfToken: '', mode: previous?.mode ?? 'production' })); }
    catch (failure) { setAccountError(errorMessage(failure)); } finally { setBusy(false); }
  };

  if (sessionLoading && !session) return <div className="session-page"><Brand /><Loading label="Connecting to your workspace…" /></div>;
  if (!signedIn) return <div className="login-page"><div className="login-brand"><Brand /></div><main className="login-card"><span className="welcome-emblem"><LockKeyhole size={30} strokeWidth={1.5} /></span><p className="eyebrow">YOUR APPLICATION WORKSPACE</p><h1>Good ideas deserve<br />great software.</h1><p>Sign in to build, improve, and manage your applications with Doxentriq.</p>{initialQuery.get('signin') === 'mfa' && <div className="info-strip" role="status"><ShieldCheck size={18} /><p>Sign in again with your owner password and an authenticator or recovery code. Completing account enrollment alone does not verify multi-factor authentication.</p></div>}{sessionError && <ErrorBanner message={sessionError} onRetry={() => { void loadSession(); }} />}<a className="button button-primary" href={initialQuery.get('signin') === 'mfa' ? '/auth/login?reauthenticate=1' : '/auth/login'}>Continue to sign in <ArrowRight size={17} /></a><span className="login-note"><ShieldCheck size={15} />Use your organization’s SSO or the local platform owner account.</span></main><p className="login-footer">Build thoughtfully. Release confidently.</p></div>;

  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to main content</a>
    {sidebarOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
    <aside id="workspace-navigation" className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''}`} aria-label="Workspace navigation"><div className="sidebar-top"><Brand /><button className="icon-button sidebar-close" aria-label="Close navigation" onClick={() => setSidebarOpen(false)}><X size={19} /></button></div>
      <button className="new-app-button" onClick={openCreate}><Plus size={18} />New application<span>+</span></button><div className="sidebar-search"><Search size={15} /><input aria-label="Search applications" value={search} onChange={event => setSearch(event.target.value)} placeholder="Find an application…" /></div>
      <div className="sidebar-scroll"><div className="sidebar-section-heading"><span>APPLICATIONS</span><span>{apps.length}</span></div>
        {appsResource.error && <p className="sidebar-error">{appsResource.error}<button onClick={appsResource.refresh}>Retry</button></p>}
        {appsResource.loading && apps.length === 0 ? <Loading label="Loading…" /> : apps.length === 0 ? <div className="sidebar-empty"><FolderOpen size={23} /><p>A workspace for your ideas.</p><span>Your applications will appear here.</span></div> : <nav className="app-list">{apps.filter(item => `${item.name} ${item.description}`.toLowerCase().includes(search.toLowerCase())).map(item => <button key={item.id} className={`app-item ${item.id === selectedAppId ? 'app-item-active' : ''}`} onClick={() => selectApp(item.id)} aria-current={item.id === selectedAppId ? 'page' : undefined}><span className="app-item-icon">{item.kind === 'mcp' || item.kind === 'api' ? <Code2 size={17} /> : <Layers3 size={17} />}</span><span><strong>{item.name}</strong><small>{humanize(item.status)}</small></span><span className={`app-status-dot dot-${item.status}`} /></button>)}</nav>}
        {search && apps.length > 0 && !apps.some(item => `${item.name} ${item.description}`.toLowerCase().includes(search.toLowerCase())) && <p className="sidebar-empty-search">No applications match “{search}”.</p>}
        {app && jobs.length > 0 && <><div className="sidebar-section-heading history-heading"><span>RECENT REQUESTS</span><button className="icon-button" aria-label="Start a new request" onClick={() => { setSelectedJobId(null); setAutoSelectJob(false); setView('chat'); setSidebarOpen(false); }}><Plus size={15} /></button></div><nav className="job-list">{jobs.slice(0, 8).map(item => <button key={item.id} className={item.id === selectedJobId && view === 'chat' ? 'job-active' : ''} onClick={() => { setSelectedJobId(item.id); setAutoSelectJob(false); setView('chat'); setSidebarOpen(false); }} title={item.request}><MessageSquare size={14} /><span>{item.request}</span></button>)}</nav></>}
      </div>
      <div className="sidebar-footer"><button className="sidebar-help" onClick={() => setShowHelp(true)}><CircleHelp size={16} />How it works<ArrowUpRight size={14} /></button><button className="account-button" onClick={() => setShowAccount(true)}><span className="account-avatar">{session!.principal!.name.slice(0, 1).toUpperCase()}</span><span><strong>{session!.principal!.name}</strong><small>{session!.principal!.localOwner ? 'Platform owner' : 'Workspace administrator'}</small></span><ChevronDown size={15} /></button></div>
    </aside>
    <div className="main-shell"><header className="topbar"><div className="workspace-breadcrumb"><button className="icon-button mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation" aria-controls="workspace-navigation" aria-expanded={sidebarOpen}><Menu size={21} /></button><span className="breadcrumb-root">Workspace</span><ChevronRight size={14} /><strong>{app?.name ?? 'Overview'}</strong></div><div className="topbar-actions">{['local', 'development', 'test'].includes(session!.mode) && <Badge tone="amber">Local development</Badge>}{app && <Badge tone={stageTone(app.status)} dot>{humanize(app.status)}</Badge>}<button className="icon-button notification-button" aria-label={`Notifications${unread > 0 ? `, ${unread} unread` : ''}`} onClick={() => { setShowNotifications(true); notificationsResource.refresh(); }}><Bell size={19} />{unread > 0 && <span className="notification-dot" />}</button></div></header>
      <div className="viewbar"><nav aria-label="Workspace sections">{views.map(({ id, label, icon: Icon }) => <button key={id} className={view === id ? 'view-active' : ''} onClick={() => setView(id)} aria-current={view === id ? 'page' : undefined}><Icon size={16} /><span>{label}</span></button>)}</nav>{view === 'chat' && app && <button className="text-button new-request" onClick={() => { setSelectedJobId(null); setAutoSelectJob(false); }}><Plus size={15} />New request</button>}</div>
      {error && <div className="global-message"><ErrorBanner message={error} onDismiss={() => setError(undefined)} /></div>}{notice && <div className="global-message"><div className="notice-banner" role="status"><Check size={17} /><span>{notice}</span><button className="icon-button" aria-label="Dismiss notification" onClick={() => setNotice(undefined)}><X size={16} /></button></div></div>}
      <main id="main-content" className={`main-content ${view === 'chat' ? 'main-chat' : ''}`}>
        {view === 'chat' && <Chat app={app} jobs={jobs} jobsLoading={jobsResource.loading} job={currentJob.job} activeRequest={activeRequest} events={currentJob.events} loading={currentJob.loading} stream={currentJob.stream} error={currentJob.error ?? jobsResource.error} draft={draft} setDraft={setDraft} onSend={send} onResume={resume} onCancel={async () => { setCancelDialog(true); }} onSelectJob={id => { setSelectedJobId(id); setAutoSelectJob(false); }} onViewReleases={() => setView('releases')} onIncreaseBudget={newLimit => { if (currentJob.job) setBudgetReview({ kind: 'job', jobId: currentJob.job.id, oldLimit: currentJob.job.budgetUsd, newLimit }); }} busy={busy} budget={budgetResource.data} />}
        {view === 'releases' && <Releases app={app} principal={session?.principal} releases={releases} loading={releasesResource.loading} error={releasesResource.error} onRetry={releasesResource.refresh} onReview={(release, action) => setReview({ release, action })} />}
        {view === 'connections' && <Connections apps={apps} selectedApp={app} connections={connectionsResource.data?.connections ?? []} loading={connectionsResource.loading} error={connectionsResource.error} onRetry={connectionsResource.refresh} canProvision={session?.principal?.localOwner === true && session.principal.mfa} />}
        {view === 'security' && <Security apps={apps} report={securityResource.data} loading={securityResource.loading} error={securityResource.error} onRetry={securityResource.refresh} onFix={fix} />}
        {view === 'telemetry' && <Telemetry data={telemetryResource.data} budget={budgetResource.data} apps={apps} loading={telemetryResource.loading} error={telemetryResource.error} budgetError={budgetResource.error} onRetry={() => { telemetryResource.refresh(); budgetResource.refresh(); }} onIncreaseBudget={newLimit => { if (budgetResource.data) setBudgetReview({ kind: 'monthly', oldLimit: budgetResource.data.monthlyLimitUsd, newLimit }); }} />}
        {view === 'access' && <Access key={app?.id ?? 'no-app'} app={app} principal={session?.principal ?? undefined} />}
      </main>
    </div>
    {budgetReview && <BudgetApproval request={budgetReview} onClose={() => setBudgetReview(undefined)} onDone={() => { budgetResource.refresh(); jobsResource.refresh(); void currentJob.refresh(); setNotice('The server applied the approved spending limit.'); }} />}
    {createDialog && <NewAppDialog request={createDialog.request} busy={busy} error={createError} onCreate={create} onClose={() => setCreateDialog(null)} />}
    {review && app && session?.principal && <ApprovalDialog release={review.release} action={review.action} app={app} releases={releases} principal={session.principal} onClose={() => setReview(undefined)} onDone={onDeployment} />}
    {cancelDialog && currentJob.job && <Modal title="Cancel this request?" description="The worker will be asked to stop the current development request." onClose={() => setCancelDialog(false)} busy={busy}><p className="modal-copy">Work already performed can remain. After cancellation, review the recorded steps and release status before starting another change.</p><div className="modal-actions"><button className="button button-secondary" onClick={() => setCancelDialog(false)} disabled={busy}>Keep working</button><button className="button button-danger" onClick={() => { void cancel(); }} disabled={busy}>{busy ? 'Cancelling…' : 'Cancel request'}</button></div></Modal>}
    {showNotifications && <Modal title="Workspace notifications" description="Updates and issues reported by your deployment." onClose={() => setShowNotifications(false)}>{notificationsResource.error && <ErrorBanner message={notificationsResource.error} onRetry={notificationsResource.refresh} />}{notificationsResource.loading && !notificationsResource.data ? <Loading /> : notificationsResource.data?.notifications.length ? <div className="notification-list">{notificationsResource.data.notifications.map(notification => <article key={notification.id} className={`notification-item notification-${notification.severity}`}><span>{notification.severity === 'error' || notification.severity === 'warning' ? <ShieldAlert size={18} /> : <Bell size={18} />}</span><div><h3>{notification.title}{!notification.read && <span className="unread-marker" />}</h3><p>{notification.message}</p><small>{formatDate(notification.createdAt, true)}</small></div></article>)}</div> : <EmptyState icon={Bell} title="You’re caught up">No notifications have been reported.</EmptyState>}</Modal>}
    {showAccount && <Modal title="Your workspace account" onClose={() => setShowAccount(false)} busy={busy}>{accountError && <ErrorBanner message={accountError} />}<div className="account-detail"><span className="account-avatar account-avatar-large">{session!.principal!.name.slice(0, 1).toUpperCase()}</span><h3>{session!.principal!.name}</h3><p>{session!.principal!.localOwner ? 'Permanent local platform owner' : 'Organization account'}</p><div className="badge-group">{session!.principal!.roles.map(role => <Badge key={role}>{humanize(role)}</Badge>)}</div><div className="info-strip"><ShieldCheck size={18} /><p>{session!.principal!.mfa ? 'This session reports multi-factor authentication.' : 'This session does not report multi-factor authentication.'}</p></div><p className="field-hint">Application accounts and permissions are managed independently of platform administrator access.</p><button className="button button-secondary" disabled={busy} onClick={() => { void signOut(); }}>{busy ? 'Signing out…' : 'Sign out of workspace'}</button></div></Modal>}
    {showHelp && <Modal title="From an idea to a running application" description="You bring the context. Doxentriq works through the details." onClose={() => setShowHelp(false)}><ol className="help-steps"><li><strong>Describe the outcome</strong><p>Explain who will use the application, what they need to do, and any systems it should connect to.</p></li><li><strong>Work through the details</strong><p>Follow the conversation and answer clarification requests. Each recorded step shows what is happening.</p></li><li><strong>Review a verified preview</strong><p>Inspect the release evidence, test the preview, and ask for improvements.</p></li><li><strong>Approve the exact release</strong><p>Review the impact before publication. Previous versions remain available for a compatibility-checked rollback.</p></li></ol></Modal>}
  </div>;
}
