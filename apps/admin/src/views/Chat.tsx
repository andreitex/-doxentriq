import { useEffect, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { ArrowUp, ArrowUpRight, Check, CheckCircle2, ChevronDown, ChevronRight, Circle, Code2, FileText, Globe, Layers3, LoaderCircle, MessageSquare, ShieldCheck, Square, Workflow } from 'lucide-react';
import type { AppRecord, Budget, JobRecord, ProgressEvent } from '../types';
import { safeUrl } from '../api';
import { Badge, ErrorBanner, Loading, formatDate, humanize, money, stageTone } from '../components/ui';
import { terminalStage } from '../hooks';
import Elapsed from '../components/Elapsed';
import { requestGuidance } from './request-guidance';

const examples = [
  { icon: FileText, title: 'Organize your documents', subtitle: 'A document management system', request: 'Build a document management system where our team can upload, search, and organize documents. Include folders, version history, and role-based permissions. Ask me about our approval process before building it.' },
  { icon: Workflow, title: 'Simplify a daily workflow', subtitle: 'Turn manual steps into an app', request: 'Help me build an app for our internal purchase approvals. Employees submit a request, managers approve it, and the finance team tracks its status. Ask me what information and roles we need.' },
  { icon: Code2, title: 'Connect your tools', subtitle: 'Create an API or MCP integration', request: 'I want an MCP that safely connects to our internal API. Help me specify which operations it should expose, what credentials are required, and how access should be limited before implementing it.' }
];

const steps = [
  { stages: ['clarification', 'specification'], label: 'Understand' },
  { stages: ['implementation'], label: 'Build' },
  { stages: ['verification'], label: 'Check' },
  { stages: ['preview', 'awaiting_approval'], label: 'Preview' },
  { stages: ['deployment'], label: 'Publish' },
  { stages: ['observation', 'completed'], label: 'Monitor' }
];

function Markdown({ children }: { children: string }) {
  return <ReactMarkdown components={{ img: ({ alt }) => <span className="muted">{alt ? `[Image: ${alt}]` : '[Image]'}</span>, a: ({ href, children: content }) => {
    const url = safeUrl(href);
    return url ? <a href={url} target="_blank" rel="noopener noreferrer">{content}</a> : <span>{content}</span>;
  } }}>{children}</ReactMarkdown>;
}

function EventCard({ event }: { event: ProgressEvent }) {
  const [expanded, setExpanded] = useState(false);
  const detail = event.detail && Object.keys(event.detail).length > 0;
  const Icon = event.kind === 'error' ? Circle : event.kind === 'test' ? ShieldCheck : event.kind === 'tool' ? Code2 : CheckCircle2;
  return <div className={`event-card ${event.kind === 'error' ? 'event-error' : ''}`}>
    <div className="event-heading"><span className="event-icon"><Icon size={16} /></span><div className="event-body"><span className="event-stage">{humanize(event.stage)}</span><div className="markdown"><Markdown>{event.message}</Markdown></div></div>
      {detail && <button className="icon-button" aria-label={expanded ? 'Hide step details' : 'Show step details'} aria-expanded={expanded} onClick={() => setExpanded(value => !value)}>{expanded ? <ChevronDown size={17} /> : <ChevronRight size={17} />}</button>}
    </div>{expanded && <pre className="event-detail">{JSON.stringify(event.detail, null, 2)}</pre>}
  </div>;
}

export default function Chat({ app, jobs, jobsLoading, job, activeRequest, events, loading, stream, error, draft, setDraft, onSend, onResume, onCancel, onSelectJob, onViewReleases, onIncreaseBudget, busy, budget }: {
  app?: AppRecord; jobs: JobRecord[]; jobsLoading: boolean; job?: JobRecord; activeRequest?: JobRecord; events: ProgressEvent[]; loading: boolean;
  stream: 'connecting' | 'live' | 'reconnecting' | 'idle'; error?: string; draft: string; setDraft: (value: string) => void;
  onSend: (request: string, budgetUsd?: number) => Promise<void>; onResume: (answer: string) => Promise<boolean>; onCancel: () => Promise<void>;
  onSelectJob: (id: string) => void; onViewReleases: () => void; onIncreaseBudget: (newLimit: number) => void; busy: boolean; budget?: Budget;
}) {
  const [answer, setAnswer] = useState('');
  const [limit, setLimit] = useState('');
  const [increase, setIncrease] = useState('');
  const [sendError, setSendError] = useState<string>();
  const composer = useRef<HTMLTextAreaElement>(null);
  const bottom = useRef<HTMLDivElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);
  const inProgress = job && !terminalStage(job.stage) && job.stage !== 'awaiting_approval';
  const blocked = Boolean(activeRequest);
  const paused = job?.stage === 'clarification' || job?.stage === 'needs_attention';
  const attentionKind = job?.result?.attentionKind;
  const protectedSetup = paused && attentionKind === 'setup';
  const modelBillingHold = paused && job?.result?.modelBillingHold === true;
  const clarification = job?.stage === 'clarification' || attentionKind === 'clarification';
  const recoveryHint = typeof job?.result?.recoveryHint === 'string' ? job.result.recoveryHint : undefined;
  const publicationRunning = job?.stage === 'deployment' || job?.stage === 'observation';
  const guidance = job ? requestGuidance(job, app) : undefined;
  useEffect(() => { setAnswer(''); setSendError(undefined); pinned.current = true; }, [job?.id, app?.id]);
  useEffect(() => {
    if (composer.current) { composer.current.style.height = 'auto'; composer.current.style.height = `${Math.min(composer.current.scrollHeight, 170)}px`; }
  }, [draft]);
  useEffect(() => { if (pinned.current) bottom.current?.scrollIntoView({ behavior: 'smooth', block: 'end' }); }, [events.length, job?.id]);
  const submit = async () => {
    const request = draft.trim();
    if (!request || busy || blocked) return;
    const requestLimit = limit.trim() ? Number(limit) : undefined;
    if (requestLimit !== undefined && (!Number.isFinite(requestLimit) || requestLimit <= 0)) { setSendError('Enter a positive budget in USD.'); return; }
    if (requestLimit !== undefined && budget && requestLimit > budget.requestLimitUsd) { setSendError(`This workspace allows up to ${money(budget.requestLimitUsd)} per request.`); return; }
    setSendError(undefined);
    await onSend(request, requestLimit);
  };
  return <section className="chat-layout" aria-label="Application development conversation">
    <div ref={scroller} className="chat-scroll" onScroll={() => {
      if (scroller.current) pinned.current = scroller.current.scrollHeight - scroller.current.scrollTop - scroller.current.clientHeight < 120;
    }}>
      {app && jobs.length > 0 && <div className="conversation-selector"><MessageSquare size={15} /><label htmlFor="conversation">Conversation</label><select id="conversation" value={job?.id ?? ''} onChange={event => onSelectJob(event.target.value)}><option value="" disabled>Select a request</option>{jobs.map(item => <option key={item.id} value={item.id}>{item.request.slice(0, 70)}</option>)}</select></div>}
      {error && <div className="chat-inner"><ErrorBanner message={error} /></div>}
      {loading || (jobsLoading && !job) ? <Loading label="Loading your conversation…" /> : !job ? <div className="welcome chat-inner">
        <span className="welcome-emblem"><Layers3 size={32} strokeWidth={1.5} /></span>
        <p className="eyebrow">YOUR IDEAS. YOUR SOFTWARE.</p><h1>{app ? `Let's shape ${app.name}.` : 'What would you like to build?'}</h1>
        <p className="welcome-description">Describe what you need in your own words.<br />We’ll work through the details, build it, and help you release it.</p>
        <details className="release-details"><summary>What should I include in my request?</summary><div className="release-detail-content"><ol><li>Who will use the app, and what should each person be allowed to do?</li><li>What daily task should it make easier? Give one example of a successful result.</li><li>Which existing tools or files should it connect to? Enter passwords and API keys only in Connections.</li></ol><p>You do not need to choose a model or programming language. Start with the most useful task, then improve the app through follow-up requests.</p></div></details>
        <div className="idea-grid">{examples.map(({ icon: Icon, title, subtitle, request }) => <button key={title} className="idea-card" onClick={() => { setDraft(request); composer.current?.focus(); }}>
          <span className="idea-icon"><Icon size={21} strokeWidth={1.6} /></span><strong>{title}</strong><span>{subtitle}</span><ArrowUpRight className="idea-arrow" size={17} />
        </button>)}</div>
        <div className="welcome-note"><ShieldCheck size={16} /><span>Every release is verified and versioned. You control when it goes live.</span></div>
      </div> : <div className="chat-inner conversation">
        <div className="user-message"><div className="user-message-label">Your request <span>{formatDate(job.createdAt, true)}</span></div><p>{job.request}</p></div>
        <div className="assistant-message"><span className="assistant-avatar"><Layers3 size={19} /></span><div className="assistant-content">
          <div className="assistant-label">Doxentriq <span>Application builder</span></div>
          <div className="progress-summary"><div className="progress-title"><span>{terminalStage(job.stage) ? job.stage === 'completed' ? 'Request completed' : job.stage === 'cancelled' ? 'Request cancelled' : 'This request needs attention' : paused ? protectedSetup ? 'Protected setup is needed' : clarification ? 'Your input is needed' : 'A review is needed' : job.stage === 'awaiting_approval' ? 'Ready for your review' : 'Working on your request'}</span><Badge tone={stageTone(job.stage)} dot>{humanize(job.stage)}</Badge></div>
            <div className="step-track" aria-label="Development steps">{steps.map(step => {
              const reached = events.some(event => step.stages.includes(event.stage));
              const current = step.stages.includes(job.stage);
              return <div key={step.label} className={`step ${current ? 'step-current' : reached ? 'step-reached' : ''}`}><span>{current && !terminalStage(job.stage) && !paused && job.stage !== 'awaiting_approval' ? <LoaderCircle size={12} className="spin" /> : reached ? <Check size={12} /> : <span className="step-empty" />}</span><small>{step.label}</small></div>;
            })}</div>
            <div className="progress-foot"><span>{money(job.costUsd)} used · {money(job.budgetUsd)} request limit</span><Elapsed job={job} events={events} />{stream === 'live' ? <span className="stream-state"><span />Live updates</span> : stream === 'reconnecting' ? <span className="stream-warning">Reconnecting · checking for updates</span> : stream === 'connecting' ? <span>Connecting to progress…</span> : <span>Updated {formatDate(job.updatedAt, true)}</span>}</div>
          </div>
          {guidance && <div className="info-strip"><MessageSquare size={18} /><div><strong>{guidance.title}</strong><p>{guidance.description}</p></div></div>}
          <div className="event-list" aria-live="polite" aria-relevant="additions">{events.length === 0 ? <p className="muted">{job.stage === 'queued' ? 'Your request is queued. Progress will appear here as work begins.' : 'No step details have been recorded yet.'}</p> : events.map(event => <EventCard key={event.id} event={event} />)}</div>
          {modelBillingHold ? <div className="resume-card"><h3>Model billing needs company review</h3><p>{recoveryHint ?? 'Ask the company operator to reconcile the interrupted provider outcome. Held reservations remain reserved.'}</p></div> : paused && job.result?.budgetBlocked === true ? <form className="resume-card" onSubmit={event => { event.preventDefault(); const amount = Number(increase); if (Number.isFinite(amount) && amount > job.budgetUsd) onIncreaseBudget(amount); }}><label htmlFor="increase-request-budget">This request reached its spending limit</label><p>Current maximum: {money(job.budgetUsd)}. Review additional model spending before the request can resume. A sufficient monthly allowance is also required.</p><input id="increase-request-budget" type="number" min={job.budgetUsd + 0.01} max={1000000} step="0.01" required placeholder="New request maximum in USD" value={increase} onChange={event => setIncrease(event.target.value)} disabled={busy} /><button className="button button-primary" disabled={busy || !increase || Number(increase) <= job.budgetUsd}>Review spending increase <ArrowUpRight size={15} /></button></form> : paused && clarification ? <form className="resume-card" onSubmit={event => { event.preventDefault(); if (answer.trim()) void onResume(answer.trim()).then(success => { if (success) setAnswer(''); }); }}><label htmlFor="resume-answer">Help Doxentriq continue</label><p>Read the latest step above and provide the requested business information. Enter integration credentials only in protected connection settings.</p><textarea id="resume-answer" value={answer} onChange={event => setAnswer(event.target.value)} placeholder="Your answer or instructions…" required rows={3} disabled={busy} /><button className="button button-primary" type="submit" disabled={busy || !answer.trim()}>Continue request <ArrowUp size={15} /></button></form> : paused && <div className="resume-card"><h3>{protectedSetup ? 'Protected platform setup is needed' : 'This request needs a reviewed next step'}</h3><p>{recoveryHint ?? 'Contact your company operator to review the latest error and correct the protected platform configuration or runtime issue. Keep credentials in protected settings.'}</p><button className="button button-primary" disabled={busy} onClick={() => { void onResume(protectedSetup ? 'Retry after protected setup was corrected' : 'Retry after the reported issue was reviewed and corrected'); }}>Retry request <ArrowUpRight size={15} /></button></div>}
          {(job.stage === 'preview' || job.stage === 'awaiting_approval' || job.stage === 'completed') && <div className="chat-actions">{app && app.previewReleaseId && job.result?.releaseId === app.previewReleaseId && safeUrl(app.previewUrl) && <a className="button button-secondary" href={`/api/v1/apps/${encodeURIComponent(app.id)}/preview-launch?releaseId=${encodeURIComponent(app.previewReleaseId)}`} target="_blank" rel="noopener noreferrer"><Globe size={16} />Open preview <ArrowUpRight size={14} /></a>}<button className="button button-primary" onClick={onViewReleases}>Review releases <ArrowUpRight size={15} /></button></div>}
        </div></div>
      </div>}
      <div ref={bottom} />
    </div>
    <div className="composer-area"><div className="composer-width">
      {sendError && <ErrorBanner message={sendError} onDismiss={() => setSendError(undefined)} />}
      {(inProgress || activeRequest) && <div className="active-request-note"><span><LoaderCircle size={14} className={paused ? '' : 'spin'} />{paused ? modelBillingHold ? 'The company operator must reconcile the interrupted model outcome before this request can continue.' : clarification ? 'Answer the business question above to continue.' : 'Review the action above before retrying this request.' : publicationRunning ? 'Publication is running. Inspect the release and recorded operation status while it completes.' : 'An application request is in progress. Follow its updates before starting another change.'}</span>{activeRequest && activeRequest.id !== job?.id ? <button className="text-button" onClick={() => onSelectJob(activeRequest.id)}>View active request</button> : publicationRunning ? <button className="text-button" onClick={onViewReleases}>Inspect release status</button> : inProgress && <button className="text-button" onClick={() => { void onCancel(); }} disabled={busy}><Square size={11} />Cancel request</button>}</div>}
      <form className="composer" onSubmit={event => { event.preventDefault(); void submit(); }}>
        <label className="sr-only" htmlFor="request">Describe the application or change you want</label><textarea id="request" ref={composer} rows={2} placeholder={app ? `What would you like to change in ${app.name}?` : 'Describe an app you want to build…'} value={draft} onChange={event => setDraft(event.target.value)} disabled={busy} onKeyDown={event => { if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); void submit(); } }} />
        <div className="composer-toolbar"><span className="composer-context"><Layers3 size={15} />{app?.name ?? 'New application'}</span><div className="composer-right"><label className="budget-field" title="Optional maximum cost for this request in USD"><span>Budget $</span><input aria-label="Request budget in USD" type="number" min="0.01" step="0.01" max={budget?.requestLimitUsd} placeholder={budget ? String(budget.requestLimitUsd) : 'Auto'} value={limit} onChange={event => setLimit(event.target.value)} disabled={busy} /></label><button className="send-button" type="submit" aria-label="Send request" disabled={busy || blocked || !draft.trim()}>{busy ? <LoaderCircle size={18} className="spin" /> : <ArrowUp size={20} />}</button></div></div>
      </form><div className="composer-caption"><span>Model and reasoning are selected automatically.</span><span>Shift + Enter for a new line</span></div>
    </div></div>
  </section>;
}
