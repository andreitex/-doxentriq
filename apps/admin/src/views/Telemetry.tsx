import { useState } from 'react';
import { Activity, CircleDollarSign, Clock3, Cpu, Database, Layers3, RefreshCw, Server, Workflow } from 'lucide-react';
import type { AppRecord, Budget, Telemetry as TelemetryData } from '../types';
import { Badge, EmptyState, ErrorBanner, Loading, formatDate, humanize, money, stageTone } from '../components/ui';

function uptime(seconds: number) {
  if (!Number.isFinite(seconds)) return 'Not reported';
  const days = Math.floor(seconds / 86400), hours = Math.floor(seconds / 3600) % 24, minutes = Math.floor(seconds / 60) % 60;
  return days ? `${days}d ${hours}h` : hours ? `${hours}h ${minutes}m` : `${minutes}m`;
}

function bytes(value?: number) {
  if (value === undefined || !Number.isFinite(value) || value < 0) return 'Not reported';
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(1)} GiB`;
}

function measuredUsage(total?: number, available?: number) {
  if (total === undefined || available === undefined || !Number.isFinite(total) || !Number.isFinite(available) || total <= 0 || available < 0 || available > total) return undefined;
  return { used: total - available, total, percent: Math.round((total - available) / total * 100) };
}

export default function Telemetry({ data, budget, apps = [], loading, error, budgetError, onRetry, onIncreaseBudget }: {
  data?: TelemetryData; budget?: Budget; apps?: AppRecord[]; loading: boolean; error?: string; budgetError?: string; onRetry: () => void; onIncreaseBudget: (newLimit: number) => void;
}) {
  const [increase, setIncrease] = useState('');
  const host = data?.services.find(service => service.name === 'vm');
  const memory = measuredUsage(host?.memoryTotalBytes, host?.memoryAvailableBytes);
  const disk = measuredUsage(host?.diskTotalBytes, host?.diskFreeBytes);
  const loads = host?.loadAverage?.length === 3 && host.loadAverage.every(value => Number.isFinite(value) && value >= 0) ? host.loadAverage as [number, number, number] : undefined;
  const usage = budget && budget.monthlyLimitUsd > 0 ? Math.min(100, Math.max(0, (budget.spentUsd + budget.reservedUsd) / budget.monthlyLimitUsd * 100)) : 0;
  return <section className="workspace-page"><div className="page-heading"><div><p className="eyebrow">WORKSPACE TELEMETRY</p><h1>Know whatâ€™s happening.</h1><p>Live workload, service availability, and model spend from your deployment.</p></div><button className="button button-secondary" onClick={onRetry} disabled={loading}><RefreshCw size={16} className={loading ? 'spin' : ''} />Refresh</button></div>
    {error && <ErrorBanner message={error} onRetry={onRetry} />}
    {loading && !data ? <Loading label="Loading workspace telemetryâ€¦" /> : data ? <>
      <div className="metric-grid">{[
        { icon: Layers3, label: 'Applications', value: data.counts.apps, note: `${data.counts.publishedApps} published` },
        { icon: Workflow, label: 'Active requests', value: data.counts.runningJobs, note: `${data.counts.jobs} total requests` },
        { icon: CircleDollarSign, label: budget?.authorityId ? 'Model budget accounted for' : 'Recorded model spend', value: money(data.costUsd), note: 'Reported by the control service' },
        { icon: Clock3, label: 'Control service uptime', value: uptime(data.uptimeSeconds), note: `${humanize(data.mode)} mode` }
      ].map(({ icon: Icon, label, value, note }) => <article className="metric-card" key={label}><div><span>{label}</span><Icon size={18} /></div><strong>{value}</strong><p>{note}</p></article>)}</div>
      <div className="section-heading"><h2>Virtual machine</h2>{host?.encryptedDataMounted !== undefined && <Badge tone={host.encryptedDataMounted ? 'green' : 'amber'}>{host.encryptedDataMounted ? 'Encrypted data mounted' : 'Encrypted data mount unavailable'}</Badge>}</div>
      <div className="metric-grid">{[
        { icon: Cpu, label: 'Host load average', value: loads ? loads[0].toFixed(2) : 'Not reported', note: loads ? `5m ${loads[1].toFixed(2)} Â· 15m ${loads[2].toFixed(2)}${host?.cpuCount ? ` Â· ${host.cpuCount} CPUs` : ''}` : 'Actual 1, 5, and 15 minute load' },
        { icon: Activity, label: 'Host memory used', value: memory ? `${memory.percent}%` : 'Not reported', note: memory ? `${bytes(memory.used)} of ${bytes(memory.total)}` : 'Available host memory has not been measured' },
        { icon: Database, label: 'Data disk used', value: disk ? `${disk.percent}%` : 'Not reported', note: disk ? `${bytes(disk.used)} of ${bytes(disk.total)}` : 'Disk capacity has not been measured' },
        { icon: Clock3, label: 'VM uptime', value: uptime(host?.uptimeSeconds ?? NaN), note: host?.detail ?? 'Authenticated host measurements are unavailable' }
      ].map(({ icon: Icon, label, value, note }) => <article className="metric-card" key={label}><div><span>{label}</span><Icon size={18} /></div><strong>{value}</strong><p>{note}</p></article>)}</div>
      <div className="telemetry-columns"><article className="telemetry-card"><div className="card-heading"><span className="neutral-icon"><Activity size={21} /></span><div><h2>Build and deployment service</h2><p>Application sandbox availability</p></div><Badge tone={data.broker.available ? 'green' : 'amber'} dot>{data.broker.available ? 'Available' : 'Unavailable'}</Badge></div><p>{data.broker.detail}</p></article>
        <article className="telemetry-card"><div className="card-heading"><span className="neutral-icon"><Server size={21} /></span><div><h2>Service metrics</h2><p>Connected telemetry sources</p></div></div>{data.services.length === 0 ? <div className="unavailable-metrics"><Database size={18} /><p>No service metrics have been reported. CPU, memory, and storage values will appear when a telemetry source is connected.</p></div> : <ul className="service-list">{data.services.map((service, index) => <li key={`${service.name}-${index}`}><span>{service.name ?? 'Unnamed service'}</span><Badge tone={stageTone(service.status ?? 'unavailable')}>{humanize(service.status ?? 'Not reported')}</Badge>{service.detail && <p>{service.detail}</p>}</li>)}</ul>}</article></div>
      <div className="section-heading"><h2>Application health and recovery</h2><span>Recorded runtime checks</span></div>
      {(data.observations?.length ?? 0) === 0 ? <div className="quiet-empty"><Activity size={23} /><div><h3>No application health observations recorded</h3><p>Published applications appear after the runtime records their exact release health. Missing observations do not establish healthy operation.</p></div></div> : <div className="observation-list">{data.observations!.map(observation => <article className="observation-card" key={observation.appId}><div className="observation-heading"><div><h3>{apps.find(app => app.id === observation.appId)?.name ?? observation.appId}</h3><p>Observed release <code>{observation.releaseId}</code></p></div><Badge tone={observation.status === 'healthy' ? 'green' : observation.status === 'unhealthy' ? 'red' : observation.status === 'unavailable' ? 'amber' : 'neutral'}>{humanize(observation.status)}</Badge></div><p>{observation.detail}</p><dl className="detail-grid"><div><dt>Latest health check</dt><dd>{formatDate(observation.checkedAt, true)}</dd></div><div><dt>Consecutive failed checks</dt><dd>{observation.consecutiveFailures.length}</dd></div><div><dt>Recovery status</dt><dd><Badge tone={observation.recoveryStatus === 'recovered' ? 'green' : observation.recoveryStatus === 'monitoring' ? 'neutral' : 'amber'}>{observation.recoveryStatus === 'recovered' ? 'Recovery completed' : humanize(observation.recoveryStatus)}</Badge></dd></div><div><dt>Publication operation</dt><dd><code>{observation.publicationOperationId || 'Not reported'}</code></dd></div>{observation.recoveryOperationId && <div><dt>Recovery operation</dt><dd><code>{observation.recoveryOperationId}</code></dd></div>}</dl>{observation.recoveryReason && <p className="observation-reason">{observation.recoveryReason}</p>}{observation.recoveryStatus === 'pending' && <p className="observation-reason">Recovery is pending. Inspect the recorded operation outcome before retrying a publication or recovery.</p>}<a className="text-button" href={`/?app=${encodeURIComponent(observation.appId)}&view=releases`}>Inspect release history</a></article>)}</div>}
    </> : <EmptyState icon={Activity} title="Telemetry is not available">Refresh to request data from the control service.</EmptyState>}
    <div className="section-heading"><h2>Model budget</h2><span><Cpu size={14} />Automatic model selection</span></div>
    {budgetError && <ErrorBanner message={budgetError} onRetry={onRetry} />}
    {budget ? <article className="budget-card"><div className="budget-card-heading"><div><h3>{budget.month} budget</h3><p>Spending limits keep each request and the workspace within its allowance.</p></div><strong>{money(budget.remainingUsd)}<span>available</span></strong></div><div className="budget-progress" role="progressbar" aria-label="Monthly model budget used and reserved" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(usage)}><div style={{ width: `${usage}%` }} /></div><div className="budget-figures"><div><span>{budget.authorityId ? 'Accounted for' : 'Spent'}</span><strong>{money(budget.spentUsd)}</strong></div><div><span>Reserved for requests</span><strong>{money(budget.reservedUsd)}</strong></div><div><span>Monthly limit</span><strong>{money(budget.monthlyLimitUsd)}</strong></div><div><span>Per-request limit</span><strong>{money(budget.requestLimitUsd)}</strong></div></div>{budget.authorityId && <><div className="budget-figures"><div><span>Workflow charges</span><strong>{money(budget.workflowSpentUsd ?? 0)}</strong></div><div><span>Company tests: confirmed</span><strong>{money(budget.externalConfirmedUsd ?? 0)}</strong></div><div><span>Conservative debit: invoice unknown</span><strong>{money(budget.externalConservativeUsd ?? 0)}</strong></div></div><p>The company tests and your requests share one allowance. A conservative debit counts toward the limit without claiming a confirmed provider invoice.</p><p>{budget.authorityExpired ? 'This allowance has expired. Generation is paused until the company reconciles the next allowance.' : 'This shared allowance is valid for the displayed month. Contact the company to change or renew it.'}</p></>}</article> : !budgetError && <p className="muted">Budget information has not been reported.</p>}
    {budget && (!budget.authorityId || !budget.authorityExpired && budget.monthlyLimitUsd < (budget.authorityLimitUsd ?? 0)) && <form className="resume-card" onSubmit={event => { event.preventDefault(); const amount = Number(increase); if (Number.isFinite(amount) && amount > budget.monthlyLimitUsd) onIncreaseBudget(amount); }}><label htmlFor="increase-monthly-budget">Increase the monthly spending maximum</label><p>{budget.authorityId ? 'This changes the workflow limit within the company shared allowance. Its amount and expiry still apply.' : 'The change applies to the recurring workspace limit. You will review the exact impact before approving it.'}</p><input id="increase-monthly-budget" type="number" min={budget.monthlyLimitUsd + 0.01} max={budget.authorityLimitUsd ?? 1000000} step="0.01" required placeholder="New monthly maximum in USD" value={increase} onChange={event => setIncrease(event.target.value)} /><button className="button button-secondary" disabled={!increase || Number(increase) <= budget.monthlyLimitUsd}>Review monthly increase</button></form>}
  </section>;
}
