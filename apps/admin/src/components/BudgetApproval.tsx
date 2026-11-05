import { useCallback, useEffect, useState } from 'react';
import { Check, ChevronRight, CircleDollarSign } from 'lucide-react';
import type { ApprovalRecord } from '../types';
import { api, errorMessage } from '../api';
import { ErrorBanner, Loading, Modal, formatDate, money } from './ui';

export default function BudgetApproval({ request, onClose, onDone }: {
  request: { kind: 'job' | 'monthly'; jobId?: string; oldLimit: number; newLimit: number };
  onClose: () => void; onDone: () => void;
}) {
  const [approval, setApproval] = useState<ApprovalRecord>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [reviewed, setReviewed] = useState(false), [submitted, setSubmitted] = useState(false);
  const [now, setNow] = useState(Date.now());
  const prepare = useCallback(async () => {
    setLoading(true); setApproval(undefined); setError(undefined); setReviewed(false); setSubmitted(false);
    try { const value = await api<{ approval: ApprovalRecord }>(request.kind === 'job' ? `/jobs/${encodeURIComponent(request.jobId!)}/budget-approval` : '/budget/monthly-approval', { method: 'POST', body: request.kind === 'job' ? { newBudgetUsd: request.newLimit } : { newMonthlyLimitUsd: request.newLimit } }); setApproval(value.approval); }
    catch (failure) { setError(errorMessage(failure)); } finally { setLoading(false); }
  }, [request]);
  useEffect(() => { void prepare(); }, [prepare]);
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 5000); return () => clearInterval(timer); }, []);
  const expired = approval ? new Date(approval.expiresAt).getTime() <= now : false;
  const approve = async () => {
    if (!approval || !reviewed || expired || busy || submitted) return;
    setBusy(true); setError(undefined);
    try {
      await api(`/approvals/${encodeURIComponent(approval.id)}/approve`, { method: 'POST', body: { artifactHash: approval.artifactHash } });
      setSubmitted(true);
      await api(request.kind === 'job' ? `/jobs/${encodeURIComponent(request.jobId!)}/extend-budget` : '/budget/extend-monthly', { method: 'POST', body: { approvalId: approval.id } });
      onDone(); onClose();
    } catch (failure) { setError(errorMessage(failure)); } finally { setBusy(false); }
  };
  return <Modal title="Review additional model spending" description={request.kind === 'job' ? 'Increase this request’s maximum spending.' : 'Increase the workspace’s recurring monthly maximum.'} onClose={onClose} busy={busy || loading}>
    {error && <ErrorBanner message={error} />}{loading ? <Loading label="Preparing the exact spending approval…" /> : approval ? <div className="approval-content">
      <div className="info-strip"><CircleDollarSign size={20} /><p>{money(request.oldLimit)} → <strong>{money(request.newLimit)}</strong> {request.kind === 'job' ? 'request limit' : 'monthly limit'}</p></div><h3>What this approval allows</h3><ul className="impact-list">{approval.impact.map((impact, index) => <li key={index}><ChevronRight size={15} /><span>{impact}</span></li>)}</ul><dl className="detail-grid"><div><dt>Exact approval digest</dt><dd><code>{approval.artifactHash}</code></dd></div><div><dt>Expires</dt><dd>{formatDate(approval.expiresAt, true)}</dd></div></dl>
      {expired || submitted ? <div className="info-strip info-strip-warning"><p>{expired ? 'This review expired. Prepare a new approval.' : 'The approval was submitted. Refresh the current limits before preparing another review.'}</p><button className="text-button" onClick={() => { void prepare(); }}>New review</button></div> : <label className="checkbox-label approval-check"><input type="checkbox" checked={reviewed} onChange={event => setReviewed(event.target.checked)} />I reviewed the impact and approve the additional model spending.</label>}<div className="modal-actions"><button className="button button-secondary" onClick={onClose} disabled={busy}>Cancel</button><button className="button button-primary" disabled={!reviewed || expired || busy || submitted} onClick={() => { void approve(); }}>{busy ? 'Submitting…' : 'Approve spending increase'}<Check size={16} /></button></div>
    </div> : <div className="modal-actions"><button className="button button-secondary" onClick={onClose}>Close</button><button className="button button-primary" onClick={() => { void prepare(); }}>Try review again</button></div>}
  </Modal>;
}
