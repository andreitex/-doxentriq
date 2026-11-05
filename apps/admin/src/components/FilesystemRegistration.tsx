import type { AppRecord } from '../types';
import type { FilesystemSource } from './FilesystemProvision';
import { ErrorBanner, Loading, formatDate } from './ui';

export const localFilesystemTime = (date: Date) => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
export default function FilesystemRegistration({ apps, appId, sourceId, root, expiresAt, sources, loading, error, busy, canProvision, onApp, onSource, onRoot, onExpiry, onRefresh }: {
  apps: AppRecord[]; appId: string; sourceId: string; root: string; expiresAt: string; sources: FilesystemSource[]; loading: boolean; error?: string; busy: boolean; canProvision: boolean;
  onApp: (id: string) => void; onSource: (id: string) => void; onRoot: (value: string) => void; onExpiry: (value: string) => void; onRefresh: () => void;
}) {
  return <>
    {!canProvision && <p className="field-hint">Only the permanent local owner with MFA can review company filesystem sources. No filesystem access is registered from this form without that source evidence.</p>}
    <label>Authorized filesystem application<select required disabled={busy || !canProvision} value={appId} onChange={event => onApp(event.target.value)}><option value="">Choose one application</option>{apps.filter(app => app.status !== 'archived').map(app => <option key={app.id} value={app.id}>{app.name}</option>)}</select></label>
    {error && <ErrorBanner message={error} onRetry={onRefresh} />}
    {loading ? <Loading label="Checking company source qualification…" /> : <label>Company-approved source<select required value={sourceId} disabled={busy || !canProvision || !appId || sources.length === 0} onChange={event => onSource(event.target.value)}><option value="">Select a qualified source</option>{sources.map(source => <option key={source.sourceRootId} value={source.sourceRootId}>{source.sourceRootId} · expires {formatDate(source.sourceExpiresAt)}</option>)}</select><span className="field-hint">Choose a reviewed logical source from the protected company catalog. Host paths and credentials are never entered here.</span></label>}
    {canProvision && appId && !loading && !error && sources.length === 0 && <p className="field-hint">No qualified source is available. Ask your company operator to review the encrypted import, adapter containment evidence and current security findings. Registration cannot activate an unqualified adapter.</p>}
    <div className="form-columns"><label>Logical root alias<input required value={root} disabled={busy || !canProvision} onChange={event => onRoot(event.target.value)} maxLength={80} pattern="[A-Za-z][A-Za-z0-9_-]{0,79}" placeholder="documents" /><span className="field-hint">Names the entire reviewed import. Only files.list and files.read are requested.</span></label><label>Registration expires at<input required type="datetime-local" value={expiresAt} disabled={busy || !canProvision} onChange={event => onExpiry(event.target.value)} /><span className="field-hint">Within 90 days and the selected company source lifetime. Times use your browser’s local timezone.</span></label></div>
    <button type="button" className="text-button" disabled={busy || !canProvision || !appId || loading} onClick={onRefresh}>Refresh company source qualification</button>
    <p className="field-hint">Filesystem registration uses no credentials. A separate exact owner approval configures the scope; the real read-only mount and contained listing must pass during application preview. Expiry is enforced on every connector request; registry edits alone do not immediately revoke a running scope.</p>
  </>;
}
