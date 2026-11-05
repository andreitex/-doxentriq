import { useState } from 'react';
import type { AppRecord, Principal } from '../types';
import { api, errorMessage } from '../api';
import { useResource } from '../hooks';
import { ErrorBanner, Modal } from './ui';

type Settings = { revision: number; visibility: 'default' | 'listed' | 'unlisted'; name: string; description: string; slug: string; url: string | null; releaseId: string | null; artifactHash: string | null; canList: boolean };
export default function PortalListing({ app, principal }: { app: AppRecord; principal?: Principal }) {
  const resource = useResource<Settings>(`/apps/${app.id}/portal-listing`);
  const [review, setReview] = useState<{ settings: Settings; visibility: 'listed' | 'unlisted' }>();
  const [confirmed, setConfirmed] = useState(false), [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>(), [notice, setNotice] = useState<string>();
  const settings = resource.data;
  const allowed = principal?.localOwner && principal.mfa;
  async function save() {
    if (!review || !confirmed) return;
    setBusy(true); setError(undefined);
    try {
      await api(`/apps/${app.id}/portal-listing`, { method: 'PUT', body: {
        revision: review.settings.revision, visibility: review.visibility,
        name: review.settings.name, description: review.settings.description,
        slug: review.settings.slug, url: review.settings.url,
        releaseId: review.settings.releaseId, artifactHash: review.settings.artifactHash,
        acknowledgePublicListing: review.visibility === 'listed',
      } });
      setNotice(review.visibility === 'listed' ? 'The app will appear in the directory while its published release is verified. Users still sign in when required.' : 'The app is hidden from the directory. Its direct link still works.');
      setReview(undefined); resource.refresh();
    } catch (value) { setError(errorMessage(value)); setReview(undefined); resource.refresh(); }
    finally { setBusy(false); }
  }
  return <section className="settings-card"><h2>Show in the app directory</h2>
    <p>Help people find this application on the apps page. Listing shows its name, description and link to visitors. Each app still controls sign-in and permissions.</p>
    {(error || resource.error) && <ErrorBanner message={error ?? resource.error!} />}
    {notice && <p role="status">{notice}</p>}
    {settings && <p>Current setting: {settings.visibility === 'listed' ? 'Listed' : settings.visibility === 'unlisted' ? 'Hidden' : 'Default — only public apps are listed'}</p>}
    {!allowed && <p>The platform owner must review directory visibility.</p>}
    {settings && !settings.canList && <p>Publish an application before listing it here. Background workers have no directory page.</p>}
    <div className="modal-actions">{(['listed', 'unlisted'] as const).map(visibility => <button key={visibility} className="button button-secondary" disabled={!settings?.canList || resource.loading || !!resource.error || busy || !allowed} onClick={() => { if (settings) { setReview({ settings, visibility }); setConfirmed(false); setError(undefined); } }}>{visibility === 'listed' ? 'Review listing' : 'Review hiding'}</button>)}</div>
    {review && <Modal title={review.visibility === 'listed' ? 'List this application?' : 'Hide this application?'} onClose={() => setReview(undefined)} busy={busy}>
      <div className="form-stack"><strong>{review.settings.name}</strong><p>{review.settings.description || 'No description.'}</p><p>App address: {review.settings.url}</p>
        <p>{review.visibility === 'listed' ? 'Anyone who can open the apps page will see this name, description and link. App accounts and permissions are still required for protected content.' : 'Visitors will no longer see this app in the directory. People with its link can still open it.'}</p>
        <label className="checkbox-label"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={busy} />I reviewed this directory change.</label>
        <button className="button button-primary" disabled={busy || !confirmed} onClick={() => { void save(); }}>{busy ? 'Saving…' : 'Confirm directory change'}</button>
      </div>
    </Modal>}
  </section>;
}
