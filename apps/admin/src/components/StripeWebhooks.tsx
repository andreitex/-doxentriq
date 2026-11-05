import { useEffect, useRef, useState } from 'react';
import type { AppRecord, ConnectionRecord } from '../types';
import { api } from '../api';
import { Badge, ErrorBanner, Modal, formatDate } from './ui';

type Scope = { account: string | null; live: boolean; eventTypes: string[] };
export type StripePolicy = { schemaVersion: 1; provider: 'stripe'; payloadFormat: 'api_v1_snapshot'; endpointId: string; appId: string; connectionId: string; url: string; registryHash: string; credentialBinding: string; credentialEnvelopeHash: string; scope: Scope };
type Approval = { id: string; endpointId: string; appId: string; connectionId: string; action: 'activate' | 'withdraw'; artifactHash: string; createdAt: string; expiresAt: string; approvedAt: string | null; approvedBy: string | null; consumedAt: string | null };
export type StripeReview = { policy: StripePolicy; approval: Approval; activeApprovalId: string | null; status?: 'pending' };
export type StripeEndpoint = { policy: StripePolicy; status: 'pending' | 'active' | 'withdrawn'; activeApprovalId: string | null; activatedAt: string | null; withdrawnAt: string | null };
export type StripeEndpointPage = { endpoints: StripeEndpoint[]; nextCursor: string | null };
type Call = (path: string, options?: { method?: string; body?: unknown }) => Promise<unknown>;
export type StripeSetup = { appId: string; account: string; live: boolean; events: string; signingSecret: string; previousSigningSecret: string };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i, hex = /^[a-f0-9]{64}$/;
const bad = () => new Error('The exact Stripe endpoint evidence is unavailable or changed. Inspect its retained state.');
const object = (value: unknown): Record<string, unknown> => { if (!value || typeof value !== 'object' || Array.isArray(value)) throw bad(); return value as Record<string, unknown>; };
const exact = (value: Record<string, unknown>, keys: string[]) => { if (Object.keys(value).sort().join('|') !== [...keys].sort().join('|')) throw bad(); };
const time = (value: unknown): value is string => typeof value === 'string' && value.length <= 40 && /^\d{4}-\d{2}-\d{2}T.*(?:Z|\+00:00)$/.test(value) && Number.isFinite(Date.parse(value));
function canonical(value: unknown): unknown { if (Array.isArray(value)) return value.map(canonical); if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, canonical(item)])); if (typeof value === 'number' && !Number.isFinite(value)) throw bad(); return value; }
export async function stripeArtifactHash(value: unknown): Promise<string> { const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(canonical(value)))); return [...new Uint8Array(digest)].map(item => item.toString(16).padStart(2, '0')).join(''); }
function scope(value: unknown): Scope {
  const item = object(value); exact(item, ['account', 'live', 'eventTypes']);
  if (item.account !== null && (typeof item.account !== 'string' || !/^acct_[A-Za-z0-9]{1,160}$/.test(item.account)) || typeof item.live !== 'boolean' || !Array.isArray(item.eventTypes) || item.eventTypes.length < 1 || item.eventTypes.length > 64 || new Set(item.eventTypes).size !== item.eventTypes.length || !item.eventTypes.every(event => typeof event === 'string' && event.length <= 160 && /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,5}$/.test(event))) throw bad();
  return item as Scope;
}
export function validateStripeOrigin(origin: string): string {
  try { const base = new URL(origin); if (base.protocol === 'https:' && base.origin === origin && !base.username && !base.password) return origin; } catch { /* Reject without echoing URL credentials. */ }
  throw new Error('An exact HTTPS admin origin is required before entering or submitting signing secrets.');
}
function policy(value: unknown, appId: string, connectionId: string, currentOrigin?: string): StripePolicy {
  const item = object(value); exact(item, ['schemaVersion', 'provider', 'payloadFormat', 'endpointId', 'appId', 'connectionId', 'url', 'registryHash', 'credentialBinding', 'credentialEnvelopeHash', 'scope']);
  if (typeof item.url !== 'string') throw bad();
  let historicalOrigin: string; try { historicalOrigin = validateStripeOrigin(new URL(item.url).origin); } catch { throw bad(); }
  if (currentOrigin !== undefined && historicalOrigin !== validateStripeOrigin(currentOrigin) || item.schemaVersion !== 1 || item.provider !== 'stripe' || item.payloadFormat !== 'api_v1_snapshot' || typeof item.endpointId !== 'string' || !uuid.test(item.endpointId) || item.appId !== appId || item.connectionId !== connectionId || item.url !== `${historicalOrigin}/webhooks/stripe/${item.endpointId}` || !['registryHash', 'credentialBinding', 'credentialEnvelopeHash'].every(key => typeof item[key] === 'string' && hex.test(item[key] as string))) throw bad();
  scope(item.scope); return item as StripePolicy;
}
function registryAllowsApp(connection: ConnectionRecord, appId: string, at: number): boolean { return uuid.test(connection.id) && connection.type === 'stripe' && ['configured', 'needs_credentials'].includes(connection.status) && connection.appIds.includes(appId) && connection.capabilities.includes('webhooks.receive') && (connection.expiresAt === null || time(connection.expiresAt) && Date.parse(connection.expiresAt) > at); }
export function eligibleStripeApp(connection: ConnectionRecord, app: AppRecord | undefined, at = Date.now()): boolean { return Boolean(app && uuid.test(app.id) && app.status !== 'archived' && registryAllowsApp(connection, app.id, at)); }
export function stripeSetupBody(input: StripeSetup, connection: ConnectionRecord, app: AppRecord | undefined, canProvision: boolean, at = Date.now()) {
  if (!canProvision || input.appId !== app?.id || !eligibleStripeApp(connection, app, at)) throw new Error('A configured Stripe connection and eligible application require permanent-owner MFA.');
  const selected = scope({ account: input.account.trim() || null, live: input.live, eventTypes: input.events.split(/[\n,]/).map(item => item.trim()).filter(Boolean) });
  const signingSecrets = [input.signingSecret, input.previousSigningSecret].filter(item => item !== '');
  if (signingSecrets.length < 1 || signingSecrets.length > 2 || new Set(signingSecrets).size !== signingSecrets.length || !signingSecrets.every(item => /^whsec_[A-Za-z0-9_+/=-]{16,240}$/.test(item))) throw new Error('Enter one or two distinct Stripe webhook signing secrets in the protected fields.');
  return { appId: input.appId, scope: selected, signingSecrets };
}
export async function validateStripeReview(value: unknown, connection: ConnectionRecord, appId: string, origin: string, action: Approval['action'], at = Date.now(), retained?: StripeEndpoint, expectedScope?: Scope): Promise<StripeReview> {
  const item = object(value); exact(item, action === 'activate' ? ['approval', 'policy', 'activeApprovalId', 'status'] : ['approval', 'policy', 'activeApprovalId']);
  validateStripeOrigin(origin);
  const checked = policy(item.policy, appId, connection.id, action === 'activate' ? origin : undefined), approval = object(item.approval);
  exact(approval, ['id', 'endpointId', 'appId', 'connectionId', 'action', 'artifactHash', 'createdAt', 'expiresAt', 'approvedAt', 'approvedBy', 'consumedAt']);
  if (typeof approval.id !== 'string' || !uuid.test(approval.id) || approval.endpointId !== checked.endpointId || approval.appId !== appId || approval.connectionId !== connection.id || approval.action !== action || typeof approval.artifactHash !== 'string' || !hex.test(approval.artifactHash) || !time(approval.createdAt) || !time(approval.expiresAt) || Date.parse(approval.createdAt) > at || Date.parse(approval.expiresAt) - Date.parse(approval.createdAt) !== 300000 || Date.parse(approval.expiresAt) <= at || approval.approvedAt !== null || approval.approvedBy !== null || approval.consumedAt !== null) throw bad();
  if (action === 'activate') {
    if (!registryAllowsApp(connection, appId, at) || item.status !== 'pending' || item.activeApprovalId !== null || checked.registryHash !== await stripeArtifactHash(connection) || expectedScope && await stripeArtifactHash(checked.scope) !== await stripeArtifactHash(expectedScope)) throw bad();
  } else if (!retained || retained.status !== 'active' || item.activeApprovalId !== retained.activeApprovalId || typeof item.activeApprovalId !== 'string' || !uuid.test(item.activeApprovalId) || await stripeArtifactHash(checked) !== await stripeArtifactHash(retained.policy)) throw bad();
  if (approval.artifactHash !== await stripeArtifactHash({ schemaVersion: 1, action, policy: checked, activeApprovalId: item.activeApprovalId })) throw bad();
  return item as StripeReview;
}
export function validateStripeEndpoints(value: unknown, connectionId: string, appId: string, origin: string): StripeEndpointPage {
  validateStripeOrigin(origin);
  const item = object(value); exact(item, ['endpoints', 'nextCursor']);
  if (!Array.isArray(item.endpoints) || item.endpoints.length > 100 || item.nextCursor !== null && (typeof item.nextCursor !== 'string' || !uuid.test(item.nextCursor))) throw bad();
  const seen = new Set<string>();
  const endpoints = item.endpoints.map(value => {
    const endpoint = object(value); exact(endpoint, ['policy', 'status', 'activeApprovalId', 'activatedAt', 'withdrawnAt']);
    const checked = policy(endpoint.policy, appId, connectionId);
    if (seen.has(checked.endpointId) || !['pending', 'active', 'withdrawn'].includes(endpoint.status as string)) throw bad(); seen.add(checked.endpointId);
    if (endpoint.status === 'pending' ? endpoint.activeApprovalId !== null || endpoint.activatedAt !== null || endpoint.withdrawnAt !== null : typeof endpoint.activeApprovalId !== 'string' || !uuid.test(endpoint.activeApprovalId) || !time(endpoint.activatedAt) || (endpoint.status === 'active' ? endpoint.withdrawnAt !== null : !time(endpoint.withdrawnAt) || Date.parse(endpoint.withdrawnAt) < Date.parse(endpoint.activatedAt))) throw bad();
    return endpoint as StripeEndpoint;
  });
  if (item.nextCursor !== null && (endpoints.length !== 100 || item.nextCursor !== endpoints.at(-1)?.policy.endpointId)) throw bad();
  return { endpoints, nextCursor: item.nextCursor as string | null };
}
export function appendStripeEndpointPage(current: StripeEndpoint[], page: StripeEndpointPage, cursor: string | null): StripeEndpoint[] {
  if (cursor === null) return page.endpoints;
  if (!current.some(endpoint => endpoint.policy.endpointId === cursor) || !page.endpoints.length) throw bad();
  const seen = new Set(current.map(endpoint => endpoint.policy.endpointId));
  for (const endpoint of page.endpoints) if (seen.has(endpoint.policy.endpointId)) throw bad(); else seen.add(endpoint.policy.endpointId);
  return [...current, ...page.endpoints];
}
export async function readStripeEndpointPage(connectionId: string, appId: string, origin: string, cursor: string | null, call: Call = api, current: () => boolean = () => true): Promise<StripeEndpointPage> {
  validateStripeOrigin(origin);
  if (!uuid.test(connectionId) || !uuid.test(appId) || cursor !== null && !uuid.test(cursor) || !current()) throw bad();
  const value = await call(`/connections/${encodeURIComponent(connectionId)}/stripe/webhooks?appId=${encodeURIComponent(appId)}${cursor === null ? '' : `&cursor=${encodeURIComponent(cursor)}`}`);
  if (!current()) throw bad();
  return validateStripeEndpoints(value, connectionId, appId, origin);
}
export async function prepareStripeReview(input: StripeSetup, connection: ConnectionRecord, app: AppRecord | undefined, canProvision: boolean, origin: string, clearSecrets: () => void, call: Call = api, clock: () => number = Date.now, current: () => boolean = () => true): Promise<StripeReview> {
  try { validateStripeOrigin(origin); if (!current()) throw bad(); const body = stripeSetupBody(input, connection, app, canProvision, clock()); const result = await call(`/connections/${encodeURIComponent(connection.id)}/stripe/webhook-reviews`, { method: 'POST', body }); if (!current()) throw bad(); return await validateStripeReview(result, connection, input.appId, origin, 'activate', clock(), undefined, body.scope); }
  finally { clearSecrets(); }
}
export class StripeSubmissionUncertain extends Error { constructor() { super('The endpoint outcome needs inspection. The approval may already be retained; inspect this exact endpoint instead of submitting it again.'); } }
const dispatched = new Set<string>();
export async function submitStripeReview(review: StripeReview, connection: ConnectionRecord, appId: string, origin: string, canProvision: boolean, retained?: StripeEndpoint, call: Call = api, clock: () => number = Date.now, current: () => boolean = () => true): Promise<StripeEndpoint> {
  if (!canProvision || !current()) throw new Error('Permanent-owner MFA is required.');
  const checked = await validateStripeReview(review, connection, appId, origin, review.approval.action, clock(), retained);
  if (!current()) throw bad();
  if (dispatched.has(checked.approval.id)) throw new StripeSubmissionUncertain();
  dispatched.add(checked.approval.id);
  try {
    const result = object(await call(`/stripe/webhook-reviews/${encodeURIComponent(checked.approval.id)}/approve`, { method: 'POST', body: { artifactHash: checked.approval.artifactHash } }));
    exact(result, ['policy', 'status', 'approval', 'activeApprovalId']); const receipt = object(result.approval);
    exact(receipt, ['id', 'endpointId', 'appId', 'connectionId', 'action', 'artifactHash', 'createdAt', 'expiresAt', 'approvedAt', 'approvedBy', 'consumedAt']);
    for (const key of ['id', 'endpointId', 'appId', 'connectionId', 'action', 'artifactHash', 'createdAt', 'expiresAt'] as const) if (receipt[key] !== checked.approval[key]) throw bad();
    if (!time(receipt.approvedAt) || receipt.consumedAt !== receipt.approvedAt || Date.parse(receipt.approvedAt) < Date.parse(checked.approval.createdAt) || Date.parse(receipt.approvedAt) >= Date.parse(checked.approval.expiresAt) || Date.parse(receipt.approvedAt) > clock() || typeof receipt.approvedBy !== 'string' || receipt.approvedBy.length < 1 || receipt.approvedBy.length > 256 || await stripeArtifactHash(result.policy) !== await stripeArtifactHash(checked.policy) || result.status !== (checked.approval.action === 'activate' ? 'active' : 'withdrawn') || result.activeApprovalId !== (checked.approval.action === 'activate' ? checked.approval.id : checked.activeApprovalId)) throw bad();
    return { policy: checked.policy, status: result.status as StripeEndpoint['status'], activeApprovalId: result.activeApprovalId as string, activatedAt: checked.approval.action === 'activate' ? receipt.approvedAt : retained!.activatedAt, withdrawnAt: checked.approval.action === 'withdraw' ? receipt.approvedAt : null };
  } catch { throw new StripeSubmissionUncertain(); }
}
type Fence = { endpointId: string; action: Approval['action']; expiresAt: string };
function readFence(key: string): Fence | undefined { try { const raw = sessionStorage.getItem(key); if (!raw) return; const item = object(JSON.parse(raw)); exact(item, ['endpointId', 'action', 'expiresAt']); if (typeof item.endpointId === 'string' && uuid.test(item.endpointId) && ['activate', 'withdraw'].includes(item.action as string) && time(item.expiresAt)) return item as Fence; } catch { /* No credentials are stored. In-memory fence still protects this instance. */ } }
function storeFence(key: string, fence?: Fence) { try { if (fence) sessionStorage.setItem(key, JSON.stringify(fence)); else sessionStorage.removeItem(key); } catch { /* Keep the in-memory fence. */ } }
export function stripeFenceResolved(fence: Fence, endpoints: StripeEndpoint[], at: number): boolean { const endpoint = endpoints.find(item => item.policy.endpointId === fence.endpointId); return Boolean(endpoint && endpoint.status === (fence.action === 'activate' ? 'active' : 'withdrawn') || Date.parse(fence.expiresAt) <= at); }

export default function StripeWebhooks({ connection, apps, selectedApp, canProvision }: { connection: ConnectionRecord; apps: AppRecord[]; selectedApp?: AppRecord; canProvision: boolean }) {
  const [appId, setAppId] = useState(selectedApp?.id ?? connection.appIds[0] ?? ''), [secret, setSecret] = useState(''), [previousSecret, setPreviousSecret] = useState(''), [account, setAccount] = useState(''), [live, setLive] = useState(false), [events, setEvents] = useState(''), [endpoints, setEndpoints] = useState<StripeEndpoint[]>([]), [nextCursor, setNextCursor] = useState<string | null>(null), [review, setReview] = useState<StripeReview>(), [reviewed, setReviewed] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState<string>(), [stateReady, setStateReady] = useState(false), [fence, setFence] = useState<Fence>(), [now, setNow] = useState(Date.now());
  const fences = useRef<Record<string, Fence>>({}), key = `autosoft.stripe-webhook.${connection.id}.${appId}`;
  const applicationOptions = [...apps, ...(selectedApp && !apps.some(item => item.id === selectedApp.id) ? [selectedApp] : [])];
  const origin = typeof window === 'undefined' ? '' : window.location.origin, app = applicationOptions.find(item => item.id === appId);
  let secureOrigin = false; try { validateStripeOrigin(origin); secureOrigin = true; } catch { /* Setup is disabled before secret entry. */ }
  const eligible = secureOrigin && eligibleStripeApp(connection, app, now), identity = JSON.stringify({ key, canProvision, origin, connection, app });
  const view = useRef({ identity, epoch: 0 }); if (view.current.identity !== identity) view.current = { identity, epoch: view.current.epoch + 1 };
  const clearSecrets = () => { setSecret(''); setPreviousSecret(''); };
  useEffect(() => { clearSecrets(); setReview(undefined); setReviewed(false); setEndpoints([]); setNextCursor(null); setStateReady(false); setBusy(false); setError(undefined); setFence(fences.current[key] ?? readFence(key)); }, [identity]);
  useEffect(() => { if (!review) return; const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, [review]);
  async function inspect(cursor: string | null = null) {
    if (!canProvision || !secureOrigin || !uuid.test(appId) || busy) return; const epoch = view.current.epoch, current = () => view.current.epoch === epoch; setBusy(true); setError(undefined);
    try { const page = await readStripeEndpointPage(connection.id, appId, origin, cursor, api, current); if (!current()) return; const result = appendStripeEndpointPage(endpoints, page, cursor); setEndpoints(result); setNextCursor(page.nextCursor); setStateReady(true); const held = fences.current[key] ?? readFence(key); if (held && stripeFenceResolved(held, result, Date.now())) { delete fences.current[key]; storeFence(key); setFence(undefined); } }
    catch { if (current()) { setStateReady(false); setError('Retained endpoint state could not be confirmed. No approval was sent.'); } } finally { if (current()) setBusy(false); }
  }
  async function prepare(event: React.FormEvent) {
    event.preventDefault(); if (!canProvision || !secureOrigin || busy || !stateReady || fence) { clearSecrets(); return; } const epoch = view.current.epoch, current = () => view.current.epoch === epoch; setBusy(true); setError(undefined);
    try { const result = await prepareStripeReview({ appId, account, live, events, signingSecret: secret, previousSigningSecret: previousSecret }, connection, app, canProvision, origin, () => { if (current()) clearSecrets(); }, api, Date.now, current); if (current()) { setReview(result); setReviewed(false); } }
    catch { if (current()) { setStateReady(false); setError('The review could not be confirmed. Signing secrets were cleared. Inspect retained endpoints before entering them again.'); } } finally { if (current()) { clearSecrets(); setBusy(false); } }
  }
  async function withdraw(endpoint: StripeEndpoint) {
    if (!canProvision || !secureOrigin || busy || fence || !stateReady || endpoint.status !== 'active') return; const epoch = view.current.epoch, current = () => view.current.epoch === epoch; setBusy(true); setError(undefined);
    try { const value = await api(`/stripe/webhooks/${encodeURIComponent(endpoint.policy.endpointId)}/withdrawal-review`, { method: 'POST', body: {} }); if (!current()) return; const result = await validateStripeReview(value, connection, appId, origin, 'withdraw', Date.now(), endpoint); if (current()) { setReview(result); setReviewed(false); } }
    catch { if (current()) setError('An exact withdrawal review could not be confirmed. Inspect the retained endpoint.'); } finally { if (current()) { clearSecrets(); setBusy(false); } }
  }
  async function submit() {
    if (!canProvision || !secureOrigin || busy || !review || !reviewed || fence) return;
    if (review.approval.action === 'activate' && !eligibleStripeApp(connection, app, Date.now())) { clearSecrets(); setReview(undefined); setError('The current application or connection scope changed. No activation was submitted.'); return; }
    const epoch = view.current.epoch, current = () => view.current.epoch === epoch; setBusy(true); setError(undefined); const intent = { endpointId: review.policy.endpointId, action: review.approval.action, expiresAt: review.approval.expiresAt }; fences.current[key] = intent; storeFence(key, intent); setFence(intent); setReview(undefined); clearSecrets();
    try { const endpoint = await submitStripeReview(review, connection, appId, origin, canProvision, endpoints.find(item => item.policy.endpointId === review.policy.endpointId), api, Date.now, current); if (!current()) return; setEndpoints([endpoint]); setNextCursor(null); delete fences.current[key]; storeFence(key); setFence(undefined); setStateReady(false); setError('The exact approval is confirmed. Inspect retained endpoints again to refresh all history pages.'); }
    catch { if (current()) { setStateReady(false); setError(new StripeSubmissionUncertain().message); } } finally { if (current()) setBusy(false); }
  }
  return <div className="settings-card form-stack"><h2>{connection.name}: Stripe webhook endpoints</h2><p>Receive verified API v1 snapshot event metadata for an exact app, account and event scope. This does not send payments or email. API v2 thin events are unsupported. Public HTTPS reachability requires a separate installation check.</p>
    {!canProvision ? <p className="field-hint">Sign in as the permanent local owner with MFA to inspect, review or withdraw Stripe webhook endpoints.</p> : <>
      <label>Webhook application<select value={appId} disabled={busy} onChange={event => setAppId(event.target.value)}><option value="">Choose an application</option>{applicationOptions.map(item => <option key={item.id} value={item.id}>{item.name}{eligibleStripeApp(connection, item, now) ? '' : ' · setup unavailable'}</option>)}</select></label>
      {!secureOrigin && <p className="field-hint">Use the exact HTTPS admin origin before entering signing secrets or managing endpoints. Secret entry and setup are disabled here.</p>}
      <button type="button" className="button button-secondary" disabled={busy || !secureOrigin || !appId} onClick={() => { void inspect(); }}>Inspect retained endpoints</button>
      {nextCursor && <button type="button" className="button button-secondary" disabled={busy || !secureOrigin || !stateReady} onClick={() => { void inspect(nextCursor); }}>Load next 100 retained endpoints</button>}
      {error && <ErrorBanner message={error} />}{fence && <p className="field-hint">This exact {fence.action === 'activate' ? 'activation' : 'withdrawal'} may already be retained. Inspect its endpoint; the submitted approval is never replayed. A fresh review requires resolved state or expiry of the original five-minute review.</p>}
      {stateReady && endpoints.length === 0 && <p className="field-hint">No retained endpoint exists for this application and connection.</p>}
      {endpoints.map(endpoint => <div className="form-stack" key={endpoint.policy.endpointId}><div><Badge tone={endpoint.status === 'active' ? 'green' : endpoint.status === 'withdrawn' ? 'red' : 'amber'}>{endpoint.status === 'active' ? 'Metadata ingress enabled' : endpoint.status === 'withdrawn' ? 'Endpoint withdrawn' : 'Pending owner review'}</Badge></div><code>{endpoint.policy.url}</code><p className="field-hint">Approved historical scope: {endpoint.policy.scope.live ? 'Live events' : 'Test events'} · {endpoint.policy.scope.account ?? 'Platform account'} · {endpoint.policy.scope.eventTypes.join(', ')}. Reachability and provider delivery are unverified.</p>{!eligible && <p className="field-hint">Current app or connection scope is unavailable for setup. This exact retained endpoint can still be withdrawn.</p>}{endpoint.policy.url !== `${origin}/webhooks/stripe/${endpoint.policy.endpointId}` && <p className="field-hint">This endpoint retains its approved historical HTTPS origin. Withdrawal stops that exact endpoint; new setup uses the current admin origin.</p>}{endpoint.status === 'active' && <button type="button" className="button button-secondary" disabled={busy || Boolean(fence) || !stateReady} onClick={() => { void withdraw(endpoint); }}>Review withdrawal of this endpoint</button>}</div>)}
      <form className="form-stack" onSubmit={event => { void prepare(event); }}><h3>Prepare a new immutable endpoint</h3>{!eligible && <p className="field-hint">Setup requires an active application in this configured Stripe connection’s webhooks.receive scope. Retained endpoints can still be inspected and withdrawn.</p>}
        <div className="form-columns"><label>Stripe connected account (optional)<input value={account} onChange={event => setAccount(event.target.value)} disabled={busy || !eligible} placeholder="acct_…" autoComplete="off" maxLength={165} /><span className="field-hint">Leave empty for this Stripe platform account.</span></label><label>Event environment<select value={live ? 'live' : 'test'} onChange={event => setLive(event.target.value === 'live')} disabled={busy || !eligible}><option value="test">Test events</option><option value="live">Live events</option></select></label></div>
        <label>Exact event types<textarea required value={events} onChange={event => setEvents(event.target.value)} disabled={busy || !eligible} rows={3} maxLength={10304} placeholder="invoice.paid" /><span className="field-hint">One exact event type per line, up to 64. Wildcards are unavailable.</span></label>
        <div className="form-columns"><label>Webhook signing secret<input required type="password" autoComplete="new-password" spellCheck={false} value={secret} onChange={event => setSecret(event.target.value)} disabled={busy || !eligible} maxLength={246} placeholder="whsec_…" /></label><label>Second signing secret (optional)<input type="password" autoComplete="new-password" spellCheck={false} value={previousSecret} onChange={event => setPreviousSecret(event.target.value)} disabled={busy || !eligible} maxLength={246} placeholder="whsec_…" /></label></div><p className="field-hint">For Stripe signing-secret overlap, enter one or two distinct secrets here. They are cleared after every submission and never included in the review. To replace an active endpoint, approve a new one and separately withdraw the old endpoint.</p>
        <button className="button button-secondary" type="submit" disabled={busy || !eligible || !stateReady || Boolean(fence)}>{busy ? 'Preparing…' : 'Review exact webhook scope'}</button>
      </form>
      {review && <Modal title={review.approval.action === 'activate' ? 'Review Stripe webhook activation' : 'Review Stripe webhook withdrawal'} description="Only the permanent owner with MFA can approve this exact five-minute artifact." wide busy={busy} onClose={() => { if (!busy) setReview(undefined); }}><div className="form-stack"><p>{review.approval.action === 'activate' ? 'Enable authenticated snapshot event metadata for this exact endpoint. Provider payments, email and other actions are not authorized.' : 'Permanently stop accepting deliveries at this exact endpoint. Retained event metadata and other endpoints remain.'}</p><dl className="detail-grid"><div><dt>Application</dt><dd>{app?.name ?? appId}</dd></div><div><dt>Connection</dt><dd>{connection.name}</dd></div><div><dt>Exact HTTPS URL</dt><dd><code>{review.policy.url}</code></dd></div><div><dt>Account and mode</dt><dd>{review.policy.scope.account ?? 'Platform account'} · {review.policy.scope.live ? 'Live' : 'Test'}</dd></div><div><dt>Event types</dt><dd>{review.policy.scope.eventTypes.join(', ')}</dd></div><div><dt>Review expiry</dt><dd>{formatDate(review.approval.expiresAt, true)}</dd></div></dl><details><summary>Exact review bindings</summary><p className="field-hint">Registry {review.policy.registryHash}<br />Artifact {review.approval.artifactHash}<br />Credential binding {review.policy.credentialBinding}<br />Protected credential version {review.policy.credentialEnvelopeHash}<br />Active approval {review.activeApprovalId ?? 'New endpoint'}</p></details><label className="checkbox-label"><input type="checkbox" checked={reviewed} disabled={busy} onChange={event => setReviewed(event.target.checked)} />I reviewed this exact URL, app, connection, account, environment and event scope.</label><div className="modal-actions"><button type="button" className="button button-secondary" disabled={busy} onClick={() => setReview(undefined)}>Cancel review</button><button type="button" className="button button-primary" disabled={busy || !reviewed || Date.parse(review.approval.expiresAt) <= now} onClick={() => { void submit(); }}>{busy ? 'Submitting…' : review.approval.action === 'activate' ? 'Approve & enable metadata ingress' : 'Approve & withdraw this endpoint'}</button></div></div></Modal>}
    </>}
  </div>;
}
