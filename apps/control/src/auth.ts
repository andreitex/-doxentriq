import { randomBytes, createHash, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Principal } from '../../../packages/core/src/types.ts';
import type { Config } from './config.ts';
import type { Store, Session } from './store.ts';
import { requireCurrentCandidatePreview } from './preview.ts';
import { directoryAuthorizationPath } from './directory-route.ts';

declare module 'fastify' { interface FastifyRequest { principal: Principal | null; session: Session | null; } }
const previewCookieName = '__Host-autosoft-preview';
const nonce = () => randomBytes(32).toString('base64url');
const tokenHash = (value: string) => createHash('sha256').update(value).digest('hex');
function equal(left: string, right: string): boolean { const a = Buffer.from(left); const b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }
function httpError(statusCode: number, message: string): Error & { statusCode: number } { return Object.assign(new Error(message), { statusCode }); }
const unexpired = (value: string | undefined) => !!value && Number.isFinite(Date.parse(value)) && Date.parse(value) > Date.now();
class OwnerMfaRequired extends Error { readonly statusCode = 403; constructor() { super('Sign in afresh with your owner password and authenticator or recovery code. Enrollment alone does not verify multi-factor authentication.'); } }

export async function installAuth(server: FastifyInstance, store: Store, config: Config): Promise<void> {
  const cookieName = config.authMode === 'oidc' ? '__Host-autosoft-session' : 'autosoft_session';
  const stateCookieName = config.authMode === 'oidc' ? '__Host-autosoft-oauth-state' : 'autosoft_oauth_state';
  server.decorateRequest('principal', null); server.decorateRequest('session', null);
  const developmentPrincipal: Principal = { id: 'development-owner', name: 'Local development owner', roles: ['platform-owner'], localOwner: true, mfa: true };
  const cookieOptions = { httpOnly: true, secure: config.authMode === 'oidc', sameSite: 'lax' as const, path: '/' };
  type Metadata = { authorization_endpoint: string; token_endpoint: string; jwks_uri: string; issuer: string };
  let metadata: Metadata | null = null;
  let keys: ReturnType<typeof createRemoteJWKSet> | null = null;
  const refreshLocks = new Map<string, Promise<Session>>();
  function sealRefresh(token: string, sessionId: string): string {
    const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', config.secretKey, iv); cipher.setAAD(Buffer.from(sessionId));
    const data = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]); return [iv, cipher.getAuthTag(), data].map(value => value.toString('base64')).join('.');
  }
  function openRefresh(envelope: string, sessionId: string): string {
    const [iv, tag, data] = envelope.split('.'); const decipher = createDecipheriv('aes-256-gcm', config.secretKey, Buffer.from(iv!, 'base64')); decipher.setAAD(Buffer.from(sessionId)); decipher.setAuthTag(Buffer.from(tag!, 'base64')); return Buffer.concat([decipher.update(Buffer.from(data!, 'base64')), decipher.final()]).toString('utf8');
  }
  async function verifiedPrincipal(accessToken: string): Promise<{ principal: Principal; expiresAt: string; sub: string }> {
    if (!keys) await discover();
    const access = await jwtVerify(accessToken, keys!, { issuer: config.oidcIssuer, audience: config.oidcClientId, algorithms: ['RS256', 'PS256', 'ES256'] }).catch(() => { throw httpError(401, 'Identity token verification failed.'); });
    if (!access.payload.sub || !access.payload.exp) throw httpError(401, 'Identity provider returned an incomplete token.');
    const realm = access.payload.realm_access as { roles?: string[] } | undefined; const roles = realm?.roles ?? [];
    const amr = Array.isArray(access.payload.amr) ? access.payload.amr as string[] : [];
    const mfa = access.payload.autosoft_mfa === true || amr.some(method => ['otp', 'mfa', 'totp'].includes(method)) || !!(config.mfaAcr && access.payload.acr === config.mfaAcr);
    const localOwner = access.payload.sub === config.ownerSubject && !access.payload.identity_provider;
    if (access.payload.sub === config.ownerSubject && !localOwner) throw httpError(403, 'The permanent local owner must sign in with its local account and MFA.');
    if (localOwner && !mfa) throw new OwnerMfaRequired();
    const brokeredAdmin = ['microsoft', 'google'].includes(String(access.payload.identity_provider ?? '')) && roles.includes('platform-admin');
    if ((!localOwner && !brokeredAdmin) || !mfa) throw httpError(403, 'Authorized platform administration with MFA is required; additional administrators must use Google or Microsoft SSO.');
    return { principal: { id: access.payload.sub, name: String(access.payload.name ?? access.payload.preferred_username ?? 'Administrator'), roles, localOwner, mfa }, expiresAt: new Date(access.payload.exp * 1000).toISOString(), sub: access.payload.sub };
  }
  async function discover() {
    if (metadata) return metadata;
    const response = await fetch(`${config.oidcIssuer}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10000), redirect: 'error' });
    if (!response.ok) throw httpError(503, 'Identity provider is unavailable.');
    const discovered = await response.json() as Metadata;
    if (discovered.issuer !== config.oidcIssuer) throw httpError(503, 'Identity provider issuer mismatch.');
    for (const endpoint of [discovered.authorization_endpoint, discovered.token_endpoint, discovered.jwks_uri]) if (new URL(endpoint).origin !== new URL(config.oidcIssuer!).origin) throw httpError(503, 'Identity endpoint leaves the configured authority.');
    keys = createRemoteJWKSet(new URL(discovered.jwks_uri)); metadata = discovered; return metadata;
  }
  async function refreshSession(session: Session): Promise<Session> {
    const existing = refreshLocks.get(session.id); if (existing) return existing;
    const pending = (async () => {
      if (!session.encryptedRefreshToken) throw httpError(401, 'Sign in to continue.');
      const provider = await discover(); const body = new URLSearchParams({ grant_type: 'refresh_token', client_id: config.oidcClientId, refresh_token: openRefresh(session.encryptedRefreshToken, session.id) }); if (config.oidcClientSecret) body.set('client_secret', config.oidcClientSecret);
      const response = await fetch(provider.token_endpoint, { method: 'POST', body, signal: AbortSignal.timeout(10000), redirect: 'error' });
      if (!response.ok) throw httpError(401, 'The identity session ended. Sign in again.');
      const tokens = await response.json() as { access_token?: string; refresh_token?: string };
      if (!tokens.access_token) throw httpError(401, 'Identity provider returned no refreshed access token.');
      const verified = await verifiedPrincipal(tokens.access_token); if (verified.sub !== session.principal.id) throw httpError(401, 'Refreshed identity changed.');
      const updated: Session = { ...session, principal: verified.principal, accessExpiresAt: verified.expiresAt, encryptedRefreshToken: tokens.refresh_token ? sealRefresh(tokens.refresh_token, session.id) : session.encryptedRefreshToken };
      await store.transaction(state => { if (!state.sessions[session.id]) throw httpError(401, 'Session ended.'); state.sessions[session.id] = updated; }); return updated;
    })(); refreshLocks.set(session.id, pending);
    try { return await pending; } catch (error) { await store.transaction(state => { delete state.sessions[session.id]; }); throw error; } finally { refreshLocks.delete(session.id); }
  }
  server.addHook('onRequest', async (request, reply) => {
    if (!request.url.startsWith('/api/')) return;
    const path = request.url.split('?')[0];
    if (path === '/api/public/v1/apps' && request.method === 'GET') return;
    if (request.method === 'POST' && request.headers.host === 'control:3000' && directoryAuthorizationPath(path)) return;
    if (request.method === 'POST' && ['/api/public/v1/invitations/inspect', '/api/public/v1/invitations/accept'].includes(path!)) return;
    if (path === '/api/auth/preview/exchange' && request.method === 'GET') return;
    const previewHost = request.headers['x-autosoft-preview-host'];
    if (path === '/api/auth/check' && typeof previewHost === 'string') {
      const cookie = request.cookies[previewCookieName];
      if (!cookie || !/^[a-zA-Z0-9_-]{43}$/.test(cookie)) throw httpError(401, 'Launch this preview from the administration page.');
      const preview = await store.read(state => state.previewSessions[tokenHash(cookie)]);
      if (!preview || preview.host !== previewHost || preview.host !== request.headers.host || !unexpired(preview.expiresAt)) throw httpError(401, 'Preview access has expired or belongs to another application.');
      let original = await store.read(state => state.sessions[preview.sessionId]);
      if (!original || !unexpired(original.expiresAt)) throw httpError(401, 'The administration session ended.');
      if (config.authMode === 'oidc' && (!original.accessExpiresAt || !Number.isFinite(Date.parse(original.accessExpiresAt)))) throw httpError(401, 'The verified identity session is incomplete. Sign in again.');
      if (original.accessExpiresAt && Date.parse(original.accessExpiresAt) <= Date.now() + 15000) original = await refreshSession(original);
      if (!original.principal.mfa || (!original.principal.localOwner && !original.principal.roles.includes('platform-admin'))) throw httpError(403, 'Administrator access with MFA is required.');
      const app = await store.read(state => state.apps[preview.appId]);
      if (!app?.previewUrl || !preview.releaseId || app.previewReleaseId !== preview.releaseId || new URL(app.previewUrl).host !== preview.host) throw httpError(401, 'This application preview is no longer available.');
      request.principal = { ...original.principal, appId: preview.appId }; return;
    }
    if (config.authMode === 'development') {
      const remote = request.ip; if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(remote)) throw httpError(403, 'Development mode accepts only local connections.');
      let session = request.cookies[cookieName] ? await store.read(state => state.sessions[request.cookies[cookieName]!]) : undefined;
      if (!session || !unexpired(session.expiresAt)) {
        session = { id: nonce(), principal: developmentPrincipal, csrfToken: nonce(), expiresAt: new Date(Date.now() + 8 * 3600000).toISOString() };
        await store.transaction(state => { state.sessions[session!.id] = session!; }); reply.setCookie(cookieName, session.id, cookieOptions);
      }
      request.session = session; request.principal = developmentPrincipal;
    } else {
      const id = request.cookies[cookieName]; let session = id ? await store.read(state => state.sessions[id]) : undefined;
      if (!session || !unexpired(session.expiresAt)) throw httpError(401, 'Sign in to continue.');
      if (!session.accessExpiresAt || !Number.isFinite(Date.parse(session.accessExpiresAt))) throw httpError(401, 'The verified identity session is incomplete. Sign in again.');
      if (session.accessExpiresAt && new Date(session.accessExpiresAt).getTime() <= Date.now() + 15000) session = await refreshSession(session);
      request.session = session; request.principal = session.principal;
    }
    if (!request.principal.localOwner && !request.principal.roles.includes('platform-admin')) throw httpError(403, 'Platform administrator authorization is required.');
    if (!request.principal.mfa) throw httpError(403, 'Multi-factor authentication is required.');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
      if (request.headers.origin !== config.publicOrigin) throw httpError(403, 'The request origin is not authorized.');
      const csrf = request.headers['x-csrf-token']; if (typeof csrf !== 'string' || !equal(csrf, request.session.csrfToken)) throw httpError(403, 'Refresh the page before submitting this action.');
    }
  });
  server.get('/auth/login', async (request, reply) => {
    if (config.authMode === 'development') return reply.redirect('/');
    const provider = await discover(); const state = nonce(); const verifier = nonce(); const value = nonce();
    await store.transaction(data => { data.authStates[state] = { verifier, nonce: value, expiresAt: new Date(Date.now() + 600000).toISOString() }; });
    reply.setCookie(stateCookieName, state, { ...cookieOptions, maxAge: 600 });
    const target = new URL(provider.authorization_endpoint);
    target.search = new URLSearchParams({ client_id: config.oidcClientId, redirect_uri: `${config.publicOrigin}/auth/callback`, response_type: 'code', scope: 'openid profile email', state, nonce: value, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
    if ((request.query as { reauthenticate?: string }).reauthenticate === '1') target.searchParams.set('prompt', 'login');
    return reply.redirect(target.toString());
  });
  server.get('/auth/callback', async (request, reply) => {
    if (config.authMode !== 'oidc') throw httpError(404, 'OIDC is not configured.');
    const query = request.query as { state?: string; code?: string };
    if (!query.state || !query.code || !request.cookies[stateCookieName] || !equal(query.state, request.cookies[stateCookieName]!)) throw httpError(400, 'Invalid sign-in callback.');
    const state = await store.transaction(data => { const item = data.authStates[query.state!]; delete data.authStates[query.state!]; return item; });
    if (!state || new Date(state.expiresAt).getTime() <= Date.now()) throw httpError(400, 'Sign-in request expired.');
    const provider = await discover(); const body = new URLSearchParams({ grant_type: 'authorization_code', code: query.code, client_id: config.oidcClientId, redirect_uri: `${config.publicOrigin}/auth/callback`, code_verifier: state.verifier });
    if (config.oidcClientSecret) body.set('client_secret', config.oidcClientSecret);
    const response = await fetch(provider.token_endpoint, { method: 'POST', body, signal: AbortSignal.timeout(10000), redirect: 'error' });
    if (!response.ok) throw httpError(401, 'Identity provider rejected the sign-in.');
    const tokens = await response.json() as { id_token?: string; access_token?: string; refresh_token?: string };
    if (!tokens.id_token || !tokens.access_token || !keys) throw httpError(401, 'Identity provider did not return required tokens.');
    const id = await jwtVerify(tokens.id_token, keys, { issuer: config.oidcIssuer, audience: config.oidcClientId, algorithms: ['RS256', 'PS256', 'ES256'] }).catch(() => { throw httpError(401, 'Sign-in token verification failed.'); });
    if (id.payload.nonce !== state.nonce) throw httpError(401, 'Sign-in nonce mismatch.');
    let verified: Awaited<ReturnType<typeof verifiedPrincipal>>;
    try { verified = await verifiedPrincipal(tokens.access_token); }
    catch (error) {
      if (!(error instanceof OwnerMfaRequired)) throw error;
      reply.clearCookie(stateCookieName, cookieOptions);
      return reply.redirect('/?signin=mfa');
    }
    if (verified.sub !== id.payload.sub) throw httpError(401, 'Token subject mismatch.');
    const principal = { ...verified.principal, name: String(id.payload.name ?? id.payload.preferred_username ?? verified.principal.name) };
    const session: Session = { id: nonce(), principal, csrfToken: nonce(), expiresAt: new Date(Date.now() + 3600000).toISOString(), accessExpiresAt: verified.expiresAt }; if (tokens.refresh_token) session.encryptedRefreshToken = sealRefresh(tokens.refresh_token, session.id); await store.transaction(data => { data.sessions[session.id] = session; });
    reply.clearCookie(stateCookieName, cookieOptions); reply.setCookie(cookieName, session.id, cookieOptions); return reply.redirect('/');
  });
  server.post('/api/v1/logout', async (request, reply) => { if (request.session) await store.transaction(state => { delete state.sessions[request.session!.id]; }); reply.clearCookie(cookieName, cookieOptions); return { ok: true }; });
  server.get('/api/v1/session', async request => ({ principal: request.principal, csrfToken: request.session?.csrfToken, mode: config.authMode }));
  server.get('/api/v1/apps/:id/preview-launch', async (request, reply) => {
    if (!request.session || !request.principal?.mfa) throw httpError(403, 'An authenticated administrator with MFA must launch previews.');
    const { id } = request.params as { id: string }; const app = await store.read(state => state.apps[id]);
    if (!app?.previewUrl) throw httpError(404, 'A verified preview is not available for this application.');
    const { releaseId } = request.query as { releaseId?: string };
    if (!app.previewReleaseId || (releaseId !== undefined && releaseId !== app.previewReleaseId)) throw httpError(409, 'This release no longer has the current application preview.');
    const release = await store.read(state => state.releases[app.previewReleaseId!]);
    if (!release || release.appId !== app.id) throw httpError(409, 'The verified preview release identity is unavailable.');
    requireCurrentCandidatePreview(app, release);
    let target: URL; try { target = new URL(app.previewUrl); } catch { throw httpError(409, 'The stored preview address is invalid.'); }
    const appsOrigin = config.appsOrigin ? new URL(config.appsOrigin) : null;
    if (!appsOrigin || target.protocol !== 'https:' || target.username || target.password || target.hostname !== `preview-${app.slug}.${appsOrigin.hostname}` || target.port !== appsOrigin.port) throw httpError(409, 'The preview address does not match this installation and application.');
    const ticket = nonce();
    await store.transaction(state => { if (state.apps[app.id]?.previewReleaseId !== release.id) throw httpError(409, 'The current preview changed. Launch the latest candidate.'); state.previewTickets[tokenHash(ticket)] = { appId: app.id, releaseId: release.id, host: target.host, sessionId: request.session!.id, expiresAt: new Date(Date.now() + 30000).toISOString() }; });
    target.pathname = '/__autosoft/preview'; target.search = new URLSearchParams({ ticket }).toString(); target.hash = '';
    reply.header('Cache-Control', 'no-store'); reply.header('Referrer-Policy', 'no-referrer'); return reply.redirect(target.toString());
  });
  server.get('/api/auth/preview/exchange', async (request, reply) => {
    const { ticket } = request.query as { ticket?: string };
    if (!ticket || !/^[a-zA-Z0-9_-]{43}$/.test(ticket)) throw httpError(401, 'The preview ticket is invalid.');
    const value = await store.transaction(state => {
      const digest = tokenHash(ticket); const value = state.previewTickets[digest];
      if (!value || !unexpired(value.expiresAt) || request.headers.host !== value.host) throw httpError(401, 'The preview ticket expired or belongs to another hostname.');
      const session = state.sessions[value.sessionId];
      if (!session || !unexpired(session.expiresAt) || (config.authMode === 'oidc' && !unexpired(session.accessExpiresAt)) || !session.principal.mfa || (!session.principal.localOwner && !session.principal.roles.includes('platform-admin'))) throw httpError(401, 'The administration session is no longer authorized.');
      const app = state.apps[value.appId]; if (!app?.previewUrl || !value.releaseId || app.previewReleaseId !== value.releaseId || new URL(app.previewUrl).host !== value.host) throw httpError(401, 'The preview is no longer available.');
      delete state.previewTickets[digest]; const token = nonce(); const expiresAt = new Date(Math.min(Date.now() + 900000, Date.parse(session.expiresAt))).toISOString();
      state.previewSessions[tokenHash(token)] = { ...value, expiresAt }; return { token, expiresAt };
    });
    reply.header('Cache-Control', 'no-store'); reply.header('Referrer-Policy', 'no-referrer');
    reply.setCookie(previewCookieName, value.token, { httpOnly: true, secure: true, sameSite: 'lax', path: '/', expires: new Date(value.expiresAt), maxAge: 900 }); return reply.redirect('/');
  });
}
export function requireOwner(request: FastifyRequest): void { if (!request.principal?.localOwner || !request.principal.mfa) throw httpError(403, 'The permanent local owner with MFA must approve this action.'); }
