import { assertAuthorityCeiling } from './spending-authority.ts';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import staticFiles from '@fastify/static';
import { randomUUID, createCipheriv, randomBytes } from 'node:crypto';
import { access, readFile } from 'node:fs/promises';
import type { ServerResponse } from 'node:http';
import { z } from 'zod';
import { evaluateReleaseGate, releaseArtifactHash, hashArtifact, redact } from '../../../packages/core/src/index.ts';
import type { AppRecord, ApprovalRecord, ConnectionRecord, JobRecord, Principal, RecoveryGrant } from '../../../packages/core/src/types.ts';
import type { Config } from './config.ts';
import type { Store, State } from './store.ts';
import { event, enqueue, notify } from './store.ts';
import { installAuth, requireOwner } from './auth.ts';
import { budgetSummary, budgetChangeHash, currentMonth, modelBillingReviewRequired, ModelBillingHoldError, type BudgetChange } from './budget.ts';
import type { EngineDependencies } from './engine.ts';
import { installReportRoutes, latestSecurityReports, verifiedCheckpoint, verifiedCheckpointReport } from './reports.ts';
import { reconcileDeployments, failDeployment } from './deployments.ts';
import { installMetrics } from './metrics.ts';
import { requireCurrentCandidatePreview } from './preview.ts';
import { validatedTelemetry } from './telemetry.ts';
import { isPortalHost, publicCatalog, loadPortalAssetWhitelist } from './portal.ts';
import { installPortalListingRoutes } from './portal-listing.ts';
import { slugSchema } from '../../../packages/core/src/schemas.ts';
import { draftRecoveryGrant, recoveryAuthorizationHash, recoveryScanHash, validateDraftRecovery } from './observation.ts';
import { currentDatabaseSchema, recordDatabaseSchema } from './schema-state.ts';
import { installAccessRoutes } from './access.ts';
import { directoryAuthorizationPath } from './directory-route.ts';
import { installConnectorRoutes } from './connectors.ts';
import { installFilesystemRoutes } from './filesystem-connectors.ts';
import { installConnectionRevocationRoutes } from './connection-revocation.ts';
import { installStripeWebhookRoutes } from './stripe-webhooks.ts';
import { knownProtectedValues } from './protected-values.ts';
import { HttpDrain } from './http-drain.ts';

export const error = (statusCode: number, message: string) => Object.assign(new Error(message), { statusCode });
const appSchema = z.object({ name: z.string().trim().min(1).max(120), description: z.string().max(5000).default(''), kind: z.enum(['web', 'api', 'worker', 'mcp']).default('web') }).strict();
const jobSchema = z.object({ request: z.string().trim().min(5).max(50000), budgetUsd: z.number().positive().optional() }).strict();
const endpointSchema = z.string().url().max(2048).refine(value => {
  try { const endpoint = new URL(value); return !endpoint.username && !endpoint.password && [...endpoint.searchParams.keys()].every(key => !/^(?:password|passwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|key|client[_-]?secret|secret|signature|authorization)$/i.test(key)); } catch { return false; }
}, 'Endpoint credentials must be supplied through the protected credentials field.');
const connectionSchema = z.object({ name: z.string().trim().min(1).max(120), type: z.enum(['filesystem', 'samba', 'microsoft', 'google', 'email', 'stripe', 'efactura', 'rest', 'mcp']), endpoints: z.array(endpointSchema).max(20).default([]), roots: z.array(z.string().max(2048)).max(20).default([]), capabilities: z.array(z.string().max(100)).max(100).default(['read']), appIds: z.array(z.string().uuid()).max(100).default([]), expiresAt: z.string().datetime().nullable().optional(), credentials: z.record(z.string(), z.unknown()).optional() }).strict();
const findApp = (state: State, id: string) => { const app = state.apps[id]; if (!app) throw error(404, 'Application not found.'); return app; };
const findRelease = (state: State, id: string) => { const release = state.releases[id]; if (!release) throw error(404, 'Release not found.'); return release; };
const timestamps = () => new Date().toISOString();
function scanReviewHash(state: State, releaseId: string, checkpointId?: string | null): string {
  const security = latestSecurityReports(state).find(report => report.releaseId === releaseId) ?? null;
  const release = state.releases[releaseId];
  return hashArtifact(release?.migrations.some(item => item.destructive) ? { security, checkpoint: verifiedCheckpointReport(state, checkpointId, release.appId) ?? null } : security);
}
function currentSecurityEvidence(state: State, releaseId: string): import('../../../packages/core/src/types.ts').Evidence | undefined {
  const report = latestSecurityReports(state).find(item => item.subject === 'app' && item.releaseId === releaseId);
  if (!report) return undefined;
  return { status: report.status, checkedAt: report.checkedAt, feedUpdatedAt: report.feedUpdatedAt, findings: report.findings, checks: report.coverage.map(item => ({ name: item.name, passed: item.status === 'passed', detail: item.detail })) };
}
function rejectChatCredentials(value: string, config: Config): void {
  if (redact(value, knownProtectedValues(config)) !== value) throw error(400, 'Credentials must be entered through protected connection forms. Remove passwords, tokens and API keys from this chat message.');
}
function checkDailyScan(state: State, releaseId: string, action: string): void {
  const currentReport = latestSecurityReports(state).find(report => report.releaseId === releaseId);
  if (currentReport && (currentReport.status === 'unavailable' || currentReport.coverage.some(item => item.status !== 'passed') || Date.now() - Date.parse(currentReport.checkedAt) > 86400000 || Date.now() - Date.parse(currentReport.feedUpdatedAt) > 86400000)) throw error(409, 'The latest daily scan is unavailable, incomplete or stale.');
  if (currentReport?.findings.some(finding => ['UNKNOWN', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(finding.severity)) && action !== 'emergency_rollback') throw error(409, 'The latest daily scan found a blocking security issue.');
}
function encryptCredential(key: Buffer, id: string, value: unknown): string {
  const nonce = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(Buffer.from(id));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]); return [nonce, cipher.getAuthTag(), encrypted].map(part => part.toString('base64')).join('.');
}

export async function createServer(config: Config, store: Store, dependencies: EngineDependencies = {}) {
  if (Boolean(config.tlsCertFile) !== Boolean(config.tlsKeyFile)) throw new Error('The control TLS certificate and key must be configured together.');
  const tls = config.tlsCertFile && config.tlsKeyFile ? { cert: await readFile(config.tlsCertFile), key: await readFile(config.tlsKeyFile), minVersion: 'TLSv1.2' as const } : undefined;
  const server = Fastify({ ...(tls ? { https: tls } : {}), logger: { level: process.env.LOG_LEVEL ?? 'info', redact: ['req.headers.authorization', 'req.headers.stripe-signature', 'req.headers.cookie', 'req.headers.x-csrf-token', 'res.headers.set-cookie'], serializers: { req: request => ({ method: request.method, url: request.url?.split('?')[0] }), err: value => ({ type: value.name, message: String(redact(value.message)), stack: '' }) } }, bodyLimit: 1024 * 1024, trustProxy: false });
  const httpDrain = new HttpDrain(); httpDrain.install(server);
  server.setErrorHandler((value, _request, reply) => {
    const fault = value as Error & { statusCode?: number };
    const status = value instanceof z.ZodError ? 400 : fault.statusCode ?? 500;
    const message = value instanceof z.ZodError ? value.issues.map(issue => `${issue.path.join('.')}: ${issue.message}`).join('; ') : status < 500 ? String(redact(fault.message)) : 'The service could not complete this action. Check diagnostic logs.';
    if (status >= 500) server.log.error(value); reply.status(status).send({ error: { message, code: status } });
  });
  await server.register(cookie); await server.register(helmet, { contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], frameSrc: config.appsOrigin ? [new URL(config.appsOrigin).origin, `https://*.${new URL(config.appsOrigin).hostname}`] : ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"] } } });
  const streams = new Set<() => void>(), streamReads = new Set<Promise<void>>(); let streamAdmissionClosed = false;
  server.addHook('preClose', async () => {
    streamAdmissionClosed = true; httpDrain.stopAdmission();
    for (const closeStream of streams) closeStream(); streams.clear();
    // Disconnected clients may still have an admitted database read. They remain tracked until it settles.
    await Promise.all([httpDrain.drain(), Promise.all([...streamReads])]);
  });
  let portalAssets = new Set<string>();
  await server.register(rateLimit, { max: 200, timeWindow: '1 minute' });
  server.addHook('onRequest', async (request, reply) => {
    const path = request.url.split('?')[0]; const portal = isPortalHost(request.headers.host, config);
    const publicInvitation = request.method === 'POST' && ['/api/public/v1/invitations/inspect', '/api/public/v1/invitations/accept'].includes(path!);
    const privateDirectory = request.method === 'POST' && directoryAuthorizationPath(path);
    if (privateDirectory && (request.headers.host !== 'control:3000' || request.headers.origin || request.url.includes('?'))) throw error(404, 'Endpoint not found.');
    if (path!.startsWith('/api/public/') && !privateDirectory && (!portal || !(path === '/api/public/v1/apps' && request.method === 'GET') && !publicInvitation)) throw error(404, 'Endpoint not found.');
    const compiledPortalAsset = path?.startsWith('/portal-assets/') && portalAssets.has(path.slice('/portal-assets/'.length));
    if (portal && !(request.method === 'GET' && (path === '/' || path === '/invite' || path === '/api/public/v1/apps' || compiledPortalAsset) || publicInvitation)) throw error(404, 'Endpoint not found.');
    if (publicInvitation && (request.headers.origin !== new URL(config.appsOrigin!).origin || !request.headers['content-type']?.startsWith('application/json'))) throw error(403, 'Use the protected invitation form on the application portal.');
    if (portal) reply.header('Cache-Control', 'no-store');
  });
  await installAuth(server, store, config);
  await installAccessRoutes(server, store, config, dependencies);
  await installConnectorRoutes(server, store, config, dependencies);
  await installFilesystemRoutes(server, store, config, dependencies);
  await installConnectionRevocationRoutes(server, store, config, dependencies);
  await installStripeWebhookRoutes(server, store, config);
  await installReportRoutes(server, store, config.reportToken, config.requestLimitUsd);
  await installMetrics(server, store, config);
  server.get('/api/auth/check', async (request, reply) => { reply.header('x-auth-user', request.principal!.id); return { authorized: true }; });
  server.get('/healthz', async () => ({ status: 'ok' }));
  server.get('/readyz', async (_request, reply) => { try { await store.read(state => state.nextEventId); return { status: 'ready', storage: store.mode, auth: config.authMode }; } catch { return reply.status(503).send({ status: 'unavailable', storage: store.mode }); } });
  installPortalListingRoutes(server, store, config);
  server.get('/api/public/v1/apps', async (_request, reply) => { reply.header('Cache-Control', 'no-store'); return publicCatalog(store, config, dependencies); });
  server.get('/api/v1/apps', async () => ({ apps: await store.read(state => Object.values(state.apps).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))) }));
  server.post('/api/v1/apps', async request => {
    const body = appSchema.parse(request.body), protectedValues = knownProtectedValues(config);
    if (redact(body.name, protectedValues) !== body.name || redact(body.description, protectedValues) !== body.description) throw error(400, 'Credentials must be entered through protected connection forms. Remove passwords, tokens and API keys from the app name and description.');
    const id = randomUUID(); const now = timestamps();
    let base = body.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'app';
    if (!/^[a-z]/.test(base) || base === 'preview' || base.startsWith('preview-')) base = `app-${base}`;
    const slug = slugSchema.parse(`${base.slice(0, 38).replace(/-+$/g, '')}-${id.slice(0, 8)}`);
    const app: AppRecord = { id, ...body, slug, status: 'draft', activeReleaseId: null, url: null, previewUrl: null, createdAt: now, updatedAt: now };
    await store.transaction(state => { state.apps[id] = app; }); return { app };
  });
  server.get<{ Params: { id: string } }>('/api/v1/apps/:id/jobs', async request => ({ jobs: await store.read(state => { findApp(state, request.params.id); return Object.values(state.jobs).filter(job => job.appId === request.params.id).sort((a, b) => a.createdAt.localeCompare(b.createdAt)); }) }));
  server.post<{ Params: { id: string } }>('/api/v1/apps/:id/jobs', async request => {
    const body = jobSchema.parse(request.body); rejectChatCredentials(body.request, config); const now = timestamps();
    if (body.budgetUsd && body.budgetUsd > config.requestLimitUsd) throw error(409, 'Requested budget exceeds the configured per-request limit.');
    const job = await store.transaction(state => {
      const app = findApp(state, request.params.id);
      if (Object.values(state.jobs).some(item => item.appId === app.id && !['completed', 'failed', 'cancelled', 'needs_attention', 'awaiting_approval'].includes(item.stage))) throw error(409, 'This app already has an active development job.');
      const summary = budgetSummary(state, config.requestLimitUsd, config.monthlyLimitUsd); if (summary.remainingUsd <= 0) throw error(409, 'Monthly spending limit has been reached.');
      const job: JobRecord = { id: randomUUID(), appId: app.id, request: body.request, stage: 'queued', baseReleaseId: app.activeReleaseId, costUsd: 0, budgetUsd: body.budgetUsd ?? config.requestLimitUsd, attempts: 0, createdAt: now, updatedAt: now };
      state.jobs[job.id] = job; event(state, job, 'queued', 'Request recorded. A durable worker will begin when available.'); enqueue(state, job.id); return job;
    }); return { job };
  });
  server.get<{ Params: { id: string } }>('/api/v1/jobs/:id', async request => store.read(state => { const job = state.jobs[request.params.id]; if (!job) throw error(404, 'Job not found.'); return { job, events: state.events.filter(item => item.jobId === job.id) }; }));
  server.get<{ Params: { id: string } }>('/api/v1/jobs/:id/events', async (request, reply) => {
    if (streamAdmissionClosed) return reply.code(503).send({ error: { message: 'The service is shutting down; reconnect to replay recorded progress.' } });
    const admissionRead = Promise.resolve().then(() => store.read(state => { if (!state.jobs[request.params.id]) throw error(404, 'Job not found.'); }));
    streamReads.add(admissionRead);
    try { await admissionRead; } finally { streamReads.delete(admissionRead); }
    if (reply.raw.destroyed || reply.raw.writableEnded) return;
    if (streamAdmissionClosed) return reply.code(503).send({ error: { message: 'The service is shutting down; reconnect to replay recorded progress.' } });
    const resume = Number(request.headers['last-event-id'] ?? (request.query as { after?: string }).after ?? 0); let cursor = Number.isSafeInteger(resume) && resume >= 0 ? resume : 0;
    reply.hijack(); reply.raw.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache, no-transform', connection: 'keep-alive', 'x-accel-buffering': 'no', 'x-content-type-options': 'nosniff' });
    let closed = false, pending: Promise<void> | undefined, timer: NodeJS.Timeout | undefined, unsubscribe: (() => void) | undefined;
    const closeStream = () => {
      if (closed) return; closed = true; if (timer) clearInterval(timer); unsubscribe?.(); streams.delete(closeStream);
      if (!reply.raw.writableEnded) reply.raw.end();
    };
    const pump = (): Promise<void> => {
      if (closed || streamAdmissionClosed) return Promise.resolve();
      if (pending) return pending;
      const task = (async () => { try {
        const snapshot = await store.read(state => {
          const session = request.session ? state.sessions[request.session.id] : undefined;
          const expiry = session ? Date.parse(session.expiresAt) : NaN; const accessExpiry = session?.accessExpiresAt ? Date.parse(session.accessExpiresAt) : null;
          const authorized = !!session && Number.isFinite(expiry) && expiry > Date.now() && (accessExpiry === null ? config.authMode === 'development' : Number.isFinite(accessExpiry) && accessExpiry > Date.now()) && session.principal.id === request.principal?.id && session.principal.mfa && (session.principal.localOwner || session.principal.roles.includes('platform-admin'));
          return { authorized, events: authorized ? state.events.filter(item => item.jobId === request.params.id && item.id > cursor) : [] };
        });
        if (closed || streamAdmissionClosed || reply.raw.destroyed || reply.raw.writableEnded) return;
        if (!snapshot.authorized) { reply.raw.write('event: session_expired\ndata: {}\n\n'); closeStream(); return; }
        const events = snapshot.events;
        for (const item of events) { reply.raw.write(`id: ${item.id}\ndata: ${JSON.stringify(redact(item))}\n\n`); cursor = item.id; }
        if (!events.length) reply.raw.write(': heartbeat\n\n');
      } catch { if (!closed && !streamAdmissionClosed && !reply.raw.destroyed && !reply.raw.writableEnded) reply.raw.write('event: unavailable\ndata: {}\n\n'); } })();
      pending = task; streamReads.add(task);
      const settled = () => { if (pending === task) pending = undefined; streamReads.delete(task); };
      void task.then(settled, settled); return task;
    };
    streams.add(closeStream); reply.raw.once('close', closeStream);
    unsubscribe = store.subscribe?.(request.params.id, () => void pump().catch(() => undefined));
    if (closed) unsubscribe?.(); else timer = setInterval(() => void pump().catch(() => undefined), 1500);
    await pump();
  });
  server.post<{ Params: { id: string } }>('/api/v1/jobs/:id/resume', async request => {
    const body = z.object({ answer: z.string().trim().min(1).max(20000) }).strict().parse(request.body);
    rejectChatCredentials(body.answer, config);
    const job = await store.transaction(state => {
      const job = state.jobs[request.params.id]; if (!job) throw error(404, 'Job not found.');
      if (!['clarification', 'needs_attention'].includes(job.stage)) throw error(409, 'This job is not awaiting input.');
      if (modelBillingReviewRequired(state, job.id)) throw new ModelBillingHoldError();
      if (Object.values(state.jobs).some(item => item.id !== job.id && item.appId === job.appId && !['completed', 'failed', 'cancelled', 'needs_attention', 'awaiting_approval'].includes(item.stage))) throw error(409, 'Another development job for this app is active.');
      job.attempts++; state.repairAttempts[job.id] = { review: 0, verification: 0 }; job.result = { ...(job.result ?? {}), answer: body.answer, ...(job.result?.modelBillingHold === true ? { modelBillingHold: false } : {}) }; event(state, job, 'queued', 'Additional information recorded; resuming development.'); enqueue(state, job.id); return job;
    }); return { job };
  });
  server.post<{ Params: { id: string } }>('/api/v1/jobs/:id/cancel', async request => ({ job: await store.transaction(state => {
    const job = state.jobs[request.params.id]; if (!job) throw error(404, 'Job not found.');
    if (['deployment', 'observation'].includes(job.stage)) throw error(409, 'Publication has been submitted to the runtime. Inspect the release and deployment operation status; cancelling this chat request cannot safely stop publication.');
    if (['completed', 'awaiting_approval'].includes(job.stage)) throw error(409, 'Development has finished; manage its release instead.');
    event(state, job, 'cancelled', 'Cancelled by an administrator. Completed source and evidence are preserved.'); return job;
  }) }));
  server.get<{ Params: { id: string } }>('/api/v1/apps/:id/releases', async request => ({ releases: await store.read(state => { findApp(state, request.params.id); return Object.values(state.releases).filter(item => item.appId === request.params.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt)); }) }));
  server.post<{ Params: { id: string } }>('/api/v1/releases/:id/approval', async request => {
    const body = z.object({ action: z.enum(['publish', 'rollback', 'emergency_rollback']).default('publish'), checkpointId: z.string().max(128).nullable().optional(), automaticRecovery: z.boolean().default(false) }).strict().parse(request.body ?? {});
    if (body.automaticRecovery && body.action !== 'publish') throw error(400, 'Automatic recovery authorization accompanies a publication approval only.');
    if (body.action === 'emergency_rollback') requireOwner(request);
    const approval = await store.transaction(state => {
      const release = findRelease(state, request.params.id); const app = findApp(state, release.appId);
      requireCurrentCandidatePreview(app, release);
      if (release.migrations.some(item => item.destructive) && !verifiedCheckpoint(state, body.checkpointId, app.id)) throw error(409, 'A successful restore verification covering this app and an unexpired checkpoint is required before destructive approval can be requested.');
      const impact = [`${body.action === 'publish' ? 'Publish' : 'Roll back'} ${app.name} to version ${release.version}.`, 'Application code changes; existing business data is preserved unless explicitly listed below.', ...release.migrations.map(item => `${item.destructive ? 'DESTRUCTIVE: ' : ''}${item.id}: ${item.impact}`)];
      const checkpoint = release.migrations.some(item => item.destructive) ? verifiedCheckpointReport(state, body.checkpointId, app.id) : undefined;
      if (checkpoint) impact.push(`Verified recovery checkpoint ${checkpoint.checkpointId}, manifest ${checkpoint.manifestHash}, restored at ${checkpoint.completedAt}, evidence expires ${checkpoint.expiresAt}. Changed recovery evidence requires a new approval.`);
      if (body.action === 'emergency_rollback') impact.push(...(latestSecurityReports(state).find(report => report.releaseId === release.id)?.findings ?? release.evidence.findings).filter(item => ['UNKNOWN', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(item.severity)).map(item => `Known ${item.severity} vulnerability: ${item.id} (${item.package} ${item.installedVersion}).`));
      const approval: ApprovalRecord = { id: randomUUID(), appId: app.id, releaseId: release.id, action: body.action, artifactHash: releaseArtifactHash(release), impact, expiresAt: new Date(Date.now() + 30 * 60000).toISOString(), approvedBy: null, approvedAt: null, consumedAt: null, checkpointId: body.checkpointId ?? null };
      let recoveryGrant;
      if (body.automaticRecovery) {
        recoveryGrant = draftRecoveryGrant(state, app, release, approval.id); state.recoveryGrants[recoveryGrant.id] = recoveryGrant; state.recoveryGrantScans[recoveryGrant.id] = recoveryScanHash(state, recoveryGrant.targetReleaseId);
        const target = state.releases[recoveryGrant.targetReleaseId]!;
        approval.impact.push(`AUTOMATIC RECOVERY: after three independent runtime health failures, authorize one recovery to exact previous version ${target.version} (${target.id}, artifact ${target.artifactHash}) until ${recoveryGrant.expiresAt}.`, 'Recovery preserves current business data. It requires compatible current schema, fresh complete security scanning and no Medium-or-higher or unclassified findings. Missing or ambiguous evidence requires administrator input; this grant does not authorize data restoration.');
      }
      state.approvals[approval.id] = approval; state.approvalScans[approval.id] = scanReviewHash(state, release.id, approval.checkpointId); return { approval, recoveryGrant };
    }); return approval;
  });
  server.post<{ Params: { id: string } }>('/api/v1/approvals/:id/approve', async request => {
    const body = z.object({ artifactHash: z.string().regex(/^[a-f0-9]{64}$/), authorizationHash: z.string().regex(/^[a-f0-9]{64}$/).optional() }).strict().parse(request.body);
    const approval = await store.transaction(state => {
      const approval = state.approvals[request.params.id]; if (!approval) throw error(404, 'Approval not found.');
      if (approval.action === 'emergency_rollback' || approval.action === 'destructive' || approval.action === 'host_maintenance') requireOwner(request);
      if (approval.consumedAt || approval.approvedAt || new Date(approval.expiresAt).getTime() <= Date.now()) throw error(409, 'Approval has expired or has already been used.');
      if (approval.action === 'budget') {
        const change = state.budgetApprovals[approval.id]; if (!change || approval.artifactHash !== body.artifactHash || budgetChangeHash(change) !== body.artifactHash || change.month !== currentMonth(config.spendingAuthority?.timezone)) throw error(409, 'The budget approval does not match the reviewed change.');
        const currentLimit = change.kind === 'job' ? state.jobs[change.jobId!]?.budgetUsd : budgetSummary(state, config.requestLimitUsd, config.monthlyLimitUsd).monthlyLimitUsd;
        if (currentLimit !== change.oldLimitUsd) throw error(409, 'The spending limit changed after review. Request a new approval.');
        if (change.kind === 'monthly') assertAuthorityCeiling(state, change.newLimitUsd);
        approval.approvedBy = request.principal!.id; approval.approvedAt = timestamps(); return approval;
      }
      const release = findRelease(state, approval.releaseId); if (approval.artifactHash !== body.artifactHash || releaseArtifactHash(release) !== body.artifactHash) throw error(409, 'Release changed after review. Request a new approval.');
      if (state.approvalScans[approval.id] !== scanReviewHash(state, release.id, approval.checkpointId)) throw error(409, release.migrations.some(item => item.destructive) ? 'Security or recovery evidence changed after review. Request a new approval.' : 'Security evidence changed after review. Request a new approval.');
      const recoveryGrant = Object.values(state.recoveryGrants).find(grant => grant.publicationApprovalId === approval.id);
      if (recoveryGrant) {
        if (body.authorizationHash !== recoveryGrant.authorizationHash || recoveryAuthorizationHash(recoveryGrant) !== body.authorizationHash || state.recoveryGrantScans[recoveryGrant.id] !== recoveryScanHash(state, recoveryGrant.targetReleaseId)) throw error(409, 'Automatic recovery authorization or target security evidence changed after review.');
        validateDraftRecovery(state, recoveryGrant);
      }
      if (release.migrations.some(item => item.destructive)) { requireOwner(request); if (!verifiedCheckpoint(state, approval.checkpointId, release.appId)) throw error(409, 'The recovery checkpoint has not been verified or has expired.'); }
      const candidate = { ...approval, approvedBy: request.principal!.id, approvedAt: timestamps() }; const app = findApp(state, release.appId); requireCurrentCandidatePreview(app, release); const current = app.activeReleaseId ? state.releases[app.activeReleaseId] : null;
      if (!['publish', 'rollback', 'emergency_rollback'].includes(candidate.action)) throw error(409, 'This approval is not a release operation.');
      const gate = evaluateReleaseGate(release, { currentReleaseId: app.activeReleaseId, currentSchemaVersion: currentDatabaseSchema(state, app), action: candidate.action as 'publish' | 'rollback' | 'emergency_rollback', principal: request.principal!, approval: candidate, checkpointVerified: verifiedCheckpoint(state, candidate.checkpointId, app.id), securityEvidence: currentSecurityEvidence(state, release.id) });
      if (!gate.allowed) throw error(409, gate.reasons.join(' ')); checkDailyScan(state, release.id, candidate.action);
      approval.approvedBy = candidate.approvedBy; approval.approvedAt = candidate.approvedAt; if (recoveryGrant) { recoveryGrant.approvedBy = candidate.approvedBy; recoveryGrant.approvedAt = candidate.approvedAt; } return approval;
    }); return { approval };
  });
  async function deploy(releaseId: string, approvalId: string, principal: Principal, action: 'publish' | 'rollback') {
    if (!dependencies.deploy) throw error(503, 'Deployment service unavailable. No deployment was attempted.');
    const operation = await store.transaction(state => {
      const release = findRelease(state, releaseId); const app = findApp(state, release.appId); const approval = state.approvals[approvalId];
      requireCurrentCandidatePreview(app, release);
      const effective: 'publish' | 'rollback' | 'emergency_rollback' = action === 'rollback' && approval?.action === 'emergency_rollback' ? 'emergency_rollback' : action;
      const current = app.activeReleaseId ? state.releases[app.activeReleaseId] : null;
      const gate = evaluateReleaseGate(release, { currentReleaseId: app.activeReleaseId, currentSchemaVersion: currentDatabaseSchema(state, app), action: effective, principal, approval, checkpointVerified: verifiedCheckpoint(state, approval?.checkpointId, app.id), securityEvidence: currentSecurityEvidence(state, release.id) });
      if (!gate.allowed) throw error(409, gate.reasons.join(' '));
      if (state.approvalScans[approval!.id] !== scanReviewHash(state, release.id, approval!.checkpointId)) throw error(409, release.migrations.some(item => item.destructive) ? 'Security or recovery evidence changed after approval. Review the current findings and recovery evidence, then request a new approval.' : 'Security evidence changed after approval. Review the current findings and request a new approval.'); checkDailyScan(state, release.id, effective);
      if (release.artifactHash !== releaseArtifactHash(release)) throw error(409, 'Stored release artifact hash does not match its immutable contents.');
      if (Object.values(state.operations).some(item => item.appId === app.id && item.status === 'running')) throw error(409, 'This app already has an active deployment.');
      const recoveryGrant = Object.values(state.recoveryGrants).find(grant => grant.publicationApprovalId === approval!.id);
      if (recoveryGrant) {
        validateDraftRecovery(state, recoveryGrant);
        if (action !== 'publish' || recoveryGrant.approvedBy !== approval!.approvedBy || recoveryGrant.approvedAt !== approval!.approvedAt || recoveryGrant.targetReleaseId !== app.activeReleaseId || recoveryGrant.publicationOperationId || state.recoveryGrantScans[recoveryGrant.id] !== recoveryScanHash(state, recoveryGrant.targetReleaseId)) throw error(409, 'The approved automatic recovery grant no longer matches this exact publication.');
      }
      const operation = { id: randomUUID(), appId: app.id, releaseId, baseReleaseId: app.activeReleaseId, action, status: 'running' as const, approvalId: approval!.id, artifactHash: approval!.artifactHash, createdAt: timestamps() }; state.operations[operation.id] = operation; approval!.consumedAt = timestamps(); if (recoveryGrant) recoveryGrant.publicationOperationId = operation.id;
      for (const job of Object.values(state.jobs)) if (job.result?.releaseId === release.id && job.stage === 'awaiting_approval') event(state, job, 'deployment', 'The exact release was approved. Starting health-checked publication.', 'status', { operationId: operation.id, releaseId: release.id });
      return { operation, app, release, approval: approval!, effective, approvedFindings: currentSecurityEvidence(state, release.id)?.findings ?? release.evidence.findings, recoveryGrant: recoveryGrant as RecoveryGrant | undefined };
    });
    try {
      const result = await dependencies.deploy({ app: operation.app, release: operation.release, approval: operation.approval, principal, operationId: operation.operation.id, action: operation.effective, approvedFindings: operation.approvedFindings, recoveryGrant: operation.recoveryGrant });
      if (!result.healthy) throw new Error('Deployment health checks did not pass.');
      if (!/^https?:\/\//.test(result.url)) throw new Error('Deployment returned an invalid application URL.');
      await store.transaction(state => {
        const app = findApp(state, operation.app.id); if (app.activeReleaseId !== operation.app.activeReleaseId) throw error(409, 'The active release changed during deployment.');
        recordDatabaseSchema(state, app, operation.release, result.schemaVersion, config.authMode === 'oidc');
        if (app.activeReleaseId) state.releases[app.activeReleaseId]!.status = 'superseded';
        const release = findRelease(state, releaseId); release.status = 'published'; release.publishedAt = timestamps(); app.activeReleaseId = release.id; app.url = result.url; app.status = 'published'; app.updatedAt = timestamps(); state.operations[operation.operation.id]!.status = 'succeeded';
        for (const job of Object.values(state.jobs)) if (job.result?.releaseId === release.id && ['awaiting_approval', 'deployment', 'observation'].includes(job.stage)) { event(state, job, 'observation', 'Runtime health checks passed; recording the active release and its URL.'); event(state, job, 'completed', 'Release published and health checks passed.', 'status', { url: result.url, releaseId: release.id }); }
        notify(state, 'info', action === 'publish' ? 'Application published' : 'Application rolled back', `${app.name} ${release.version} is healthy at ${result.url}.`);
      }); return { operationId: operation.operation.id, status: 'published', url: result.url };
    } catch (value) {
      const message = String(redact(value instanceof Error ? value.message : 'Deployment failed.'));
      await store.transaction(state => { const record = state.operations[operation.operation.id]; if (record?.status === 'running') { const rejected = (value as { confirmedRejected?: boolean })?.confirmedRejected; if (rejected === true) failDeployment(state, record.id, message); else record.error = message; } notify(state, 'error', 'Deployment needs attention', `${operation.app.name}: ${message}. The previous recorded release is preserved; verify broker operation ${operation.operation.id} before retrying.`); });
      await reconcileDeployments(store, dependencies, operation.operation.id);
      throw error(503, message);
    }
  }
  server.post<{ Params: { id: string } }>('/api/v1/releases/:id/publish', async request => { const body = z.object({ approvalId: z.string().uuid() }).strict().parse(request.body); return deploy(request.params.id, body.approvalId, request.principal!, 'publish'); });
  server.post<{ Params: { id: string } }>('/api/v1/apps/:id/rollback', async request => { const body = z.object({ releaseId: z.string().uuid(), approvalId: z.string().uuid() }).strict().parse(request.body); await store.read(state => { const release = findRelease(state, body.releaseId); if (release.appId !== request.params.id) throw error(404, 'Release does not belong to this application.'); }); return deploy(body.releaseId, body.approvalId, request.principal!, 'rollback'); });
  server.get<{ Params: { id: string } }>('/api/v1/apps/:id/operations', async request => ({ operations: await store.read(state => { findApp(state, request.params.id); return Object.values(state.operations).filter(item => item.appId === request.params.id); }) }));
  server.get<{ Params: { id: string } }>('/api/v1/apps/:id/observation', async request => store.read(state => { findApp(state, request.params.id); return { observation: state.observations[request.params.id] ?? null, attempts: Object.values(state.observationAttempts).filter(attempt => attempt.appId === request.params.id).sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt)).slice(0, 100), recoveryIntents: Object.values(state.recoveryIntents).filter(intent => intent.appId === request.params.id), recoveryGrants: Object.values(state.recoveryGrants).filter(grant => grant.appId === request.params.id) }; }));
  server.post<{ Params: { id: string } }>('/api/v1/operations/:id/reconcile', async request => { await store.read(state => { if (!state.operations[request.params.id]) throw error(404, 'Operation not found.'); }); await reconcileDeployments(store, dependencies, request.params.id); return { operation: await store.read(state => state.operations[request.params.id]) }; });
  server.get('/api/v1/connections', async () => ({ connections: await store.read(state => Object.values(state.connections)) }));
  server.post('/api/v1/connections', async request => {
    const body = connectionSchema.parse(request.body); const id = randomUUID();
    const connection = await store.transaction(state => {
      for (const appId of body.appIds) findApp(state, appId);
      const secretRef = body.credentials ? `connection:${id}` : null;
      if (secretRef) state.secrets[secretRef] = encryptCredential(config.secretKey, secretRef, body.credentials);
      const connection: ConnectionRecord = { id, name: body.name, type: body.type, endpoints: body.endpoints, roots: body.roots, capabilities: body.capabilities, appIds: body.appIds, secretRef, expiresAt: body.expiresAt ?? null, status: body.credentials ? 'configured' : 'needs_credentials', dossier: { documentation: [], provenance: 'Awaiting research and scoped connectivity verification.', license: 'unreviewed', reviewStatus: 'pending' }, createdAt: timestamps() };
      state.connections[id] = connection; notify(state, 'info', 'Connection registered', `${connection.name} is awaiting documentation, security and scope review before applications can use it.`); return connection;
    }); return { connection };
  });
  server.get('/api/v1/budget', async () => store.read(state => budgetSummary(state, config.requestLimitUsd, config.monthlyLimitUsd)));
  server.get<{ Params: { id: string } }>('/api/v1/jobs/:id/model-calls', async request => ({ calls: await store.read(state => { if (!state.jobs[request.params.id]) throw error(404, 'Job not found.'); return Object.values(state.modelCalls).filter(call => call.jobId === request.params.id).sort((a, b) => a.startedAt.localeCompare(b.startedAt)); }) }));
  function createBudgetApproval(state: State, change: BudgetChange, appId: string, impact: string[]): ApprovalRecord {
    const approval: ApprovalRecord = { id: randomUUID(), appId, releaseId: change.jobId ?? 'monthly-budget-policy', action: 'budget', artifactHash: budgetChangeHash(change), impact, expiresAt: new Date(Date.now() + 30 * 60000).toISOString(), approvedBy: null, approvedAt: null, consumedAt: null, checkpointId: null };
    state.approvals[approval.id] = approval; state.budgetApprovals[approval.id] = change; return approval;
  }
  function consumeBudgetApproval(state: State, approvalId: string, kind: BudgetChange['kind'], jobId?: string): BudgetChange {
    const approval = state.approvals[approvalId]; const change = state.budgetApprovals[approvalId];
    if (!approval || !change || approval.action !== 'budget' || change.kind !== kind || (jobId && change.jobId !== jobId) || change.appliedAt || approval.consumedAt || !approval.approvedAt || !approval.approvedBy || Date.parse(approval.expiresAt) <= Date.now() || approval.artifactHash !== budgetChangeHash(change) || change.month !== currentMonth(config.spendingAuthority?.timezone)) throw error(409, 'A current, approved budget change for this exact action is required.');
    const currentLimit = change.kind === 'job' ? state.jobs[change.jobId!]?.budgetUsd : budgetSummary(state, config.requestLimitUsd, config.monthlyLimitUsd).monthlyLimitUsd;
    if (currentLimit !== change.oldLimitUsd) throw error(409, 'The spending limit changed after this approval was prepared.');
    if (change.kind === 'monthly') assertAuthorityCeiling(state, change.newLimitUsd);
    approval.consumedAt = timestamps(); change.appliedAt = approval.consumedAt; return change;
  }
  server.post<{ Params: { id: string } }>('/api/v1/jobs/:id/budget-approval', async request => {
    const body = z.object({ newBudgetUsd: z.number().positive().max(1000000) }).strict().parse(request.body);
    return { approval: await store.transaction(state => {
      const job = state.jobs[request.params.id]; if (!job) throw error(404, 'Job not found.');
      if (body.newBudgetUsd <= job.budgetUsd) throw error(409, 'A budget increase must exceed the current job limit.');
      if (body.newBudgetUsd > budgetSummary(state, config.requestLimitUsd, config.monthlyLimitUsd).monthlyLimitUsd) throw error(409, 'Approve a sufficient monthly cap before increasing this job limit.');
      return createBudgetApproval(state, { kind: 'job', jobId: job.id, oldLimitUsd: job.budgetUsd, newLimitUsd: body.newBudgetUsd, month: currentMonth(config.spendingAuthority?.timezone), appliedAt: null }, job.appId, [`Increase this request's model spending limit from USD ${job.budgetUsd} to USD ${body.newBudgetUsd}.`, `USD ${job.costUsd.toFixed(4)} has already been spent on this request.`, 'A request paused for budget will resume and may incur additional provider charges up to this approved limit; publication requires its own approval.']);
    }) };
  });
  server.post<{ Params: { id: string } }>('/api/v1/jobs/:id/extend-budget', async request => {
    const body = z.object({ approvalId: z.string().uuid() }).strict().parse(request.body);
    return { job: await store.transaction(state => {
      const job = state.jobs[request.params.id]; if (!job) throw error(404, 'Job not found.'); const change = consumeBudgetApproval(state, body.approvalId, 'job', job.id); job.budgetUsd = change.newLimitUsd;
      if (job.stage === 'needs_attention' && job.result?.budgetBlocked === true) { job.result.budgetBlocked = false; event(state, job, 'queued', 'The exact budget increase was approved; resuming the paused request.'); enqueue(state, job.id); }
      notify(state, 'info', 'Request spending limit increased', `${state.apps[job.appId]?.name}: approved limit USD ${job.budgetUsd}.`); return job;
    }) };
  });
  server.post('/api/v1/budget/monthly-approval', async request => {
    const body = z.object({ newMonthlyLimitUsd: z.number().positive().max(1000000) }).strict().parse(request.body);
    return { approval: await store.transaction(state => { const current = budgetSummary(state, config.requestLimitUsd, config.monthlyLimitUsd).monthlyLimitUsd;
      assertAuthorityCeiling(state, body.newMonthlyLimitUsd);
      if (body.newMonthlyLimitUsd <= current) throw error(409, 'The new monthly cap must exceed the current cap.');
      return createBudgetApproval(state, { kind: 'monthly', jobId: null, oldLimitUsd: current, newLimitUsd: body.newMonthlyLimitUsd, month: currentMonth(config.spendingAuthority?.timezone), appliedAt: null }, 'platform', [`Increase the recurring monthly model spending cap from USD ${current} to USD ${body.newMonthlyLimitUsd}.`, 'This cap continues in future months until an administrator changes the policy. Request limits remain unchanged.']);
    }) };
  });
  server.post('/api/v1/budget/extend-monthly', async request => {
    const body = z.object({ approvalId: z.string().uuid() }).strict().parse(request.body); await store.transaction(state => { const change = consumeBudgetApproval(state, body.approvalId, 'monthly'); state.settings.budget = { monthlyLimitUsd: change.newLimitUsd }; notify(state, 'info', 'Monthly spending cap increased', `The approved recurring monthly model spending cap is now USD ${change.newLimitUsd}.`); });
    return store.read(state => budgetSummary(state, config.requestLimitUsd, config.monthlyLimitUsd));
  });
  server.get('/api/v1/notifications', async () => ({ notifications: await store.read(state => Object.values(state.notifications).sort((a, b) => b.createdAt.localeCompare(a.createdAt))) }));
  server.post<{ Params: { id: string } }>('/api/v1/notifications/:id/read', async request => { await store.transaction(state => { const item = state.notifications[request.params.id]; if (!item) throw error(404, 'Notification not found.'); item.read = true; }); return { ok: true }; });
  server.get('/api/v1/security', async () => store.read(state => {
    const reports = latestSecurityReports(state); const releases = Object.values(state.releases);
    const scans = releases.map(release => { const report = reports.find(item => item.releaseId === release.id); const checkedAt = report?.checkedAt ?? release.evidence.checkedAt; const feedUpdatedAt = report?.feedUpdatedAt ?? release.evidence.feedUpdatedAt; const stale = Date.now() - Date.parse(checkedAt) > 86400000 || Date.now() - Date.parse(feedUpdatedAt) > 86400000; return { releaseId: release.id, appId: release.appId, status: stale ? 'unavailable' : report?.status ?? release.evidence.status, checkedAt, feedUpdatedAt, stale, coverage: report?.coverage ?? release.evidence.checks }; });
    const allFindings = [...releases.flatMap(release => (reports.find(report => report.releaseId === release.id)?.findings ?? release.evidence.findings).map(finding => ({ ...finding, appId: release.appId }))), ...(reports.find(report => report.subject === 'vm')?.findings ?? [])];
    const findings = allFindings.filter(item => ['MEDIUM', 'HIGH', 'CRITICAL'].includes(item.severity)); const unclassifiedFindings = allFindings.filter(item => item.severity === 'UNKNOWN');
    const vm = reports.find(report => report.subject === 'vm');
    return { findings, unclassifiedFindings, scans, vm: vm ? { ...vm, stale: Date.now() - Date.parse(vm.checkedAt) > 86400000 || Date.now() - Date.parse(vm.feedUpdatedAt) > 86400000 } : { status: 'unavailable', detail: 'No authenticated VM security report has been received. Coverage is unavailable.' } };
  }));
  server.get('/api/v1/telemetry', async () => {
    const counts = await store.read(state => ({ apps: Object.keys(state.apps).length, jobs: Object.keys(state.jobs).length, runningJobs: Object.values(state.jobs).filter(job => !['completed', 'needs_attention', 'awaiting_approval', 'failed', 'cancelled'].includes(job.stage)).length, publishedApps: Object.values(state.apps).filter(app => app.status === 'published').length }));
    let live: Awaited<ReturnType<NonNullable<EngineDependencies['telemetry']>>> = {};
    if (dependencies.telemetry) try { live = validatedTelemetry(await dependencies.telemetry()); } catch { live = { broker: { available: false, detail: 'Telemetry broker unavailable or returned malformed metrics.' } }; }
    const backups = await store.read(state => Object.values(state.backupReports).sort((a, b) => b.completedAt.localeCompare(a.completedAt)).slice(0, 10));
    return { mode: store.mode, uptimeSeconds: process.uptime(), counts, costUsd: (await store.read(state => budgetSummary(state, config.requestLimitUsd, config.monthlyLimitUsd))).spentUsd, broker: live.broker ?? { available: false, detail: 'Sandbox/deployment broker is not connected.' }, services: live.services ?? [], backups, observations: await store.read(state => Object.values(state.observations)) };
  });
  try {
    await access(config.adminDist); await server.register(staticFiles, { root: config.adminDist, prefix: '/' });
    try { portalAssets = await loadPortalAssetWhitelist(config.adminDist); } catch (value) { server.log.warn({ err: value }, 'Portal assets are unavailable; no file is implicitly whitelisted.'); }
    server.get<{ Params: { filename: string } }>('/portal-assets/:filename', async (request, reply) => { if (!isPortalHost(request.headers.host, config) || !portalAssets.has(request.params.filename)) throw error(404, 'Endpoint not found.'); return reply.sendFile(`assets/${request.params.filename}`); });
    server.get('/', async (request, reply) => reply.sendFile(isPortalHost(request.headers.host, config) ? 'portal.html' : 'index.html'));
    server.get('/invite', async (request, reply) => { if (!isPortalHost(request.headers.host, config)) throw error(404, 'Endpoint not found.'); reply.header('Referrer-Policy', 'no-referrer'); return reply.sendFile('portal.html'); });
    server.setNotFoundHandler((request, reply) => { if (isPortalHost(request.headers.host, config) || request.url.startsWith('/api/') || request.url.startsWith('/auth/') || request.url.startsWith('/webhooks')) return reply.status(404).send({ error: { message: 'Endpoint not found.' } }); return reply.sendFile('index.html'); });
  } catch { server.get('/', async (request, reply) => isPortalHost(request.headers.host, config) ? reply.status(503).send({ error: { message: 'The application portal build is unavailable.' } }) : ({ service: 'AutoSoft control API', adminBuild: 'unavailable', message: 'Build the administration UI with npm run build.' })); server.get('/invite', async (_request, reply) => reply.status(503).send({ error: { message: 'The protected invitation form build is unavailable.' } })); }
  return server;
}
