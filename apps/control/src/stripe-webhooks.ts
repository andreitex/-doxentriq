import { createCipheriv, createDecipheriv, createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import type { StripeWebhookScope } from '../../../packages/core/src/stripe-webhook.ts';
import { requireOwner } from './auth.ts';
import type { Config } from './config.ts';
import { connectionWithdrawn } from './connection-revocation.ts';
import { recordStripeWebhook } from './external-effects.ts';
import type { State, Store } from './store.ts';

const uuid = z.string().uuid(), hex = z.string().regex(/^[a-f0-9]{64}$/);
const scopeSchema = z.object({ account: z.string().regex(/^acct_[A-Za-z0-9]{1,160}$/).nullable(), live: z.boolean(), eventTypes: z.array(z.string().regex(/^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,5}$/).max(160)).min(1).max(64) }).strict().refine(value => new Set(value.eventTypes).size === value.eventTypes.length);
const secretsSchema = z.array(z.string().regex(/^whsec_[A-Za-z0-9_+/=-]{16,240}$/)).min(1).max(2).refine(value => new Set(value).size === value.length);
const setupSchema = z.object({ appId: uuid, scope: scopeSchema, signingSecrets: secretsSchema }).strict();
const listSchema = z.object({ appId: uuid, cursor: uuid.optional() }).strict();
const policySchema = z.object({ schemaVersion: z.literal(1), provider: z.literal('stripe'), payloadFormat: z.literal('api_v1_snapshot'), endpointId: uuid, appId: uuid, connectionId: uuid, url: z.string().url().max(2048), registryHash: hex, credentialBinding: hex, credentialEnvelopeHash: hex, scope: scopeSchema }).strict();
export type StripeWebhookPolicy = z.infer<typeof policySchema>;
export type StripeWebhookEndpoint = { policy: StripeWebhookPolicy; secretRef: string; status: 'pending' | 'active' | 'withdrawn'; approvalId: string | null; createdAt: string; activatedAt: string | null; withdrawnAt: string | null };
export type StripeWebhookApproval = { id: string; endpointId: string; appId: string; connectionId: string; action: 'activate' | 'withdraw'; artifactHash: string; createdAt: string; expiresAt: string; approvedAt: string | null; approvedBy: string | null; consumedAt: string | null };
const approvalSchema = z.object({ id: uuid, endpointId: uuid, appId: uuid, connectionId: uuid, action: z.enum(['activate', 'withdraw']), artifactHash: hex, createdAt: z.string().datetime(), expiresAt: z.string().datetime(), approvedAt: z.string().datetime().nullable(), approvedBy: z.string().min(1).max(256).nullable(), consumedAt: z.string().datetime().nullable() }).strict();
const fault = (statusCode: number, message: string) => Object.assign(new Error(message), { statusCode });
const pathFor = (id: string) => `/webhooks/stripe/${id}`;

function origin(config: Config): URL {
  try { const value = new URL(config.publicOrigin); if (value.protocol !== 'https:' || value.origin !== config.publicOrigin || value.username || value.password || !value.hostname) throw new Error(); return value; }
  catch { throw fault(503, 'An exact configured HTTPS administration origin is required for Stripe ingress.'); }
}
function registry(state: State, appId: string, connectionId: string, expected?: string): void {
  const app = state.apps[appId], item = state.connections[connectionId];
  if (!app || app.status === 'archived' || !item || item.type !== 'stripe' || !['configured', 'needs_credentials'].includes(item.status) || !item.appIds.includes(appId) || !item.capabilities.includes('webhooks.receive') || connectionWithdrawn(state, appId, connectionId) || item.expiresAt !== null && (!Number.isFinite(Date.parse(item.expiresAt)) || Date.parse(item.expiresAt) <= Date.now()) || expected !== undefined && hashArtifact(item) !== expected) throw fault(409, 'The exact authorized Stripe app and connection scope is unavailable.');
}
function credentialBinding(config: Config, id: string, secrets: readonly string[]): string {
  return createHmac('sha256', config.secretKey).update(`stripe-webhook-signing-scope-v1:${id}\0`).update(JSON.stringify(secrets)).digest('hex');
}
function seal(config: Config, ref: string, secrets: readonly string[]): string {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', config.secretKey, iv); cipher.setAAD(Buffer.from(ref));
  const data = Buffer.concat([cipher.update(JSON.stringify(secrets), 'utf8'), cipher.final()]); return [iv, cipher.getAuthTag(), data].map(value => value.toString('base64')).join('.');
}
function open(config: Config, ref: string, value: string): string[] {
  try {
    if (typeof value !== 'string' || value.length > 4096) throw new Error();
    const parts = value.split('.'); if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9+/]+={0,2}$/.test(part))) throw new Error();
    const [iv, tag, data] = parts.map(part => Buffer.from(part, 'base64'));
    if (iv!.length !== 12 || tag!.length !== 16) throw new Error();
    const decipher = createDecipheriv('aes-256-gcm', config.secretKey, iv!); decipher.setAAD(Buffer.from(ref)); decipher.setAuthTag(tag!);
    return secretsSchema.parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat([decipher.update(data!), decipher.final()]))));
  } catch { throw fault(503, 'Protected Stripe signing credentials are unavailable.'); }
}
function reviewed(state: State, endpoint: StripeWebhookEndpoint, config: Config, expectedId: string): { policy: StripeWebhookPolicy; secrets: string[]; envelopeHash: string } {
  const policy = policySchema.parse(endpoint.policy), base = origin(config);
  if (policy.endpointId !== expectedId || policy.url !== `${base.origin}${pathFor(expectedId)}` || endpoint.secretRef !== `stripe-webhook:${expectedId}`) throw fault(409, 'The approved Stripe endpoint binding changed.');
  registry(state, policy.appId, policy.connectionId, policy.registryHash);
  const envelope = state.secrets[endpoint.secretRef]; if (!envelope) throw fault(503, 'Protected Stripe signing credentials are unavailable.');
  const secrets = open(config, endpoint.secretRef, envelope);
  if (credentialBinding(config, policy.endpointId, secrets) !== policy.credentialBinding || hashArtifact(envelope) !== policy.credentialEnvelopeHash) throw fault(409, 'The approved Stripe signing credentials changed.');
  return { policy, secrets, envelopeHash: hashArtifact(envelope) };
}
function artifact(action: StripeWebhookApproval['action'], endpoint: StripeWebhookEndpoint): string {
  return hashArtifact({ schemaVersion: 1, action, policy: endpoint.policy, activeApprovalId: action === 'withdraw' ? endpoint.approvalId : null });
}
function review(state: State, endpoint: StripeWebhookEndpoint, action: StripeWebhookApproval['action']): StripeWebhookApproval {
  const now = Date.now(), id = randomUUID(), approval: StripeWebhookApproval = { id, endpointId: endpoint.policy.endpointId, appId: endpoint.policy.appId, connectionId: endpoint.policy.connectionId, action, artifactHash: artifact(action, endpoint), createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 300000).toISOString(), approvedAt: null, approvedBy: null, consumedAt: null };
  state.stripeWebhookApprovals[id] = approval; return approval;
}
function currentApproval(state: State, endpoint: StripeWebhookEndpoint, config: Config): void {
  const parsed = approvalSchema.safeParse(endpoint.approvalId ? state.stripeWebhookApprovals[endpoint.approvalId] : undefined), item = parsed.success ? parsed.data : null, now = Date.now();
  if (!item || item.id !== endpoint.approvalId || item.action !== 'activate' || item.endpointId !== endpoint.policy.endpointId || item.appId !== endpoint.policy.appId || item.connectionId !== endpoint.policy.connectionId || item.artifactHash !== artifact('activate', endpoint) || !item.approvedBy || config.ownerSubject !== undefined && item.approvedBy !== config.ownerSubject || !item.approvedAt || !item.consumedAt || item.approvedAt !== item.consumedAt || endpoint.activatedAt !== item.consumedAt || endpoint.withdrawnAt !== null || Date.parse(item.createdAt) > now || Date.parse(item.approvedAt) > now || Date.parse(item.expiresAt) - Date.parse(item.createdAt) !== 300000 || Date.parse(item.approvedAt) < Date.parse(item.createdAt) || Date.parse(item.approvedAt) >= Date.parse(item.expiresAt)) throw fault(409, 'The exact consumed owner approval for Stripe ingress is unavailable.');
}
function retainedPolicy(endpoint: StripeWebhookEndpoint, expectedId: string): StripeWebhookPolicy {
  const policy = policySchema.parse(endpoint.policy);
  try {
    const url = new URL(policy.url);
    if (policy.endpointId !== expectedId || url.protocol !== 'https:' || url.username || url.password || policy.url !== `${url.origin}${pathFor(expectedId)}` || endpoint.secretRef !== `stripe-webhook:${expectedId}`) throw new Error();
  } catch { throw fault(409, 'The retained approved Stripe endpoint binding is unavailable.'); }
  return policy;
}
function exactHeaders(request: FastifyRequest, config: Config, id: string): string {
  const base = origin(config), count = (name: string) => request.raw.rawHeaders.filter((_, index, all) => index % 2 === 0 && all[index]!.toLowerCase() === name).length;
  if (request.url !== pathFor(id) || request.headers.host !== base.host || count('host') !== 1 || count('stripe-signature') !== 1 || count('content-type') !== 1 || count('content-length') > 1 || count('transfer-encoding') > 1 || request.headers['content-length'] !== undefined && request.headers['transfer-encoding'] !== undefined || request.headers['content-encoding'] !== undefined || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '') || request.headers.origin !== undefined || request.headers.cookie !== undefined || typeof request.headers['stripe-signature'] !== 'string') throw fault(400, 'Stripe delivery transport is invalid.');
  return request.headers['stripe-signature'];
}

/** Protected policy enrollment plus authenticated metadata-only ingress.
 * No Stripe API request or provider effect is dispatched. TLS reverse-proxy
 * exposure is an installation boundary requiring separate acceptance. */
export async function installStripeWebhookRoutes(server: FastifyInstance, store: Store, config: Config): Promise<void> {
  await server.register(async management => {
  management.setErrorHandler((value, _request, reply) => {
    const status = value instanceof z.ZodError ? 400 : (value as { statusCode?: number }).statusCode ?? 500;
    reply.status([400, 401, 403, 404, 409, 429, 503].includes(status) ? status : 503).send({ error: { message: status === 400 ? 'Stripe configuration or approval input is invalid.' : status === 403 ? 'The permanent local owner with MFA must approve this action.' : status === 409 ? 'The Stripe connection, endpoint or review changed. Inspect its saved state.' : 'Stripe configuration could not be completed.' } });
  });
  management.post('/api/v1/connections/:connectionId/stripe/webhook-reviews', async request => {
    requireOwner(request); const connectionId = uuid.parse((request.params as { connectionId: string }).connectionId), body = setupSchema.parse(request.body); origin(config);
    return store.transaction(state => {
      registry(state, body.appId, connectionId);
      const endpointId = randomUUID(), secretRef = `stripe-webhook:${endpointId}`, envelope = seal(config, secretRef, body.signingSecrets), policy: StripeWebhookPolicy = { schemaVersion: 1, provider: 'stripe', payloadFormat: 'api_v1_snapshot', endpointId, appId: body.appId, connectionId, url: `${origin(config).origin}${pathFor(endpointId)}`, registryHash: hashArtifact(state.connections[connectionId]), credentialBinding: credentialBinding(config, endpointId, body.signingSecrets), credentialEnvelopeHash: hashArtifact(envelope), scope: body.scope };
      const endpoint: StripeWebhookEndpoint = { policy, secretRef, status: 'pending', approvalId: null, createdAt: new Date().toISOString(), activatedAt: null, withdrawnAt: null };
      state.secrets[secretRef] = envelope; state.stripeWebhookEndpoints[endpointId] = endpoint;
      return { approval: review(state, endpoint, 'activate'), policy, status: endpoint.status, activeApprovalId: null };
    });
  });
  management.get('/api/v1/connections/:connectionId/stripe/webhooks', async request => {
    requireOwner(request); const connectionId = uuid.parse((request.params as { connectionId: string }).connectionId), { appId, cursor } = listSchema.parse(request.query);
    return store.read(state => {
      const records = Object.entries(state.stripeWebhookEndpoints).filter(([, item]) => item.policy.appId === appId && item.policy.connectionId === connectionId);
      for (const [id, item] of records) { retainedPolicy(item, id); z.string().datetime().parse(item.createdAt); }
      records.sort(([a, first], [b, second]) => Date.parse(first.createdAt) - Date.parse(second.createdAt) || a.localeCompare(b));
      const position = cursor === undefined ? -1 : records.findIndex(([id]) => id === cursor);
      if (cursor !== undefined && position < 0) throw fault(404, 'The retained Stripe page cursor is unavailable in this app and connection.');
      const page = records.slice(position + 1, position + 101), more = position + 1 + page.length < records.length;
      return { endpoints: page.map(([, item]) => ({ policy: item.policy, status: item.status, activeApprovalId: item.approvalId, activatedAt: item.activatedAt, withdrawnAt: item.withdrawnAt })), nextCursor: more ? page[page.length - 1]![0] : null };
    });
  });
  management.post('/api/v1/stripe/webhooks/:endpointId/withdrawal-review', async request => {
    requireOwner(request); const endpointId = uuid.parse((request.params as { endpointId: string }).endpointId); z.object({}).strict().parse(request.body);
    return store.transaction(state => { const endpoint = state.stripeWebhookEndpoints[endpointId]; if (!endpoint || endpoint.status !== 'active') throw fault(409, 'An active Stripe endpoint is required for withdrawal.'); retainedPolicy(endpoint, endpointId); currentApproval(state, endpoint, config); return { approval: review(state, endpoint, 'withdraw'), policy: endpoint.policy, activeApprovalId: endpoint.approvalId }; });
  });
  management.post('/api/v1/stripe/webhook-reviews/:approvalId/approve', async request => {
    requireOwner(request); const approvalId = uuid.parse((request.params as { approvalId: string }).approvalId), body = z.object({ artifactHash: hex }).strict().parse(request.body);
    return store.transaction(state => {
      const approval = state.stripeWebhookApprovals[approvalId], endpoint = approval ? state.stripeWebhookEndpoints[approval.endpointId] : undefined, now = Date.now();
      if (!approvalSchema.safeParse(approval).success || !approval || !endpoint || approval.id !== approvalId || endpoint.policy.endpointId !== approval.endpointId || approval.appId !== endpoint.policy.appId || approval.connectionId !== endpoint.policy.connectionId || approval.artifactHash !== body.artifactHash || approval.artifactHash !== artifact(approval.action, endpoint) || approval.consumedAt || approval.approvedAt || approval.approvedBy || Date.parse(approval.createdAt) > now || Date.parse(approval.expiresAt) - Date.parse(approval.createdAt) !== 300000 || Date.parse(approval.expiresAt) <= now) throw fault(409, 'A current five-minute owner review for this exact Stripe artifact is required.');
      if (approval.action === 'activate') { if (endpoint.status !== 'pending') throw fault(409, 'This Stripe endpoint cannot be activated again.'); reviewed(state, endpoint, config, approval.endpointId); endpoint.status = 'active'; endpoint.approvalId = approval.id; endpoint.activatedAt = new Date(now).toISOString(); }
      else { if (approval.action !== 'withdraw' || endpoint.status !== 'active') throw fault(409, 'This Stripe endpoint cannot be withdrawn again.'); retainedPolicy(endpoint, approval.endpointId); currentApproval(state, endpoint, config); endpoint.status = 'withdrawn'; endpoint.withdrawnAt = new Date(now).toISOString(); }
      approval.approvedAt = approval.consumedAt = new Date(now).toISOString(); approval.approvedBy = request.principal!.id;
      return { policy: endpoint.policy, status: endpoint.status, approval, activeApprovalId: endpoint.approvalId };
    });
  });
  });
  await server.register(async ingress => {
    ingress.removeContentTypeParser('application/json'); ingress.addContentTypeParser('application/json', { parseAs: 'buffer', bodyLimit: 1024 * 1024 }, (_request, body, done) => done(null, body));
    // Do not log parser/verifier failures: neither raw body nor signature is diagnostic output.
    ingress.setErrorHandler((value, _request, reply) => { const status = (value as { statusCode?: number }).statusCode; reply.status(status === 413 ? 413 : status === 503 ? 503 : status === 404 ? 404 : 400).send({ error: 'Stripe delivery was not recorded.' }); });
    ingress.post('/webhooks/stripe/:endpointId', { bodyLimit: 1024 * 1024, config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (request, reply) => {
      const endpointId = uuid.parse((request.params as { endpointId: string }).endpointId), signature = exactHeaders(request, config, endpointId);
      if (!Buffer.isBuffer(request.body)) throw fault(400, 'Stripe delivery body is invalid.');
      const checked = await store.read(state => { const endpoint = state.stripeWebhookEndpoints[endpointId]; if (!endpoint || endpoint.status !== 'active') throw fault(404, 'Stripe endpoint is unavailable.'); currentApproval(state, endpoint, config); return reviewed(state, endpoint, config, endpointId); });
      try {
        await recordStripeWebhook(store, { appId: checked.policy.appId, connectionId: checked.policy.connectionId, raw: request.body, signature, activeSecrets: checked.secrets, scope: checked.policy.scope as StripeWebhookScope, authorizeCommit: state => {
          const endpoint = state.stripeWebhookEndpoints[endpointId]; if (!endpoint || endpoint.status !== 'active') throw fault(404, 'Stripe endpoint is unavailable.'); currentApproval(state, endpoint, config); const current = reviewed(state, endpoint, config, endpointId);
          if (hashArtifact(current.policy) !== hashArtifact(checked.policy) || current.envelopeHash !== checked.envelopeHash) throw fault(409, 'Stripe endpoint scope changed before commit.');
          return 'signing_only_ingress';
        } });
      } catch (value) { if ((value as { statusCode?: number }).statusCode) throw value; if (value instanceof Error && value.message === 'Stripe webhook verification or configured event scope failed.') throw fault(400, 'Stripe delivery verification failed.'); throw fault(503, 'Stripe delivery could not be recorded.'); }
      reply.header('Cache-Control', 'no-store'); return { received: true };
    });
  });
}
