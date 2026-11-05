import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import { verifyStripeWebhook, type StripeWebhookScope, type StripeWebhookMetadata } from '../../../packages/core/src/stripe-webhook.ts';
import { connectionWithdrawn } from './connection-revocation.ts';
import type { Store, State } from './store.ts';

const hex = z.string().regex(/^[a-f0-9]{64}$/), uuid = z.string().uuid();
const intentSchema = z.object({ appId: uuid, connectionId: uuid, operationId: uuid, capability: z.string().regex(/^[a-z][a-z0-9_.:-]{0,79}$/), requestSha256: hex }).strict();
export type ExternalEffectIntent = z.infer<typeof intentSchema>;
export type ExternalEffectRecord = ExternalEffectIntent & { id: string; state: 'dispatched' | 'succeeded' | 'rejected' | 'unknown'; dispatchToken: string; createdAt: string; receiptSha256: string | null; resolvedAt: string | null };
export type ExternalEventRecord = StripeWebhookMetadata & { id: string; provider: 'stripe'; appId: string; connectionId: string; receivedAt: string };
function authorized(state: State, input: { appId: string; connectionId: string }, capability: string, timestamp: number, signingOnlyIngress = false): void {
  const app = state.apps[input.appId], connection = state.connections[input.connectionId];
  if (!app || app.status === 'archived' || !connection || !(connection.status === 'configured' || signingOnlyIngress && capability === 'webhooks.receive' && connection.status === 'needs_credentials') || !connection.appIds.includes(input.appId) || !connection.capabilities.includes(capability) || connectionWithdrawn(state, input.appId, input.connectionId) || connection.expiresAt !== null && (!Number.isFinite(Date.parse(connection.expiresAt)) || Date.parse(connection.expiresAt) <= timestamp)) throw new Error('External connection scope is unavailable or withdrawn.');
}
const effectKey = (input: Pick<ExternalEffectIntent, 'appId' | 'connectionId' | 'operationId'>) => hashArtifact({ schemaVersion: 1, ...input });

/** Internal journal for qualified adapters, not an execution/approval endpoint.
 * Commit a dispatch fence before a single provider call. Retained dispatched or
 * unknown operations cannot be reclaimed after crashes, lease expiry or retries.
 * A separate adapter must validate its exact approval, runtime and credential scope. */
export async function beginExternalEffect(store: Store, input: ExternalEffectIntent): Promise<{ dispatch: true; record: ExternalEffectRecord } | { dispatch: false; record: ExternalEffectRecord }> {
  const intent = intentSchema.parse(input);
  return store.transaction(state => {
    authorized(state, intent, intent.capability, Date.now());
    const id = effectKey({ appId: intent.appId, connectionId: intent.connectionId, operationId: intent.operationId }), old = state.externalEffects[id];
    if (old) {
      if (old.requestSha256 !== intent.requestSha256 || old.capability !== intent.capability || old.appId !== intent.appId || old.connectionId !== intent.connectionId || old.operationId !== intent.operationId) throw new Error('External operation identity was reused for a different request.');
      return { dispatch: false, record: old };
    }
    const record: ExternalEffectRecord = { ...intent, id, state: 'dispatched', dispatchToken: randomUUID(), createdAt: new Date().toISOString(), receiptSha256: null, resolvedAt: null };
    state.externalEffects[id] = record;
    return { dispatch: true, record };
  });
}

/** A trusted adapter may settle its original dispatch once. Error/timeout/lost
 * response must use unknown; rejected requires authoritative no-effect evidence.
 * This cannot resolve an unknown result or authorize a new provider operation. */
export async function settleExternalEffect(store: Store, input: { id: string; dispatchToken: string; outcome: 'succeeded' | 'rejected' | 'unknown'; receiptSha256: string | null }): Promise<ExternalEffectRecord> {
  const settlement = z.object({ id: hex, dispatchToken: uuid, outcome: z.enum(['succeeded', 'rejected', 'unknown']), receiptSha256: hex.nullable() }).strict().parse(input);
  if (settlement.outcome !== 'unknown' && settlement.receiptSha256 === null) throw new Error('A normalized provider receipt is required for a known outcome.');
  return store.transaction(state => {
    const record = state.externalEffects[settlement.id];
    if (!record || record.dispatchToken !== settlement.dispatchToken || record.state !== 'dispatched') throw new Error('External dispatch cannot be settled by a stale or repeated result.');
    record.state = settlement.outcome; record.receiptSha256 = settlement.receiptSha256; record.resolvedAt = new Date().toISOString();
    return record;
  });
}

/** Persist verified metadata atomically before an HTTP adapter acknowledges it.
 * No business payload, secret, payment action or assumption about event ordering
 * is stored. Repeated event IDs are deduplicated per app and connection. */
export async function recordStripeWebhook(store: Store, input: { appId: string; connectionId: string; raw: Buffer; signature: string; activeSecrets: readonly string[]; scope: StripeWebhookScope; authorizeCommit?: (state: State) => 'signing_only_ingress' | void }): Promise<{ duplicate: boolean; event: ExternalEventRecord }> {
  const identity = z.object({ appId: uuid, connectionId: uuid }).strict().parse({ appId: input.appId, connectionId: input.connectionId });
  const authorizeCommit = input.authorizeCommit;
  const timestamp = Date.now(), metadata = verifyStripeWebhook(input.raw, input.signature, input.activeSecrets, input.scope, Math.floor(timestamp / 1000));
  return store.transaction(state => {
    const signingOnlyIngress = authorizeCommit?.(state) === 'signing_only_ingress';
    authorized(state, identity, 'webhooks.receive', Date.now(), signingOnlyIngress);
    if (state.connections[identity.connectionId]!.type !== 'stripe') throw new Error('Stripe event requires a Stripe connection.');
    const id = hashArtifact({ schemaVersion: 1, provider: 'stripe', ...identity, eventId: metadata.eventId });
    const old = state.externalEvents[id];
    if (old) {
      if (hashArtifact({ ...old, id: undefined, provider: undefined, appId: undefined, connectionId: undefined, receivedAt: undefined }) !== hashArtifact(metadata)) throw new Error('A retained Stripe event ID has conflicting content.');
      return { duplicate: true, event: old };
    }
    const event: ExternalEventRecord = { ...metadata, id, provider: 'stripe', ...identity, receivedAt: new Date(timestamp).toISOString() };
    state.externalEvents[id] = event; return { duplicate: false, event };
  });
}
