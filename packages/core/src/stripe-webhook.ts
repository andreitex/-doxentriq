import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';

const stripeId = (prefix: string) => z.string().regex(new RegExp(`^${prefix}_[A-Za-z0-9]{1,160}$`));
const eventType = z.string().regex(/^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,5}$/).max(160);
const scopeSchema = z.object({ account: stripeId('acct').nullable(), live: z.boolean(), eventTypes: z.array(eventType).min(1).max(64) }).strict();
export type StripeWebhookScope = z.infer<typeof scopeSchema>;
export type StripeWebhookMetadata = { eventId: string; eventType: string; objectId: string; account: string | null; live: boolean; created: number; bodySha256: string };
const snapshotSchema = z.object({
  id: stripeId('evt'), object: z.literal('event'), type: eventType, livemode: z.boolean(),
  created: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER), account: stripeId('acct').optional(),
  context: z.never().optional(), data: z.object({ object: z.object({ id: z.string().regex(/^[A-Za-z][A-Za-z0-9_]{1,199}$/) }).passthrough() }).passthrough()
}).passthrough();

/** API v1 snapshot events only. Call on a bounded, unmodified HTTP body before parsing.
 * This implements Stripe's documented manual verification protocol without an SDK.
 * Verification does not grant app access, acknowledge delivery, or process a payment. */
export function verifyStripeWebhook(raw: Buffer, signature: string, activeSecrets: readonly string[], scope: StripeWebhookScope, nowSeconds = Math.floor(Date.now() / 1000)): StripeWebhookMetadata {
  try {
    const approvedScope = scopeSchema.parse(scope);
    if (new Set(approvedScope.eventTypes).size !== approvedScope.eventTypes.length || !Buffer.isBuffer(raw) || raw.length === 0 || raw.length > 1024 * 1024 || typeof signature !== 'string' || signature.length > 4096 || /[\r\n\0]/.test(signature) || !Number.isSafeInteger(nowSeconds) || nowSeconds < 0) throw new Error();
    if (!Array.isArray(activeSecrets) || activeSecrets.length < 1 || activeSecrets.length > 2 || new Set(activeSecrets).size !== activeSecrets.length || activeSecrets.some(secret => typeof secret !== 'string' || !/^whsec_[A-Za-z0-9_+/=-]{16,240}$/.test(secret))) throw new Error();
    const timestamps: string[] = [], signatures: Buffer[] = [];
    const entries = signature.split(','); if (entries.length > 32) throw new Error();
    for (const entry of entries) {
      const pair = /^([A-Za-z0-9]+)=([^=]+)$/.exec(entry.trim()); if (!pair) throw new Error();
      if (pair[1] === 't') timestamps.push(pair[2]!);
      if (pair[1] === 'v1') { if (!/^[a-f0-9]{64}$/.test(pair[2]!)) throw new Error(); signatures.push(Buffer.from(pair[2]!, 'hex')); }
    }
    if (timestamps.length !== 1 || !/^(?:0|[1-9][0-9]{0,10})$/.test(timestamps[0]!) || signatures.length < 1 || signatures.length > 16) throw new Error();
    const timestamp = Number(timestamps[0]);
    if (!Number.isSafeInteger(timestamp) || Math.abs(nowSeconds - timestamp) > 300) throw new Error();
    let matched = false;
    for (const secret of activeSecrets) {
      const expected = createHmac('sha256', secret).update(timestamps[0]! + '.').update(raw).digest();
      for (const candidate of signatures) matched = timingSafeEqual(expected, candidate) || matched;
    }
    if (!matched) throw new Error();
    const value = snapshotSchema.parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)));
    if ((value.account ?? null) !== approvedScope.account || value.livemode !== approvedScope.live || !approvedScope.eventTypes.includes(value.type)) throw new Error();
    return { eventId: value.id, eventType: value.type, objectId: value.data.object.id, account: value.account ?? null, live: value.livemode, created: value.created, bodySha256: createHash('sha256').update(raw).digest('hex') };
  } catch { throw new Error('Stripe webhook verification or configured event scope failed.'); }
}
