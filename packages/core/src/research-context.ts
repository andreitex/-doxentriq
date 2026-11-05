import { z } from 'zod';
import { createHash } from 'node:crypto';
import { hashArtifact } from './security.js';
import { idSchema } from './schemas.js';

const sha = z.string().regex(/^[a-f0-9]{64}$/);
const sdkCandidate = z.object({ packageName: z.string().min(1).max(160), repository: z.string().url().max(300), version: z.literal('not_selected') }).strict().nullable();
const metadata = z.object({
  publisher: z.string().min(1).max(120), provenance: z.string().min(1).max(600),
  license: z.string().min(1).max(300), maintenance: z.string().min(1).max(600),
  reviewedBy: z.string().min(1).max(120), reviewedAt: z.string().datetime(),
  reviewStatus: z.literal('reviewed'),
  qualification: z.literal('pending_dependency_and_protocol_checks')
}).strict();
export const integrationResearchContextSchema = z.object({
  schemaVersion: z.literal(1), appId: idSchema, jobId: idSchema,
  catalogHash: sha, contextHash: sha, evidenceHash: sha, asOf: z.string().datetime(), expiresAt: z.string().datetime(),
  integrations: z.array(z.object({
    id: z.enum(['samba', 'stripe', 'microsoft', 'google', 'efactura', 'filesystem']),
    runtimeAdapter: z.enum(['separate_samba_authorization_and_live_verification_required', 'separate_filesystem_authorization_and_live_verification_required', 'unavailable']),
    sources: z.array(z.object({
      url: z.string().url().max(1000), purpose: z.enum(['documentation', 'sdk', 'license']),
      sdkCandidate,
      sourceHash: sha, bodySha256: sha, textSha256: sha, retrievedAt: z.string().datetime(),
      text: z.string().min(1).max(8000), metadata
    }).strict()).min(1).max(3)
  }).strict()).max(6)
}).strict();
export type IntegrationResearchContext = z.infer<typeof integrationResearchContextSchema>;

/** This projection authorizes no dependency, connector, protocol or deployment. */
export function validatedIntegrationResearch(value: unknown, appId: string, jobId: string, now = Date.now()): IntegrationResearchContext | undefined {
  if (value === undefined) return undefined;
  const context = integrationResearchContextSchema.parse(value);
  if (context.appId !== appId || context.jobId !== jobId) throw new Error('Integration research belongs to another application or job');
  const fresh = (date: string, age: number) => Number.isFinite(Date.parse(date)) && Date.parse(date) <= now + 60000 && now - Date.parse(date) <= age;
  if (!fresh(context.asOf, 86400000) || Date.parse(context.expiresAt) <= now || Date.parse(context.expiresAt) > Date.parse(context.asOf) + 86400000) throw new Error('Integration research evidence is missing or stale');
  const ids = new Set<string>();
  for (const integration of context.integrations) {
    if (ids.has(integration.id)) throw new Error('Integration research contains duplicate identities');
    ids.add(integration.id);
    if ((integration.id === 'samba') !== (integration.runtimeAdapter === 'separate_samba_authorization_and_live_verification_required')) throw new Error('Integration research cannot claim an installed generic adapter');
    if ((integration.id === 'filesystem') !== (integration.runtimeAdapter === 'separate_filesystem_authorization_and_live_verification_required')) throw new Error('Integration research cannot claim qualified filesystem access');
    if (!integration.sources.some(source => source.purpose === 'documentation')) throw new Error('Official documentation evidence is required');
    const sdk = integration.sources.find(source => source.purpose === 'sdk');
    if (sdk && (!sdk.sdkCandidate || !integration.sources.some(source => source.purpose === 'license' && hashArtifact(source.sdkCandidate) === hashArtifact(sdk.sdkCandidate)))) throw new Error('SDK evidence requires an exact matching publisher license source');
    const urls = new Set<string>();
    for (const source of integration.sources) {
      const url = new URL(source.url);
      if (url.protocol !== 'https:' || url.username || url.password || url.port && url.port !== '443' || url.hash || url.search || urls.has(source.url)) throw new Error('Invalid official research citation');
      urls.add(source.url);
      if (source.purpose === 'documentation' && source.sdkCandidate || source.purpose === 'sdk' && !source.sdkCandidate || source.purpose === 'license' && !source.sdkCandidate && integration.id !== 'filesystem') throw new Error('SDK source identity is missing or inconsistent');
      if (source.sourceHash !== hashArtifact({ url: source.url, purpose: source.purpose, sdkCandidate: source.sdkCandidate, metadata: source.metadata }) || source.textSha256 !== createHash('sha256').update(source.text).digest('hex')) throw new Error('Integration source text or catalog binding changed');
      if (source.sdkCandidate) {
        const repository = new URL(source.sdkCandidate.repository);
        if (repository.origin !== 'https://github.com' || !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository.pathname) || repository.search || repository.hash || url.hostname !== 'raw.githubusercontent.com' || !url.pathname.startsWith(`${repository.pathname}/`)) throw new Error('SDK evidence is not from its exact publisher repository');
      }
      if (!fresh(source.retrievedAt, 86400000) || !fresh(source.metadata.reviewedAt, 30 * 86400000)) throw new Error('Integration source or company review is stale');
    }
  }
  return context;
}
