import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import { isIP } from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import { hashArtifact, redact } from '../../../packages/core/src/security.ts';
import { validatedIntegrationResearch, type IntegrationResearchContext } from '../../../packages/core/src/research-context.ts';
import type { AppRecord, JobRecord } from '../../../packages/core/src/types.ts';
import type { GenerationConnectionInventory } from '../../../packages/core/src/connection-context.ts';
import { event, type Store, type State } from './store.ts';

const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
const metadata = z.object({ publisher: z.string().min(1).max(120), provenance: z.string().min(1).max(600), license: z.string().min(1).max(300), maintenance: z.string().min(1).max(600), reviewedBy: z.string().min(1).max(120), reviewedAt: z.string().datetime(), reviewStatus: z.literal('reviewed'), qualification: z.literal('pending_dependency_and_protocol_checks') }).strict();
const sourceSchema = z.object({ url: z.string().url().max(1000), purpose: z.enum(['documentation', 'sdk', 'license']), sdkCandidate: z.object({ packageName: z.string().min(1).max(160), repository: z.string().url().max(300), version: z.literal('not_selected') }).strict().nullable(), metadata }).strict();
export const integrationCatalogSchema = z.object({ schemaVersion: z.literal(1), integrations: z.array(z.object({ id: z.enum(['samba', 'stripe', 'microsoft', 'google', 'efactura', 'filesystem']), aliases: z.array(z.string().min(2).max(60)).min(1).max(16), sources: z.array(sourceSchema).min(1).max(3) }).strict()).min(1).max(6) }).strict();
export type IntegrationCatalog = z.infer<typeof integrationCatalogSchema>;
type CatalogSource = IntegrationCatalog['integrations'][number]['sources'][number];
type ResearchSource = CatalogSource & { sourceHash: string; status: 'retrieved' | 'unavailable'; retrievedAt: string; bodySha256: string | null; textSha256: string | null; text: string | null; reason: string | null };
export type IntegrationResearchRecord = {
  id: string; appId: string; jobId: string; runtimeFence: number; contextHash: string; catalogHash: string | null; evidenceHash: string;
  asOf: string; expiresAt: string; status: 'retrieved' | 'unavailable';
  availabilityReason: 'protected_catalog_unavailable' | 'source_unavailable' | null;
  integrations: { id: IntegrationCatalog['integrations'][number]['id']; sources: ResearchSource[] }[];
};
export type ResearchInput = { app: AppRecord; job: JobRecord; context: { previousSpecification?: unknown; answer?: string; connectionInventory?: GenerationConnectionInventory }; worker: { owner: string; runtimeFence: number } };
export class IntegrationResearchUnavailable extends Error {
  constructor(readonly kind: 'setup' | 'runtime_unavailable', readonly recordId?: string) { super(kind === 'setup' ? 'Required integration research company catalog, provenance, license or maintenance review is missing or stale. Ask the company operator to review the protected catalog.' : 'Required official integration documentation is unavailable. Research evidence is retained; ask the company operator to inspect connectivity or source availability before retrying. Documentation retrieval never qualifies an SDK or authorizes a connection.'); }
}

/** Only ordinary globally routable addresses can be pinned. Special ranges fail closed. */
export function publicResearchAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a, b, c] = address.split('.').map(Number) as [number, number, number, number];
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && (b === 0 || b === 168 || b === 88 && c === 99) || a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) || a === 203 && b === 0 && c === 113);
  }
  if (isIP(address) !== 6 || address.includes('%') || address.includes('.')) return false;
  const head = address.toLowerCase().split(':'); const first = parseInt(head[0]!, 16), second = parseInt(head[1] || '0', 16);
  return first >= 0x2000 && first <= 0x3fff && first !== 0x2002 && !(first === 0x2001 && (second < 0x200 || second === 0xdb8)) && !(first === 0x3fff && second < 0x1000);
}
function officialUrl(value: string): URL {
  const url = new URL(value), host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || url.port && url.port !== '443' || url.hash || url.search || isIP(host) || host.includes(':') || !/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(host) || /(?:^|\.)(?:localhost|local|internal|test|invalid)$/.test(host)) throw new Error('Invalid protected research source URL');
  return url;
}
export type ResolvedAddress = { address: string; family: number };
export type ResearchFetcher = (url: string) => Promise<{ body: Buffer; contentType: string }>;
type PinnedTransport = (url: URL, address: ResolvedAddress, limits: { maxBytes: number; timeoutMs: number }) => Promise<{ body: Buffer; contentType: string }>;
function canonicalAddress(address: string): string { return isIP(address) === 6 ? new URL(`https://[${address}]/`).hostname.slice(1, -1) : address; }
function deadline<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout;
  return Promise.race([promise, new Promise<T>((_, reject) => { timer = setTimeout(() => reject(new Error('Research source timeout')), timeoutMs); })]).finally(() => clearTimeout(timer));
}
export function pinnedResearchHttps(url: URL, pinned: ResolvedAddress, limits: { maxBytes: number; timeoutMs: number }, requestImpl: typeof request = request): Promise<{ body: Buffer; contentType: string }> {
  return new Promise((resolve, reject) => {
    let settled = false; const finish = (error?: Error, result?: { body: Buffer; contentType: string }) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(result!); };
    const req = requestImpl(url, { method: 'GET', agent: false, minVersion: 'TLSv1.2', rejectUnauthorized: true, maxHeaderSize: 16384, servername: url.hostname, headers: { Accept: 'text/plain, text/html, text/markdown, application/json', 'Accept-Encoding': 'identity', 'User-Agent': 'AutoSoft-Official-Research/1' }, lookup: (_host, options, callback) => {
      if (typeof options === 'object' && options.all) callback(null, [{ address: pinned.address, family: pinned.family }]);
      else callback(null, pinned.address, pinned.family);
    } }, response => {
      const fail = (message: string) => { finish(new Error(message)); response.destroy(); req.destroy(); };
      if (response.statusCode !== 200) { fail('Official research source did not return HTTP 200; redirects are not followed'); return; }
      const type = String(response.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
      if (!['text/plain', 'text/html', 'text/markdown', 'application/json', 'application/xhtml+xml'].includes(type) || response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity') { fail('Research source format is unsupported'); return; }
      const declared = response.headers['content-length'];
      if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > limits.maxBytes)) { fail('Research source exceeds its bounded response size'); return; }
      const chunks: Buffer[] = []; let bytes = 0;
      response.on('data', (chunk: Buffer) => { bytes += chunk.length; if (bytes > limits.maxBytes) fail('Research source exceeds its bounded response size'); else chunks.push(chunk); });
      response.on('error', () => finish(new Error('Research response interrupted')));
      response.on('end', () => finish(undefined, { body: Buffer.concat(chunks), contentType: type }));
    });
    const timer = setTimeout(() => { finish(new Error('Research source timeout')); req.destroy(); }, limits.timeoutMs);
    req.on('socket', socket => socket.once('secureConnect', () => {
      const actual = socket.remoteAddress?.replace(/^::ffff:/, '');
      if (!actual || canonicalAddress(actual) !== canonicalAddress(pinned.address)) { finish(new Error('Research connection did not use its pinned DNS address')); req.destroy(); }
    }));
    req.on('error', () => finish(new Error('Official research HTTPS connection unavailable'))); req.end();
  });
}
export function createResearchFetcher(options: { resolve?: (host: string) => Promise<ResolvedAddress[]>; transport?: PinnedTransport; maxBytes?: number; timeoutMs?: number } = {}): ResearchFetcher {
  const maxBytes = options.maxBytes ?? 1024 * 1024, timeoutMs = options.timeoutMs ?? 10000;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 1024 * 1024 || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) throw new Error('Invalid research network limits');
  return async value => {
    const url = officialUrl(value);
    const started = Date.now();
    const addresses = await deadline((options.resolve ?? (host => lookup(host, { all: true, verbatim: true })))(url.hostname), timeoutMs);
    if (!addresses.length || addresses.length > 16 || addresses.some(item => ![4, 6].includes(item.family) || isIP(item.address) !== item.family || !publicResearchAddress(item.address))) throw new Error('Research DNS contains an unsafe or unavailable address');
    const remaining = timeoutMs - (Date.now() - started); if (remaining <= 0) throw new Error('Research source timeout');
    // IPv4 preference avoids an unusable IPv6 route on IPv4-only installations.
    // Every returned answer was checked above; no second DNS resolution or fallback occurs.
    const pinned = addresses.find(address => address.family === 4) ?? addresses[0]!;
    const result = await deadline((options.transport ?? pinnedResearchHttps)(url, pinned, { maxBytes, timeoutMs: remaining }), remaining);
    if (!Buffer.isBuffer(result.body) || result.body.length === 0 || result.body.length > maxBytes || !['text/plain', 'text/html', 'text/markdown', 'application/json', 'application/xhtml+xml'].includes(result.contentType)) throw new Error('Research response is invalid or exceeds limits');
    return result;
  };
}

export function validateIntegrationCatalog(value: unknown, now = Date.now()): IntegrationCatalog {
  const catalog = integrationCatalogSchema.parse(value), ids = new Set<string>(), urls = new Set<string>();
  for (const integration of catalog.integrations) {
    if (ids.has(integration.id) || new Set(integration.aliases.map(alias => alias.toLowerCase())).size !== integration.aliases.length) throw new Error('Duplicate protected research catalog identity'); ids.add(integration.id);
    if (!integration.sources.some(source => source.purpose === 'documentation') || integration.sources.some(source => source.purpose === 'sdk') && !integration.sources.some(source => source.purpose === 'license')) throw new Error('Official documentation and selected SDK license references are required');
    const sdk = integration.sources.find(source => source.purpose === 'sdk');
    if (sdk && (!sdk.sdkCandidate || !integration.sources.some(source => source.purpose === 'license' && hashArtifact(source.sdkCandidate) === hashArtifact(sdk.sdkCandidate)))) throw new Error('SDK candidates require an exact publisher repository and matching license reference');
    for (const source of integration.sources) {
      officialUrl(source.url); const review = Date.parse(source.metadata.reviewedAt);
      if (source.purpose === 'documentation' && source.sdkCandidate || source.purpose === 'sdk' && !source.sdkCandidate || source.purpose === 'license' && !source.sdkCandidate && integration.id !== 'filesystem') throw new Error('SDK provenance identity is missing or inconsistent');
      if (source.sdkCandidate) { const repository = officialUrl(source.sdkCandidate.repository), url = officialUrl(source.url); if (repository.origin !== 'https://github.com' || !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository.pathname) || url.hostname !== 'raw.githubusercontent.com' || !url.pathname.startsWith(`${repository.pathname}/`)) throw new Error('SDK source does not match its publisher repository'); }
      if (review > now + 60000 || now - review > 30 * 86400000 || Object.entries(source.metadata).some(([key, value]) => !['qualification', 'reviewStatus', 'reviewedAt'].includes(key) && /^(?:unknown|pending|unreviewed|n\/a)$/i.test(value.trim())) || urls.has(source.url)) throw new Error('Company source provenance, license or maintenance review is missing or stale');
      urls.add(source.url);
    }
  }
  return catalog;
}
function textExcerpt(body: Buffer, type: string, secrets: string[], maxChars: number): string {
  let text = new TextDecoder('utf-8', { fatal: true }).decode(body);
  if (/<title[^>]*>\s*(?:just a moment|access denied|security check|sign in)[\s\S]*?<\/title>/i.test(text)) throw new Error('Research returned a login or challenge page');
  if (type === 'text/html' || type === 'application/xhtml+xml') text = text.replace(/<(script|style|noscript)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ').replace(/<!--[\s\S]*?-->/g, ' ').replace(/<[^>]*>/g, ' ').replace(/&(?:nbsp|amp|lt|gt|quot|#39);/g, ' ');
  text = String(redact(text, secrets)).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '').replace(/\s+/g, ' ').trim().slice(0, maxChars);
  if (text.length < 40) throw new Error('Official research source contains insufficient readable evidence'); return text;
}
function recordHash(record: Omit<IntegrationResearchRecord, 'evidenceHash'> | IntegrationResearchRecord): string { const { evidenceHash: _ignored, ...value } = record as IntegrationResearchRecord; return hashArtifact(value); }
function owned(state: State, input: ResearchInput, now: number): boolean {
  const app = state.apps[input.app.id], job = state.jobs[input.job.id], lease = state.leases[input.job.id];
  return !!app && app.status !== 'archived' && !!job && job.appId === app.id && job.stage !== 'cancelled' && job.request === input.job.request && app.activeReleaseId === input.job.baseReleaseId && job.baseReleaseId === input.job.baseReleaseId && job.runtimeFence === input.worker.runtimeFence && app.runtimeFence === input.worker.runtimeFence && lease?.owner === input.worker.owner && Date.parse(lease.until) > now;
}
function contextHash(input: ResearchInput, secrets: string[]): string { return hashArtifact(redact({ appId: input.app.id, jobId: input.job.id, baseReleaseId: input.job.baseReleaseId, request: input.job.request, previousSpecification: input.context.previousSpecification ?? null, answer: input.context.answer ?? null, connectionInventory: input.context.connectionInventory ?? null }, secrets)); }
function requested(catalog: IntegrationCatalog, input: ResearchInput): IntegrationCatalog['integrations'] {
  const raw = JSON.stringify({ request: input.job.request, answer: input.context.answer, previousSpecification: input.context.previousSpecification });
  if (raw.length > 100000) throw new IntegrationResearchUnavailable('setup');
  const text = raw.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  const types = new Set(input.context.connectionInventory?.connections.filter(connection => [connection.id, connection.name].some(value => value.length >= 3 && text.includes(value.toLowerCase()))).map(connection => connection.type));
  return catalog.integrations.filter(integration => types.has(integration.id) || integration.aliases.some(alias => { const normalized = alias.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); return new RegExp(`(?:^|[^a-z0-9])${normalized}(?:$|[^a-z0-9])`).test(text); }));
}
function projection(record: IntegrationResearchRecord, now = Date.now()): IntegrationResearchContext {
  if (record.status !== 'retrieved' || !record.catalogHash || recordHash(record) !== record.evidenceHash) throw new Error('Research record is unavailable or corrupt');
  return validatedIntegrationResearch({ schemaVersion: 1, appId: record.appId, jobId: record.jobId, catalogHash: record.catalogHash, contextHash: record.contextHash, evidenceHash: record.evidenceHash, asOf: record.asOf, expiresAt: record.expiresAt,
    integrations: record.integrations.map(integration => ({ id: integration.id, runtimeAdapter: integration.id === 'samba' ? 'separate_samba_authorization_and_live_verification_required' : integration.id === 'filesystem' ? 'separate_filesystem_authorization_and_live_verification_required' : 'unavailable', sources: integration.sources.map(source => {
      if (source.status !== 'retrieved' || !source.text || !source.bodySha256 || !/^[a-f0-9]{64}$/.test(source.bodySha256) || sha(source.text) !== source.textSha256) throw new Error('Research source evidence is corrupt');
      return { url: source.url, purpose: source.purpose, sdkCandidate: source.sdkCandidate, metadata: source.metadata, sourceHash: source.sourceHash, bodySha256: source.bodySha256, textSha256: source.textSha256, retrievedAt: source.retrievedAt, text: source.text };
    }) })) }, record.appId, record.jobId, now)!;
}
function exactSources(record: IntegrationResearchRecord, selected: IntegrationCatalog['integrations']): boolean { return record.integrations.length === selected.length && record.integrations.every((integration, index) => integration.id === selected[index]?.id && integration.sources.length === selected[index]?.sources.length && integration.sources.every((source, sourceIndex) => source.sourceHash === hashArtifact(selected[index]!.sources[sourceIndex]) && hashArtifact({ url: source.url, purpose: source.purpose, sdkCandidate: source.sdkCandidate, metadata: source.metadata }) === source.sourceHash)); }
export function createIntegrationResearch(store: Store, options: { catalogFile?: string; readCatalog?: () => Promise<unknown>; fetch?: ResearchFetcher; knownSecrets?: string[]; now?: () => number } = {}) {
  const now = options.now ?? Date.now, load = options.readCatalog ?? (async () => { const text = await readFile(options.catalogFile ?? 'models/integrations.json', 'utf8'); if (Buffer.byteLength(text) > 128 * 1024) throw new Error('Company research catalog exceeds its bound'); return JSON.parse(text); }), fetch = options.fetch ?? createResearchFetcher(), secrets = options.knownSecrets ?? [];
  const persist = async (input: ResearchInput, record: IntegrationResearchRecord) => {
    record.evidenceHash = recordHash(record);
    await store.transaction(state => {
      if (!owned(state, input, now())) throw new Error('Integration research worker lease or fence lost; stale results were rejected');
      const records = Object.values(state.integrationResearch);
      if (records.filter(existing => existing.appId === input.app.id).length >= 256 || records.filter(existing => existing.jobId === input.job.id).length >= 32) throw new IntegrationResearchUnavailable('setup');
      state.integrationResearch[record.id] = record;
      event(state, state.jobs[input.job.id]!, 'specification', record.status === 'retrieved' ? 'Official integration evidence recorded. SDK qualification and connection authorization remain separate required checks.' : 'Required official source or company review evidence is unavailable; development is paused before model execution.', 'status', { researchRecordId: record.id, status: record.status });
    });
  };
  return async (input: ResearchInput): Promise<IntegrationResearchContext> => {
    if (!await store.read(state => owned(state, input, now()))) throw new Error('Integration research worker lease or fence lost; no generation is authorized');
    const expectedContext = contextHash(input, secrets);
    let catalog: IntegrationCatalog;
    try { catalog = validateIntegrationCatalog(await load(), now()); } catch {
      const record: IntegrationResearchRecord = { id: randomUUID(), appId: input.app.id, jobId: input.job.id, runtimeFence: input.worker.runtimeFence, contextHash: expectedContext, catalogHash: null, evidenceHash: '', asOf: new Date(now()).toISOString(), expiresAt: new Date(now()).toISOString(), status: 'unavailable', availabilityReason: 'protected_catalog_unavailable', integrations: [] };
      await persist(input, record); throw new IntegrationResearchUnavailable('setup', record.id);
    }
    const catalogHash = hashArtifact(catalog), selected = requested(catalog, input);
    const cached = await store.read(state => {
      if (!owned(state, input, now())) throw new Error('Integration research worker lease or fence lost; no generation is authorized');
      return Object.values(state.integrationResearch).find(record => record.jobId === input.job.id && record.appId === input.app.id && record.contextHash === expectedContext && record.catalogHash === catalogHash && record.status === 'retrieved' && Date.parse(record.expiresAt) > now());
    });
    if (cached) {
      try { if (exactSources(cached, selected)) return projection(cached, now()); } catch { /* Never reuse corrupt or stale evidence. */ }
    }
    const asOf = new Date(now()).toISOString(), record: IntegrationResearchRecord = { id: randomUUID(), appId: input.app.id, jobId: input.job.id, runtimeFence: input.worker.runtimeFence, contextHash: expectedContext, catalogHash, evidenceHash: '', asOf, expiresAt: new Date(Date.parse(asOf) + 86400000).toISOString(), status: 'retrieved', availabilityReason: null, integrations: [] };
    const excerptLimit = Math.min(8000, Math.floor(24000 / Math.max(1, selected.reduce((sum, integration) => sum + integration.sources.length, 0))));
    // At most eighteen credential-free reads, sequential and individually bounded. No source-provided links are fetched.
    for (const integration of selected) {
      const sources: ResearchSource[] = [];
      for (const source of integration.sources) {
        await store.transaction(state => { if (!owned(state, input, now())) throw new Error('Integration research worker lease or fence lost; no generation is authorized'); event(state, state.jobs[input.job.id]!, 'specification', `Reading official ${integration.id} ${source.purpose} evidence (${sources.length + 1}/${integration.sources.length}).`, 'status'); });
        try {
          const result = await fetch(source.url), text = textExcerpt(result.body, result.contentType, secrets, excerptLimit);
          sources.push({ ...source, sourceHash: hashArtifact(source), status: 'retrieved', retrievedAt: new Date(now()).toISOString(), bodySha256: sha(result.body), textSha256: sha(text), text, reason: null });
        } catch {
          record.status = 'unavailable'; record.availabilityReason = 'source_unavailable'; sources.push({ ...source, sourceHash: hashArtifact(source), status: 'unavailable', retrievedAt: new Date(now()).toISOString(), bodySha256: null, textSha256: null, text: null, reason: 'Official source retrieval unavailable or rejected by bounded network/format controls; SDK suitability remains unqualified.' });
        }
      }
      record.integrations.push({ id: integration.id, sources });
    }
    let currentCatalogHash: string;
    try { currentCatalogHash = hashArtifact(validateIntegrationCatalog(await load(), now())); } catch { throw new IntegrationResearchUnavailable('setup'); }
    if (currentCatalogHash !== catalogHash) throw new IntegrationResearchUnavailable('setup');
    await persist(input, record);
    if (record.status === 'unavailable') throw new IntegrationResearchUnavailable('runtime_unavailable', record.id);
    return projection(record, now());
  };
}
