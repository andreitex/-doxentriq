import { z } from 'zod';
import type { Store } from './store.ts';
import type { Config } from './config.ts';
import type { EngineDependencies } from './engine.ts';
import { releaseArtifactHash } from '../../../packages/core/src/index.ts';
import { imageSchema } from '../../../packages/core/src/schemas.ts';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const catalogSchema = z.object({ apps: z.array(z.object({ appId: z.string().uuid(), releaseId: z.string().uuid(), artifactHash: z.string().regex(/^[a-f0-9]{64}$/), images: z.array(imageSchema).min(1).max(32), auth: z.enum(['public', 'local', 'sso']) }).strict()).max(1000) }).strict();
export function isPortalHost(host: string | undefined, config: Config): boolean { return !!config.appsOrigin && host === new URL(config.appsOrigin).host; }
export async function loadPortalAssetWhitelist(dist: string): Promise<Set<string>> {
  const manifest: unknown = JSON.parse(await readFile(join(dist, '.vite', 'manifest.json'), 'utf8'));
  const entry = z.object({ file: z.string(), css: z.array(z.string()).optional(), assets: z.array(z.string()).optional(), imports: z.array(z.string()).optional(), dynamicImports: z.array(z.string()).optional() }).passthrough();
  const parsed = z.record(z.string(), entry).parse(manifest); const visited = new Set<string>(), assets = new Set<string>();
  const add = (file: string) => { if (!/^assets\/[a-zA-Z0-9_.-]+$/.test(file)) throw new Error('Portal manifest assets must be bounded compiled filenames.'); assets.add(file.slice('assets/'.length)); };
  const walk = (key: string) => { if (visited.has(key)) return; if (visited.size >= 100) throw new Error('Portal manifest dependency graph exceeds its bound.'); visited.add(key); const value = parsed[key]; if (!value) throw new Error('Portal manifest dependency is unavailable.'); add(value.file); for (const file of [...(value.css ?? []), ...(value.assets ?? [])]) add(file); for (const dependency of [...(value.imports ?? []), ...(value.dynamicImports ?? [])]) walk(dependency); };
  walk('portal.html'); return assets;
}
export async function publicCatalog(store: Store, config: Config, dependencies: EngineDependencies) {
  if (!config.appsOrigin || new URL(config.appsOrigin).protocol !== 'https:' || !(dependencies.publishedCatalog || dependencies.publicCatalog)) throw Object.assign(new Error('The verified application catalog is unavailable.'), { statusCode: 503 });
  const parsed = catalogSchema.safeParse(await (dependencies.publishedCatalog ?? dependencies.publicCatalog!)());
  if (!parsed.success) throw Object.assign(new Error('The trusted catalog returned malformed publication evidence.'), { statusCode: 503 });
  const portalOrigin = new URL(config.appsOrigin); const entries = new Map(parsed.data.apps.map(entry => [entry.appId, entry]));
  if (entries.size !== parsed.data.apps.length) throw Object.assign(new Error('The trusted catalog returned ambiguous application entries.'), { statusCode: 503 });
  return store.read(state => ({ schemaVersion: 2, portalOrigin: portalOrigin.origin, listingPolicy: 'explicit_listing', apps: Object.values(state.apps).flatMap(app => {
    const entry = entries.get(app.id); const release = app.activeReleaseId ? state.releases[app.activeReleaseId] : undefined;
    if (!entry || !release || app.status === 'archived' || release.status !== 'published' || release.appId !== app.id || entry.releaseId !== release.id || entry.artifactHash !== release.artifactHash || releaseArtifactHash(release) !== entry.artifactHash || JSON.stringify(entry.images) !== JSON.stringify(release.images) || app.kind === 'worker' || app.slug.startsWith('preview-') || !/^[a-z][a-z0-9-]{1,47}$/.test(app.slug)) return [];
    const listing = state.portalListings[app.id];
    if (listing?.visibility === 'unlisted' || (entry.auth !== 'public' && listing?.visibility !== 'listed')) return [];
    if (listing && (listing.slug !== app.slug || listing.url !== `https://${app.slug}.${portalOrigin.host}/`)) return [];
    return [{ id: app.id, name: listing?.name ?? app.name, description: listing?.description ?? app.description, kind: app.kind, access: entry.auth === 'public' ? 'public' : 'signin_required', url: `https://${app.slug}.${portalOrigin.host}/` }];
  }).sort((a, b) => a.name.localeCompare(b.name)) }));
}
