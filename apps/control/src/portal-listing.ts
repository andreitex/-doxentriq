import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import type { Store } from './store.ts';
import type { Config } from './config.ts';
import { requireOwner } from './auth.ts';
import { releaseArtifactHash } from '../../../packages/core/src/index.ts';
import { slugSchema } from '../../../packages/core/src/schemas.ts';

export type PortalListing = {
  appId: string; revision: number; visibility: 'listed' | 'unlisted';
  name: string; description: string; slug: string; changedBy: string; changedAt: string;
  url: string; releaseId: string; artifactHash: string;
};
const fault = (statusCode: number, message: string) => Object.assign(new Error(message), { statusCode });
const changeSchema = z.object({
  revision: z.number().int().nonnegative(), visibility: z.enum(['listed', 'unlisted']),
  releaseId: z.string().uuid(), artifactHash: z.string().regex(/^[a-f0-9]{64}$/),
  acknowledgePublicListing: z.boolean(),
  name: z.string().min(1).max(120), description: z.string().max(5000),
  slug: slugSchema, url: z.string().url().max(2048),
}).strict();

function listingUrl(slug: string, config: Config): string | null {
  if (!config.appsOrigin || !slugSchema.safeParse(slug).success) return null;
  try {
    const origin = new URL(config.appsOrigin);
    if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) return null;
    return `https://${slug}.${origin.host}/`;
  } catch { return null; }
}

export function installPortalListingRoutes(server: FastifyInstance, store: Store, config: Config) {
  server.get<{ Params: { id: string } }>('/api/v1/apps/:id/portal-listing', async request => store.read(state => {
    const app = state.apps[request.params.id]; if (!app) throw fault(404, 'Application not found.');
    const listing = state.portalListings[app.id];
    const release = app.activeReleaseId ? state.releases[app.activeReleaseId] : undefined;
    const url = listingUrl(app.slug, config);
    return { revision: listing?.revision ?? 0, visibility: listing?.visibility ?? 'default',
      name: app.name, description: app.description, slug: app.slug, url,
      releaseId: release?.id ?? null, artifactHash: release?.artifactHash ?? null,
      canList: !!url && app.kind !== 'worker' && app.status !== 'archived' && release?.status === 'published' };
  }));
  server.put<{ Params: { id: string } }>('/api/v1/apps/:id/portal-listing', async request => {
    requireOwner(request);
    const body = changeSchema.parse(request.body);
    if (body.visibility === 'listed' && !body.acknowledgePublicListing) throw fault(400, 'Confirm that visitors may see the application name, description and link.');
    return store.transaction(state => {
      const app = state.apps[request.params.id]; if (!app) throw fault(404, 'Application not found.');
      const previous = state.portalListings[app.id];
      if (body.name !== app.name || body.description !== app.description) throw fault(409, 'Application details changed. Refresh and review the text visitors will see.');
      const url = listingUrl(app.slug, config);
      if (!url || body.slug !== app.slug || body.url !== url) throw fault(409, 'The application link changed. Refresh and review the exact link visitors will see.');
      if ((previous?.revision ?? 0) !== body.revision) throw fault(409, 'Directory settings changed. Refresh and review them again.');
      const release = app.activeReleaseId ? state.releases[app.activeReleaseId] : undefined;
      if (!release || release.id !== body.releaseId || release.status !== 'published' || release.appId !== app.id || release.artifactHash !== body.artifactHash || releaseArtifactHash(release) !== body.artifactHash) throw fault(409, 'The published release changed. Refresh and review the application again.');
      if (body.visibility === 'listed' && (app.status === 'archived' || app.kind === 'worker')) throw fault(409, 'This application cannot be listed in the portal.');
      const listing: PortalListing = { appId: app.id, revision: body.revision + 1, visibility: body.visibility,
        name: app.name, description: app.description, slug: app.slug,
        url, releaseId: release.id, artifactHash: release.artifactHash,
        changedBy: request.principal!.id, changedAt: new Date().toISOString() };
      state.portalListings[app.id] = listing;
      state.portalListingHistory[randomUUID()] = listing;
      return { listing };
    });
  });
}
