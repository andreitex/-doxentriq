export type PublicPortalApp = {
  id: string; name: string; description: string; kind: 'web' | 'api' | 'mcp'; access: 'public' | 'signin_required'; url: string;
};
export type PublicPortalCatalog = {
  schemaVersion: 1 | 2; portalOrigin: string; listingPolicy: 'public_only' | 'explicit_listing'; apps: PublicPortalApp[];
};

function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
const invalid = () => new Error('The published application list could not be verified. Contact your company operator.');

// Browser validation is defense in depth. Publication and public discovery policy
// must be checked independently by the backend against protected runtime evidence.
export function parsePortalCatalog(value: unknown, expectedOrigin: string): PublicPortalCatalog {
  const origin = new URL(expectedOrigin);
  if (!record(value) || !((value.schemaVersion === 1 && value.listingPolicy === 'public_only') || (value.schemaVersion === 2 && value.listingPolicy === 'explicit_listing')) || value.portalOrigin !== origin.origin || !Array.isArray(value.apps) || value.apps.length > 1000) throw invalid();
  const ids = new Set<string>();
  const urls = new Set<string>();
  const apps: PublicPortalApp[] = value.apps.map(item => {
    if (!record(item) || typeof item.id !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$/.test(item.id) || ids.has(item.id) || typeof item.name !== 'string' || !item.name.trim() || item.name.length > 120 || typeof item.description !== 'string' || item.description.length > 5000 || !['web', 'api', 'mcp'].includes(String(item.kind)) || !(item.access === 'public' || (value.schemaVersion === 2 && item.access === 'signin_required')) || typeof item.url !== 'string') throw invalid();
    let destination: URL;
    try { destination = new URL(item.url); } catch { throw invalid(); }
    const suffix = `.${origin.hostname}`;
    const slug = destination.hostname.endsWith(suffix) ? destination.hostname.slice(0, -suffix.length) : '';
    if (destination.protocol !== 'https:' || destination.username || destination.password || destination.port !== origin.port || !/^[a-z][a-z0-9-]{1,47}$/.test(slug) || ['admin', 'auth', 'api', 'registry', 'metrics', 'preview'].includes(slug) || slug.startsWith('preview-') || destination.pathname !== '/' || destination.search || destination.hash || urls.has(destination.href)) throw invalid();
    ids.add(item.id); urls.add(destination.href);
    return { id: item.id, name: item.name.trim(), description: item.description, kind: item.kind as PublicPortalApp['kind'], access: item.access as PublicPortalApp['access'], url: destination.href };
  });
  return { schemaVersion: value.schemaVersion as 1 | 2, portalOrigin: origin.origin, listingPolicy: value.listingPolicy as PublicPortalCatalog['listingPolicy'], apps };
}

export async function loadPortalCatalog(origin: string, signal?: AbortSignal, transport: typeof fetch = fetch): Promise<PublicPortalCatalog> {
  const response = await transport('/api/public/v1/apps', { method: 'GET', headers: { Accept: 'application/json' }, credentials: 'omit', cache: 'no-store', redirect: 'error', signal });
  if (!response.ok) throw new Error('The application directory is temporarily unavailable. Retry or contact your company operator.');
  if (!(response.headers.get('content-type') ?? '').toLowerCase().includes('application/json')) throw invalid();
  const text = await response.text();
  if (text.length > 1024 * 1024) throw invalid();
  let data: unknown;
  try { data = JSON.parse(text); } catch { throw invalid(); }
  return parsePortalCatalog(data, origin);
}
