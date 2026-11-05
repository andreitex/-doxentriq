import { useEffect, useState } from 'react';
import { ArrowUpRight, Code2, Globe, Layers3, LockKeyhole, RefreshCw, Search, Sparkles } from 'lucide-react';
import { loadPortalCatalog, type PublicPortalCatalog } from './catalog';

const kindLabels = { web: 'Application', api: 'API service', mcp: 'MCP service' };

export function PortalView({ catalog, loading, error, onRetry }: { catalog?: PublicPortalCatalog; loading: boolean; error?: string; onRetry: () => void }) {
  const [query, setQuery] = useState('');
  const apps = catalog?.apps.filter(app => `${app.name} ${app.description}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())) ?? [];
  return <div className="portal-shell"><a className="portal-skip" href="#applications">Skip to applications</a>
    <header className="portal-header"><a className="portal-brand" href="/" aria-label="AutoSoft applications home"><span><Layers3 size={23} strokeWidth={1.7} /></span>AutoSoft<span className="portal-period">.</span></a><span className="portal-header-label"><Globe size={15} />APPLICATIONS</span></header>
    <main className="portal-main" id="applications"><div className="portal-hero"><span className="portal-eyebrow"><Sparkles size={14} />YOUR ORGANIZATION’S APPLICATIONS</span><h1>A place to get things done.</h1><p>Open a published application and get started.</p></div>
      <div className="portal-tools"><div className="portal-section-heading"><h2>Application directory</h2>{catalog && <span>{catalog.apps.length} {catalog.apps.length === 1 ? 'app' : 'apps'}</span>}</div><div className="portal-tools-actions"><label className="portal-search"><Search size={17} /><span className="portal-sr-only">Search applications</span><input type="search" placeholder="Find an application…" value={query} onChange={event => setQuery(event.target.value)} disabled={!catalog} /></label><button className="portal-refresh" onClick={onRetry} disabled={loading} aria-label="Refresh published applications"><RefreshCw size={18} className={loading ? 'portal-spin' : ''} /></button></div></div>
      {error && <div className="portal-error" role="alert"><p>{error}</p><button onClick={onRetry} disabled={loading}>Try again</button></div>}
      {loading && !catalog ? <div className="portal-empty" role="status"><RefreshCw className="portal-spin" size={27} /><h2>Loading published applications…</h2><p>Checking the application directory.</p></div> : catalog ? apps.length > 0 ? <div className="portal-grid">{apps.map(app => <article className="portal-card" key={app.id}><div className="portal-card-top"><span className="portal-app-icon">{app.kind === 'web' ? <Layers3 size={25} strokeWidth={1.6} /> : <Code2 size={25} strokeWidth={1.6} />}</span><span className="portal-public">{app.access === 'signin_required' ? <LockKeyhole size={13} /> : <span />}{app.access === 'signin_required' ? 'Sign in required' : 'Public access'}</span></div><h2>{app.name}</h2><p className="portal-description">{app.description || 'Open this published application to learn more.'}</p><div className="portal-card-footer"><span>{kindLabels[app.kind]}</span><a href={app.url} rel="noopener noreferrer">Open {app.kind === 'web' ? 'app' : 'service'}<ArrowUpRight size={16} /></a></div></article>)}</div> : <div className="portal-empty"><Layers3 size={30} strokeWidth={1.4} /><h2>{query.trim() ? 'No matching applications' : 'No applications are listed yet'}</h2><p>{query.trim() ? 'Try another name or clear your search.' : 'Your administrator can list published applications here. Ask them for a direct link if your app is missing.'}</p>{query.trim() && <button onClick={() => setQuery('')}>Clear search</button>}</div> : !loading && <div className="portal-empty"><Globe size={28} /><h2>The application directory is unavailable</h2><p>Retry to request the current published application list.</p></div>}
      <aside className="portal-private"><span><LockKeyhole size={20} /></span><div><h2>Looking for a private application?</h2><p>Use the direct app link provided by your organization. Sign in on that application’s page with its configured company SSO or local account. Some applications are hidden from this directory. Being listed does not grant access to protected content.</p></div></aside>
    </main><footer className="portal-footer"><span>Built with AutoSoft</span><span>Each application manages its own access.</span></footer>
  </div>;
}

export default function Portal() {
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<{ catalog?: PublicPortalCatalog; loading: boolean; error?: string }>({ loading: true });
  useEffect(() => {
    const controller = new AbortController();
    setState(previous => ({ ...previous, loading: true, error: undefined }));
    loadPortalCatalog(window.location.origin, controller.signal)
      .then(catalog => { if (!controller.signal.aborted) setState({ catalog, loading: false }); })
      .catch(error => { if (!controller.signal.aborted) setState({ loading: false, error: error instanceof Error ? error.message : 'The application directory is temporarily unavailable.' }); });
    return () => controller.abort();
  }, [revision]);
  return <PortalView {...state} onRetry={() => setRevision(value => value + 1)} />;
}
