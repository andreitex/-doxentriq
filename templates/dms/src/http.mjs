import { createServer } from 'node:http';
import { createServer as createSecureServer } from 'node:https';
import { readFile } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';
import { HttpError } from './domain.mjs';
import { handleMcp } from './mcp.mjs';

async function jsonBody(request) {
  if (!String(request.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) throw new HttpError(415, 'Use application/json.');
  let size = 0; const parts = [];
  for await (const part of request) { size += part.length; if (size > 24 * 1024 * 1024) throw new HttpError(413, 'The request is too large.'); parts.push(part); }
  try { const value = JSON.parse(Buffer.concat(parts).toString('utf8')); if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error(); return value; } catch { throw new HttpError(400, 'A JSON object is required.'); }
}
function content(input) { if (typeof input !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(input)) throw new HttpError(400, 'Valid base64 document content is required.'); return Buffer.from(input, 'base64'); }
export function createApplication({ service, verify, publicConfig, origin, staticRoot, ready = async () => {}, tls, allowInsecureHttp = false }) {
  if (!origin) throw new Error('An exact application Origin is required.');
  if (!tls && !allowInsecureHttp) throw new Error('Application TLS is required unless explicitly using a local test transport.');
  if (tls && (!tls.cert || !tls.key)) throw new Error('The TLS certificate and key must be supplied together.');
  const oidcOrigin = new URL(publicConfig.issuer).origin;
  const handler = async (request, response) => {
    response.setHeader('x-content-type-options', 'nosniff'); response.setHeader('referrer-policy', 'no-referrer'); response.setHeader('cache-control', 'no-store'); response.setHeader('content-security-policy', `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ${oidcOrigin}; img-src 'self' blob:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' ${oidcOrigin}`);
    const send = (status, value) => { response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' }); response.end(value === undefined ? undefined : JSON.stringify(value)); };
    try {
      if (request.headers.origin && request.headers.origin !== origin) throw new HttpError(403, 'The request Origin is not allowed.');
      const url = new URL(request.url, 'http://internal.invalid'), path = url.pathname, method = request.method;
      if (method === 'GET' && path === '/healthz') { await ready(); return send(200, { ready: true }); }
      if (method === 'GET' && path === '/api/config') return send(200, publicConfig);
      if (method === 'GET' && path === '/.well-known/oauth-protected-resource') return send(200, { resource: origin + '/mcp', authorization_servers: [publicConfig.issuer], scopes_supported: ['dms.read', 'dms.search'], bearer_methods_supported: ['header'] });
      if (path === '/mcp') {
        const principal = await verify(request.headers.authorization, 'mcp');
        if (method === 'GET' || method === 'DELETE') { response.setHeader('allow', 'POST'); return send(405, { error: 'This stateless MCP endpoint uses JSON responses and does not offer an SSE stream.' }); }
        if (method !== 'POST') throw new HttpError(405, 'Method not allowed.');
        const accept = String(request.headers.accept ?? ''); if (!accept.includes('application/json') || !accept.includes('text/event-stream')) throw new HttpError(406, 'Accept application/json and text/event-stream.');
        const value = await handleMcp({ message: await jsonBody(request), principal, service, protocolHeader: request.headers['mcp-protocol-version'] }); return value === null ? send(202) : send(200, value);
      }
      if (path.startsWith('/api/')) {
        const principal = await verify(request.headers.authorization, 'api');
        if (method === 'GET' && path === '/api/session') return send(200, { principal: { id: principal.id, appId: principal.appId, roles: principal.roles.filter(permission => ['dms.read', 'dms.write', 'dms.admin', 'dms.search'].includes(permission)), permissionsValidUntil: new Date(Math.min(Date.now() + 60000, principal.directoryAuthorization ? Date.parse(principal.directoryAuthorization.validUntil) : Infinity)).toISOString() } });
        if (method === 'GET' && path === '/api/folders') return send(200, { folders: await service.listFolders(principal) });
        if (method === 'POST' && path === '/api/folders') return send(201, { folder: await service.createFolder(principal, await jsonBody(request)) });
        if (method === 'GET' && path === '/api/documents') return send(200, { documents: await service.search(principal, url.searchParams.get('q') ?? '', url.searchParams.get('archived') === 'true') });
        if (method === 'POST' && path === '/api/documents') { const input = await jsonBody(request); return send(201, { document: await service.upload(principal, { ...input, content: content(input.contentBase64) }) }); }
        const match = /^\/api\/documents\/([a-zA-Z0-9_-]+)(?:\/(versions|restore|archive)(?:\/([a-zA-Z0-9_-]+)(?:\/(content))?)?)?$/.exec(path);
        if (match) {
          const [, documentId, action, versionId, download] = match;
          if (method === 'GET' && !action) return send(200, { document: await service.document(principal, documentId) });
          if (method === 'GET' && action === 'versions' && !versionId) return send(200, { versions: await service.versions(principal, documentId) });
          if (method === 'POST' && action === 'versions' && !versionId) { const input = await jsonBody(request); return send(201, { document: await service.upload(principal, { ...input, content: content(input.contentBase64) }, documentId) }); }
          if (method === 'POST' && action === 'restore' && !versionId) return send(201, { version: await service.restore(principal, documentId, (await jsonBody(request)).versionId) });
          if (method === 'POST' && action === 'archive' && !versionId) { await jsonBody(request); return send(200, await service.archive(principal, documentId)); }
          if (method === 'GET' && action === 'versions' && versionId && download) { const value = await service.content(principal, documentId, versionId); response.writeHead(200, { 'content-type': value.mime, 'content-disposition': 'attachment; filename="document"', 'content-length': value.content.length }); return response.end(value.content); }
        }
        if (method === 'GET' && path === '/api/audit') return send(200, { records: await service.auditRecords(principal) });
        const samba = /^\/api\/connections\/([a-zA-Z0-9_-]+)\/(list|read)$/.exec(path);
        if (method === 'POST' && samba) { const input = await jsonBody(request); return send(200, await service.samba(principal, samba[1], samba[2], input.path ?? '')); }
        throw new HttpError(404, 'API route was not found.');
      }
      if (method === 'GET' && staticRoot) {
        const requested = path === '/' || path === '/auth/callback' ? '/index.html' : path, filename = resolve(staticRoot, '.' + requested);
        if (!filename.startsWith(resolve(staticRoot) + sep) || !['.html', '.js', '.css', '.svg'].includes(extname(filename))) throw new HttpError(404, 'Page was not found.');
        let body; try { body = await readFile(filename); } catch { throw new HttpError(404, 'Page was not found.'); }
        response.writeHead(200, { 'content-type': ({ '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' })[extname(filename)] }); return response.end(body);
      }
      throw new HttpError(404, 'Route was not found.');
    } catch (error) {
      if (error.status === 401) response.setHeader('www-authenticate', request.url?.startsWith('/mcp') ? `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"` : 'Bearer');
      // Provider, database, content, headers, paths, and credentials never enter logs or error bodies.
      send(error instanceof HttpError ? error.status : 503, { error: error instanceof HttpError ? error.message : 'The application could not complete this request. Please contact its administrator.' });
    }
  };
  const server = tls ? createSecureServer(tls, handler) : createServer(handler);
  server.requestTimeout = 30000; server.headersTimeout = 15000; return server;
}
