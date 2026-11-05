import { readFile } from 'node:fs/promises';
import { HttpError } from './domain.mjs';

export function safeRelativePath(value) {
  if (typeof value !== 'string' || value.length > 512 || /[\\:%\x00-\x1f\x7f]/.test(value) || value.startsWith('/') || value.split('/').some(part => part === '..' || part === '.' || part === '' && value !== '')) throw new HttpError(400, 'The file path must stay inside its approved connector root.');
  return value;
}
export class SambaConnector {
  constructor(registry, token, request = fetch) { this.registry = registry; this.token = token; this.request = request; }
  async perform({ appId, connectionId, operation, relativePath }) {
    safeRelativePath(relativePath);
    if (!['list', 'read'].includes(operation)) throw new HttpError(403, 'This connector permits read-only access.');
    const connection = this.registry.connections?.find(item => item.id === connectionId);
    if (!connection || !['samba', 'filesystem'].includes(connection.type) || connection.reviewStatus !== 'approved' || !connection.appIds?.includes(appId) || !connection.capabilities?.includes(`files.${operation}`) || !Array.isArray(connection.roots) || connection.roots.length !== 1) throw new HttpError(403, 'This app has no approved access to that read-only file capability.');
    const endpoint = new URL(connection.adapterUrl);
    if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new HttpError(503, 'The connector adapter is not configured securely.');
    endpoint.pathname = endpoint.pathname.replace(/\/$/, '') + `/v1/connections/${encodeURIComponent(connectionId)}/${operation}`;
    let response; try { response = await this.request(endpoint, { method: 'POST', redirect: 'error', headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ appId, root: connection.roots[0], path: relativePath }), signal: AbortSignal.timeout(10000) }); } catch { throw new HttpError(503, 'The approved file connector is unavailable.'); }
    if (!response.ok) throw new HttpError(502, 'The file adapter rejected the request.');
    const reader = response.body.getReader(); let size = 0; const chunks = [];
    for (;;) { const chunk = await reader.read(); if (chunk.done) break; size += chunk.value.byteLength; if (size > 24 * 1024 * 1024) { await reader.cancel(); throw new HttpError(413, 'The connector response exceeds the allowed size.'); } chunks.push(Buffer.from(chunk.value)); }
    let body; try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new HttpError(502, 'The file adapter returned invalid data.'); }
    if (operation === 'list') {
      if (!Array.isArray(body.entries) || body.entries.length > 1000 || body.entries.some(item => !item || typeof item.name !== 'string' || item.name.length > 240 || /[\\/\x00-\x1f]/.test(item.name) || !['file', 'directory'].includes(item.kind))) throw new HttpError(502, 'The file listing is invalid.');
      return { entries: body.entries.map(item => ({ name: item.name, kind: item.kind })) };
    }
    if (typeof body.contentBase64 !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(body.contentBase64)) throw new HttpError(502, 'The file content is invalid.');
    return { contentBase64: body.contentBase64, mime: typeof body.mime === 'string' && /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(body.mime) ? body.mime : 'application/octet-stream' };
  }
}
export async function loadConnector(environment) {
  if (!environment.CONNECTOR_REGISTRY_FILE && !environment.CONNECTOR_TOKEN_FILE) return undefined;
  if (!environment.CONNECTOR_REGISTRY_FILE || !environment.CONNECTOR_TOKEN_FILE) throw new Error('Both app-scoped connector registry and token files are required.');
  const registry = JSON.parse(await readFile(environment.CONNECTOR_REGISTRY_FILE, 'utf8')), token = (await readFile(environment.CONNECTOR_TOKEN_FILE, 'utf8')).trim();
  if (registry.schemaVersion !== 1 || !Array.isArray(registry.connections) || !token) throw new Error('Invalid app connector configuration.'); return new SambaConnector(registry, token);
}
