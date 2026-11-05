import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import { isIP } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { publicResearchAddress } from './integration-research.ts';

export type DirectoryHttp = (input: { url: string; method: 'GET' | 'POST'; bearer?: string; form?: URLSearchParams }) => Promise<unknown>;
type Address = { address: string; family: number };
export function directoryUrl(value: string, method: 'GET' | 'POST'): URL {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.port || value.length > 10000 || /[\x00-\x20\x7f]/.test(value)) throw new Error('Invalid fixed directory endpoint.');
  const valid = method === 'POST'
    ? url.origin === 'https://oauth2.googleapis.com' && url.pathname === '/token' && !url.search || url.origin === 'https://login.microsoftonline.com' && /^\/[a-f0-9-]{36}\/oauth2\/v2\.0\/token$/.test(url.pathname) && !url.search
    : url.origin === 'https://graph.microsoft.com' && /^\/v1\.0\/(?:organization|users\/[a-f0-9-]{36}(?:\/transitiveMemberOf)?)$/.test(url.pathname) || url.origin === 'https://admin.googleapis.com' && /^\/admin\/directory\/v1\/(?:customers\/[A-Za-z0-9_-]{1,128}|users\/[0-9]{1,128}|groups(?:\/[A-Za-z0-9_-]{1,128}\/hasMember\/[0-9]{1,128})?)$/.test(url.pathname);
  if (!valid) throw new Error('Directory access is restricted to fixed official read endpoints and OAuth token exchanges.'); return url;
}
export function createDirectoryHttp(options: { resolve?: (host: string) => Promise<Address[]>; transport?: (input: { url: URL; address: Address; method: 'GET' | 'POST'; bearer?: string; form?: URLSearchParams }) => Promise<unknown> } = {}): DirectoryHttp {
  return async input => {
    const url = directoryUrl(input.url, input.method);
    if (input.bearer && (!/^[\x21-\x7e]{1,16384}$/.test(input.bearer)) || input.method === 'GET' && input.form || input.method === 'POST' && (!input.form || input.bearer) || input.form && Buffer.byteLength(input.form.toString()) > 20000) throw new Error('Invalid transient directory credential envelope.');
    let timer: NodeJS.Timeout | undefined;
    const work = async () => {
      const addresses = await (options.resolve ?? (host => lookup(host, { all: true, verbatim: true })))(url.hostname);
      if (!addresses.length || addresses.length > 16 || addresses.some(item => ![4, 6].includes(item.family) || isIP(item.address) !== item.family || !publicResearchAddress(item.address))) throw new Error('Directory DNS is unavailable or contains an unsafe address.');
      const address = addresses.find(item => item.family === 4) ?? addresses[0]!;
      return (options.transport ?? directoryHttps)({ ...input, url, address });
    };
    try { return await Promise.race([work(), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('Directory lookup timed out.')), 10000); })]); }
    catch { throw new Error('The protected directory read is unavailable; no membership permission was granted.'); }
    finally { if (timer) clearTimeout(timer); }
  };
}
function directoryHttps(input: { url: URL; address: Address; method: 'GET' | 'POST'; bearer?: string; form?: URLSearchParams }): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const body = input.form?.toString();
    const req = request(input.url, { method: input.method, agent: false, minVersion: 'TLSv1.2', rejectUnauthorized: true, servername: input.url.hostname, maxHeaderSize: 16384,
      lookup: ((_host: string, _options: unknown, callback: (error: Error | null, address: string, family: number) => void) => callback(null, input.address.address, input.address.family)) as never,
      headers: { accept: 'application/json', 'accept-encoding': 'identity', ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(body ? { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body) } : {}) }, timeout: 9500 }, res => {
      const socketAddress = res.socket.remoteAddress?.replace(/^::ffff:/, '');
      if (socketAddress !== input.address.address || !(res.socket as TLSSocket).authorized || res.statusCode !== 200 || !/^application\/json(?:;|$)/i.test(String(res.headers['content-type'] ?? '')) || res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity') { res.destroy(); reject(new Error('Invalid verified directory response.')); return; }
      const chunks: Buffer[] = []; let size = 0;
      res.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 1024 * 1024) { res.destroy(); reject(new Error('Directory response limit exceeded.')); } else chunks.push(chunk); });
      res.on('end', () => { try { resolve(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); } catch { reject(new Error('Invalid directory JSON.')); } }); res.on('error', reject);
    });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('Directory timeout.'))); req.end(body);
  });
}
