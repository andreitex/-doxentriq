/** Fixed credential-bearing daily security read; no retry or alternate authority. */
import { readFileSync, statSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const REQUEST_LIMIT = 65536;
export const REPORT_LIMIT = 4194304;
export const TIMEOUT_MS = 300000;
export const FAILURE = 'Trusted daily application check unavailable\n';

export async function requestDailySecurity(Transport, request, token, fetchImpl = globalThis.fetch) {
  try {
    if (typeof request !== 'object' || request === null || Array.isArray(request) ||
        typeof token !== 'string' || token.length === 0 || Buffer.byteLength(token) > 4096 || /[\x00-\x20\x7f]/.test(token)) throw new Error();
    const body = JSON.stringify(request);
    if (Buffer.byteLength(body) > REQUEST_LIMIT) throw new Error();
    const client = new Transport({ url: 'https://broker:8090', token, fetch: fetchImpl });
    const report = await client.post('/v1/security', body, {}, TIMEOUT_MS, REPORT_LIMIT);
    const encoded = JSON.stringify(report);
    if (Buffer.byteLength(encoded) > REPORT_LIMIT) throw new Error();
    return encoded;
  } catch {
    // No external error, refused body, credential or confirmed-rejection flag escapes.
    throw new Error(FAILURE.trimEnd());
  }
}

async function main() {
  try {
    const { TrustedBrokerHttp } = await import('/app/packages/core/src/trusted-broker-http.ts');
    const file = '/run/secrets/broker-token';
    if (!statSync(file).isFile() || statSync(file).size > 4096) throw new Error();
    const token = readFileSync(file, 'utf8').trim();
    const chunks = []; let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > REQUEST_LIMIT) throw new Error();
      chunks.push(chunk);
    }
    const request = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    process.stdout.write(await requestDailySecurity(TrustedBrokerHttp, request, token));
  } catch {
    process.stderr.write(FAILURE);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
