/** Credential-bearing requests to the company runtime. Unknown outcomes never retry here. */
export class TrustedBrokerHttp {
  private readonly origin: string;
  constructor(private readonly config: { url: string; token: string; fetch?: typeof fetch }) {
    let url: URL;
    try { url = new URL(config.url); } catch { throw new Error('An exact trusted HTTPS broker origin or loopback development is required.'); }
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
        url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)))
      throw new Error('An exact trusted HTTPS broker origin or loopback development is required.');
    this.origin = url.origin;
  }

  async post<T>(route: string, body: string, proof: Record<string, string>, timeout: number, maximum: number): Promise<T> {
    let response: Response;
    try {
      const target = new URL(route, this.origin);
      if (target.origin !== this.origin) throw new Error();
      response = await (this.config.fetch ?? fetch)(target, { method: 'POST', redirect: 'error',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${this.config.token}`, ...proof },
        body, signal: AbortSignal.timeout(timeout) });
    } catch { throw uncertain(); }
    let value: Record<string, unknown>;
    try {
      if (response.redirected || response.url && new URL(response.url).origin !== this.origin) throw new Error();
      value = await readReceipt(response, response.status === 200 ? maximum : 65536);
    } catch {
      await response.body?.cancel().catch(() => {});
      throw uncertain();
    }
    if (response.status !== 200)
      throw Object.assign(new Error(`Trusted broker operation is unavailable or rejected (HTTP ${response.status}); inspect its retained operation without repeating dispatch.`),
        { confirmedRejected: !response.ok && value.rejectedBeforeExecution === true });
    return value as T;
  }
}

function uncertain(): Error & { confirmedRejected: false } {
  return Object.assign(new Error('Trusted broker receipt is unavailable, malformed or exceeds its bounded byte limit; retain the operation for reconciliation.'), { confirmedRejected: false as const });
}

async function readReceipt(response: Response, maximum: number): Promise<Record<string, unknown>> {
  const length = response.headers.get('content-length');
  if (!response.body || length !== null && (!/^(?:0|[1-9][0-9]{0,11})$/.test(length) || Number(length) > maximum)) throw new Error();
  const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const part = await reader.read(); if (part.done) break;
      size += part.value.byteLength;
      if (size > maximum) throw new Error();
      chunks.push(part.value);
    }
    if (length !== null && size !== Number(length)) throw new Error();
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch {
    await reader.cancel().catch(() => {});
    throw new Error();
  } finally { reader.releaseLock(); }
}
