/** Fixed provider destinations; unknown transport outcomes retain their billing reservation. */
export async function postModelRequest(provider: 'openai' | 'anthropic', headers: Record<string, string>, body: string, request: typeof fetch): Promise<{ status: number; body: Record<string, any> | null }> {
  const endpoint = provider === 'openai' ? 'https://api.openai.com/v1/responses' : 'https://api.anthropic.com/v1/messages';
  let response: Response | undefined;
  try {
    response = await request(endpoint, { method: 'POST', redirect: 'error', headers: { ...headers, 'accept-encoding': 'identity' }, body, signal: AbortSignal.timeout(provider === 'openai' ? 900000 : 300000) });
    if (response.redirected || response.url && new URL(response.url).href !== endpoint) throw new Error();
    if (response.status !== 200) {
      await response.body?.cancel();
      return { status: response.status, body: null };
    }
    const streaming = response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() === 'text/event-stream';
    if (streaming && provider !== 'openai') throw new Error();
    return { status: 200, body: streaming ? await readOpenAiStream(response) : await readModelReceipt(response) };
  } catch {
    await response?.body?.cancel().catch(() => {});
    throw new Error('Model connection ended without a confirmed billing outcome; the reservation remains held for reconciliation');
  }
}

/** Only a final, identity-bound response carries a billing receipt. Deltas and
 * provider error text are never published, executed or mistaken for success. */
async function readOpenAiStream(response: Response): Promise<Record<string, any>> {
  const maximumEvent = 8 * 1024 * 1024, maximumStream = 64 * 1024 * 1024;
  const length = response.headers.get('content-length'), encoding = response.headers.get('content-encoding');
  if (!response.body || length !== null && (!/^(?:0|[1-9][0-9]{0,11})$/.test(length) || Number(length) > maximumStream) ||
      encoding !== null && !['identity', 'gzip', 'br', 'deflate'].includes(encoding)) throw new Error();
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true });
  let buffer = '', data: string[] = [], eventName = '', eventSize = 0, size = 0, events = 0, responseId: string | undefined;
  const dispatch = (): Record<string, any> | undefined => {
    if (!data.length) { eventName = ''; eventSize = 0; return; }
    if (++events > 100000) throw new Error();
    const value: unknown = JSON.parse(data.join('\n'));
    data = []; eventSize = 0;
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    const event = value as Record<string, any>;
    if (typeof event.type !== 'string' || eventName && eventName !== event.type) throw new Error();
    eventName = '';
    if (event.type === 'error') throw new Error();
    if (event.type === 'response.created') {
      if (responseId || !event.response || typeof event.response.id !== 'string' || !/^resp_[A-Za-z0-9_-]{1,200}$/.test(event.response.id)) throw new Error();
      responseId = event.response.id;
    }
    if (['response.completed', 'response.incomplete', 'response.failed'].includes(event.type)) {
      const final = event.response;
      if (!responseId || !final || typeof final !== 'object' || Array.isArray(final) || final.id !== responseId ||
          final.status !== event.type.slice('response.'.length)) throw new Error();
      return final;
    }
  };
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) throw new Error(); // EOF is not a completion or a zero-cost receipt.
      size += part.value.byteLength;
      if (size > maximumStream) throw new Error();
      buffer += decoder.decode(part.value, { stream: true });
      let end: number;
      while ((end = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, end).replace(/\r$/, ''); buffer = buffer.slice(end + 1);
        if (line.length > maximumEvent) throw new Error();
        if (!line) {
          const final = dispatch();
          if (final) { await reader.cancel(); return final; }
        } else if (!line.startsWith(':')) {
          const colon = line.indexOf(':'), field = colon < 0 ? line : line.slice(0, colon);
          let value = colon < 0 ? '' : line.slice(colon + 1); if (value.startsWith(' ')) value = value.slice(1);
          if (field === 'data') { eventSize += value.length; if (eventSize > maximumEvent) throw new Error(); data.push(value); }
          else if (field === 'event') eventName = value;
        }
      }
      if (buffer.length > maximumEvent) throw new Error();
    }
  } catch {
    await reader.cancel().catch(() => {}); throw new Error();
  } finally { reader.releaseLock(); }
}

async function readModelReceipt(response: Response): Promise<Record<string, any>> {
  const maximum = 8 * 1024 * 1024, length = response.headers.get('content-length');
  const encoding = response.headers.get('content-encoding');
  if (!response.body || length !== null && (!/^(?:0|[1-9][0-9]{0,11})$/.test(length) || Number(length) > maximum) ||
      encoding !== null && !['identity', 'gzip', 'br', 'deflate'].includes(encoding)) throw new Error();
  const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const part = await reader.read(); if (part.done) break;
      size += part.value.byteLength; if (size > maximum) throw new Error();
      chunks.push(part.value);
    }
    // Fetch returns decoded bytes; a compressed Content-Length describes wire bytes.
    if ((encoding === null || encoding === 'identity') && length !== null && size !== Number(length)) throw new Error();
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value as Record<string, any>;
  } catch {
    await reader.cancel().catch(() => {}); throw new Error();
  } finally { reader.releaseLock(); }
}

export function modelUsage(body: Record<string, any>, provider: 'openai' | 'anthropic', inputLimit: number, outputLimit: number) {
  const u: unknown = body.usage;
  const invalid = () => new Error('Provider billing metadata is unavailable; reservation remains held');
  if (!u || typeof u !== 'object' || Array.isArray(u)) throw invalid();
  const usage = u as Record<string, unknown>;
  // The confirmed processing tier, not the requested tier, determines billing eligibility.
  if (provider === 'openai' ? body.service_tier !== 'default' : usage.service_tier !== 'standard') throw invalid();
  const counter = (value: unknown, optional = false): number => {
    if (optional && (value === undefined || value === null)) return 0;
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw invalid();
    return value;
  };
  const details = usage.input_tokens_details;
  if (provider === 'openai' && details !== undefined && details !== null && (typeof details !== 'object' || Array.isArray(details))) throw invalid();
  const d = (details ?? {}) as Record<string, unknown>;
  const result = { inputTokens: counter(usage.input_tokens), outputTokens: counter(usage.output_tokens),
    cachedTokens: counter(provider === 'openai' ? d.cached_tokens : usage.cache_read_input_tokens, true),
    cacheWriteTokens: counter(provider === 'openai' ? d.cache_write_tokens : usage.cache_creation_input_tokens, true) };
  const inputTotal = provider === 'openai' ? result.inputTokens : result.inputTokens + result.cachedTokens + result.cacheWriteTokens;
  if (!Number.isSafeInteger(inputTotal) || inputTotal > inputLimit || result.outputTokens > outputLimit ||
      provider === 'openai' && result.cachedTokens + result.cacheWriteTokens > result.inputTokens) throw invalid();
  return result;
}
