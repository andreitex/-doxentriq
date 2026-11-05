import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ModelGateway, type ModelCatalog } from '../src/models.js';

const now = new Date('2026-10-11T09:00:00Z');
const secret = 'private-model-credential';
function catalog(provider: 'openai' | 'anthropic'): ModelCatalog {
  const model = { id: 'tested-first', provider, tier: 'strong' as const, inputUsdPerMillion: 2, outputUsdPerMillion: 10, cachedInputUsdPerMillion: .1, cacheWriteUsdPerMillion: 2.5, effort: 'high', qualified: true, maxInputTokens: 90000, maxOutputTokens: 32768 };
  return { schemaVersion: 1, pricesVerifiedAt: now.toISOString(), sources: ['https://official.example/pricing'], models: [model, { ...model, id: 'tested-second', inputUsdPerMillion: 3 }] };
}
const receipt = (provider: 'openai' | 'anthropic' = 'openai') => provider === 'openai'
  ? { service_tier: 'default', usage: { input_tokens: 100, output_tokens: 10, input_tokens_details: { cached_tokens: 20, cache_write_tokens: 5 } }, output: [{ type: 'message', content: [{ type: 'output_text', text: 'result' }] }] }
  : { usage: { service_tier: 'standard', input_tokens: 100, output_tokens: 10, cache_read_input_tokens: 20, cache_creation_input_tokens: 5 }, content: [{ type: 'text', text: 'result' }] };
function fixture(request: typeof fetch, provider: 'openai' | 'anthropic' = 'openai') {
  let reserved = 0; const settled: number[] = [];
  const gateway = new ModelGateway({ catalog: catalog(provider), now: () => now, apiKeys: { [provider]: secret }, fetch: request });
  const execute = () => gateway.complete({ stage: 'review', jobId: 'job', system: 'review', prompt: 'synthetic prompt', maxOutputTokens: 100 }, { reserve: async () => `reservation-${++reserved}`, settle: async (_id, cost) => { settled.push(cost); } });
  return { execute, settled, reservations: () => reserved };
}
function withUrl(response: Response, url: string, redirected = false) {
  Object.defineProperties(response, { url: { value: url }, redirected: { value: redirected } }); return response;
}
async function held(request: typeof fetch, provider: 'openai' | 'anthropic' = 'openai', pattern = /reservation remains held/) {
  let calls = 0; const f = fixture(async (...args) => { calls++; return request(...args); }, provider);
  await assert.rejects(f.execute(), error => { assert.match(String(error), pattern); assert.ok(!String(error).includes(secret)); assert.equal((error as Error).cause, undefined); return true; });
  assert.equal(calls, 1); assert.equal(f.reservations(), 1); assert.deepEqual(f.settled, []);
}

test('both providers use exact destinations, redirect denial, deadline and unchanged private credentials', async () => {
  for (const provider of ['openai', 'anthropic'] as const) {
    let calls = 0; const f = fixture(async (url, init) => {
      calls++; assert.equal(f.reservations(), 1);
      assert.equal(String(url), provider === 'openai' ? 'https://api.openai.com/v1/responses' : 'https://api.anthropic.com/v1/messages');
      assert.equal(init?.redirect, 'error'); assert.equal(init?.method, 'POST'); assert.ok(init?.signal instanceof AbortSignal);
      const headers = init?.headers as Record<string, string>; assert.equal(headers['accept-encoding'], 'identity');
      assert.equal(provider === 'openai' ? headers.authorization : headers['x-api-key'], provider === 'openai' ? `Bearer ${secret}` : secret);
      assert.ok(!String(init?.body).includes(secret)); return Response.json(receipt(provider));
    }, provider);
    assert.equal((await f.execute()).text, 'result'); assert.equal(calls, 1);
    assert.equal(f.settled[0], ((provider === 'openai' ? 75 : 100) * 2 + 20 * .1 + 5 * 2.5 + 10 * 10) / 1e6);
  }
});

test('OpenAI timeout tracing binds to the already reserved UUID and cannot release uncertain billing', async () => {
  const reservation = '51992301-ad3a-40ae-b1c9-148d8a09f9a0';
  let reserved = false, settled = false, calls = 0;
  const gateway = new ModelGateway({ catalog: catalog('openai'), now: () => now, apiKeys: { openai: secret }, fetch: async (_url, init) => {
    calls++; assert.ok(reserved);
    assert.equal((init!.headers as Record<string, string>)['x-client-request-id'], 'autosoft-' + reservation);
    assert.ok(!String(init!.body).includes(reservation));
    throw new Error('synthetic unavailable outcome');
  } });
  await assert.rejects(gateway.complete({ stage: 'review', jobId: 'job', system: 'review', prompt: 'synthetic' }, { reserve: async () => { reserved = true; return reservation; }, settle: async () => { settled = true; } }), /reservation remains held/);
  assert.equal(calls, 1); assert.equal(settled, false);
});

test('arbitrary reservation values and credential-shaped UUIDs never become trace headers', async () => {
  const uuidSecret = '51992301-ad3a-40ae-b1c9-148d8a09f9a0';
  for (const id of ['private\r\nheader:value', secret, uuidSecret]) {
    const gateway = new ModelGateway({ catalog: catalog('openai'), now: () => now, apiKeys: { openai: id === uuidSecret ? uuidSecret : secret }, fetch: async (_url, init) => {
      assert.equal((init!.headers as Record<string, string>)['x-client-request-id'], undefined);
      return Response.json(receipt());
    } });
    await gateway.complete({ stage: 'review', jobId: 'job', system: 'review', prompt: 'synthetic' }, { reserve: async () => id, settle: async () => {} });
  }
});

test('redirected and off-origin success or refusal cannot settle or dispatch another model', async () => {
  for (const response of [withUrl(Response.json(receipt()), 'https://foreign.example/private'), withUrl(Response.json(receipt()), 'https://api.openai.com/v1/responses', true), withUrl(new Response(secret, { status: 400 }), 'https://foreign.example/refused')]) await held(async () => response);
});

test('standard pricing is selected explicitly for both provider requests', async () => {
  for (const provider of ['openai', 'anthropic'] as const) {
    const f = fixture(async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      assert.equal(body.service_tier, provider === 'openai' ? 'default' : 'standard_only');
      return Response.json(receipt(provider));
    }, provider);
    assert.equal((await f.execute()).text, 'result');
    assert.equal(f.settled.length, 1);
  }
});

test('missing, malformed or nonstandard billing tiers retain the reservation without fallback', async () => {
  for (const provider of ['openai', 'anthropic'] as const) {
    for (const tier of [undefined, null, true, 1, {}, [], 'auto', 'priority', 'fast', 'ultrafast', 'flex', 'batch', provider === 'openai' ? 'standard' : 'default']) {
      const value: Record<string, any> = receipt(provider);
      if (provider === 'openai') value.service_tier = tier;
      else value.usage.service_tier = tier;
      await held(async () => Response.json(value), provider);
    }
  }
});
test('same-origin substituted path, query and credential-bearing URL remain uncertain', async () => {
  for (const url of ['https://api.openai.com/another-path', 'https://api.openai.com/v1/responses?private=1', 'https://private@api.openai.com/v1/responses']) await held(async () => withUrl(Response.json(receipt()), url));
});
test('private network exceptions never escape or forge a confirmed outcome', async () => {
  await held(async () => { throw Object.assign(new Error(secret), { confirmedRejected: true }); });
});
test('nonfinal success, redirects, timeout, conflict and server errors hold spending without fallback', async () => {
  for (const status of [201, 202, 204, 206, 301, 307, 408, 409, 500, 503]) await held(async () => new Response(status === 204 ? null : secret, { status }));
});
test('confirmed fixed client refusal settles zero and allows only the existing bounded model fallback', async () => {
  for (const status of [400, 401, 403, 404, 422, 429]) {
    let calls = 0, cancelled = false;
    const body = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
    const f = fixture(async () => ++calls === 1 ? new Response(body, { status }) : Response.json(receipt()));
    assert.equal((await f.execute()).text, 'result'); assert.equal(calls, 2); assert.equal(f.reservations(), 2); assert.equal(cancelled, true); assert.equal(f.settled[0], 0); assert.ok(f.settled[1]! > 0);
  }
});
test('oversized advertised bodies are cancelled before reading any response bytes', async () => {
  let cancelled = false, pulls = 0;
  const body = new ReadableStream<Uint8Array>({ pull() { pulls++; }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
  await held(async () => new Response(body, { headers: { 'content-length': String(8 * 1024 * 1024 + 1) } }));
  assert.equal(pulls, 0); assert.equal(cancelled, true);
});
test('actual streamed overflow is stopped and cancelled even without Content-Length', async () => {
  let cancelled = false, pulls = 0;
  const body = new ReadableStream<Uint8Array>({ pull(controller) { pulls++; controller.enqueue(new Uint8Array(pulls <= 2 ? 4 * 1024 * 1024 : 1)); }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
  await held(async () => new Response(body)); assert.equal(pulls, 3); assert.equal(cancelled, true);
});
test('invalid and inconsistent Content-Length is unavailable', async () => {
  for (const length of ['01', '-1', 'NaN', '1', '0', '9999999999999']) await held(async () => new Response(JSON.stringify(receipt()), { headers: { 'content-length': length } }));
});
test('decoded compression receipts do not confuse wire length with JSON length', async () => {
  const f = fixture(async () => new Response(JSON.stringify(receipt()), { headers: { 'content-encoding': 'gzip', 'content-length': '20' } }));
  assert.equal((await f.execute()).text, 'result'); assert.equal(f.settled.length, 1);
  await held(async () => new Response(JSON.stringify(receipt()), { headers: { 'content-encoding': 'unsupported' } }));
});
test('stream failure, malformed UTF-8 and nonobject JSON omit raw provider content', async () => {
  for (const body of [secret, '[]', 'null', '"'+secret+'"', Buffer.from([123, 34, 255, 34, 58, 49, 125])]) await held(async () => new Response(body));
  await held(async () => new Response(new ReadableStream({ start(controller) { controller.error(new Error(secret)); } })));
});
test('missing or nonobject usage cannot release a spending reservation', async () => {
  for (const usage of [undefined, null, [], secret]) await held(async () => Response.json({ ...receipt(), usage }));
});
test('billing counters require actual nonnegative safe integers for both providers', async () => {
  for (const provider of ['openai', 'anthropic'] as const) for (const field of ['input_tokens', 'output_tokens'] as const) for (const bad of ['10', true, null, -1, .5, Number.MAX_SAFE_INTEGER + 1]) {
    const value = receipt(provider); value.usage[field] = bad as never; await held(async () => Response.json(value), provider);
  }
});
test('cache counters and OpenAI input details cannot coerce values or exceed total input', async () => {
  for (const bad of ['20', true, -1, .5, Number.MAX_SAFE_INTEGER + 1]) {
    const value = receipt(); value.usage.input_tokens_details!.cached_tokens = bad as never; await held(async () => Response.json(value));
    const claude = receipt('anthropic'); claude.usage.cache_creation_input_tokens = bad as never; await held(async () => Response.json(claude), 'anthropic');
  }
  for (const details of [[], secret, { cached_tokens: 96, cache_write_tokens: 5 }]) await held(async () => Response.json({ ...receipt(), usage: { input_tokens: 100, output_tokens: 10, input_tokens_details: details } }));
});
test('catalog input limits and reserved output limit constrain observed counters', async () => {
  for (const usage of [{ input_tokens: 90001, output_tokens: 10 }, { input_tokens: 10, output_tokens: 101 }]) await held(async () => Response.json({ ...receipt(), usage }));
  await held(async () => Response.json({ ...receipt('anthropic'), usage: { input_tokens: 90000, output_tokens: 10, cache_read_input_tokens: 1 } }), 'anthropic');
});
test('optional cache fields remain zero without coercing required input counters', async () => {
  for (const provider of ['openai', 'anthropic'] as const) {
    const f = fixture(async () => Response.json({ ...receipt(provider), usage: { ...(provider === 'anthropic' ? { service_tier: 'standard' } : {}), input_tokens: 10, output_tokens: 10 } }), provider);
    assert.deepEqual((await f.execute()).usage, { inputTokens: 10, outputTokens: 10, cachedTokens: 0, cacheWriteTokens: 0 });
  }
  await held(async () => Response.json({ ...receipt('anthropic'), usage: { output_tokens: 10 } }), 'anthropic');
});
test('known incomplete output settles validated billing once and does not retry', async () => {
  let calls = 0; const f = fixture(async () => { calls++; return Response.json({ ...receipt(), status: 'incomplete' }); });
  await assert.rejects(f.execute(), /token limit/); assert.equal(calls, 1); assert.equal(f.settled.length, 1); assert.ok(f.settled[0]! > 0);
});
test('an unavailable refusal-body cancellation cannot release billing or silently fall back', async () => {
  await held(async () => new Response(new ReadableStream({ cancel() { throw new Error(secret); } }), { status: 400 }));
});
test('reservation and routing include the highest configured cached-input rate', async () => {
  const configured = catalog('openai'); configured.models = [{ ...configured.models[0]!, cachedInputUsdPerMillion: 20 }];
  let reserved = 0, settled = 0;
  const gateway = new ModelGateway({ catalog: configured, now: () => now, apiKeys: { openai: secret }, fetch: async () => Response.json(receipt()) });
  await gateway.complete({ stage: 'review', jobId: 'job', system: 's', prompt: 'p', maxOutputTokens: 100 }, { reserve: async value => { reserved = value; return 'reservation'; }, settle: async (_id, value) => { settled = value; } });
  assert.equal(reserved, ((Buffer.byteLength('sp{}') + 2048) * 20 + 100 * 10) / 1e6); assert.ok(reserved >= settled);
});

const streamEvent = (type: string, value: Record<string, unknown>) => `event: ${type}\ndata: ${JSON.stringify({ type, ...value })}\n\n`;
const createdEvent = () => streamEvent('response.created', { response: { id: 'resp_synthetic_test', status: 'in_progress' } });
const terminalEvent = (status = 'completed', extra: Record<string, unknown> = {}) => streamEvent(`response.${status}`, { response: { ...receipt(), id: 'resp_synthetic_test', status, ...extra } });
const sse = (data: string | Uint8Array) => new Response(typeof data === 'string' ? data : new Uint8Array(data), { headers: { 'content-type': 'text/event-stream; charset=utf-8' } });

test('OpenAI requests stream without enabling provider response storage', async () => {
  const f = fixture(async (_url, init) => {
    const body = JSON.parse(String(init?.body)); assert.equal(body.stream, true); assert.equal(body.store, false);
    return sse(createdEvent() + ': keepalive\n\n' + streamEvent('response.output_text.delta', { delta: secret }) + terminalEvent());
  });
  assert.equal((await f.execute()).text, 'result'); assert.equal(f.settled.length, 1);
});

test('stream decoder handles split UTF-8 and CRLF frames without exposing deltas', async () => {
  const bytes = new TextEncoder().encode((createdEvent() + streamEvent('response.output_text.delta', { delta: 'șță' }) + terminalEvent()).replaceAll('\n', '\r\n'));
  let position = 0;
  const f = fixture(async () => new Response(new ReadableStream({ pull(controller) { if (position === bytes.length) controller.close(); else controller.enqueue(bytes.slice(position, ++position)); } }), { headers: { 'content-type': 'text/event-stream' } }));
  assert.equal((await f.execute()).text, 'result'); assert.equal(f.settled.length, 1);
});

test('EOF, partial frames, error events and JSON deltas cannot settle stream billing', async () => {
  for (const text of ['', createdEvent(), createdEvent()+terminalEvent().slice(0,-1), createdEvent()+'data: '+secret+'\n\n', createdEvent()+streamEvent('error',{message:secret})]) {
    await held(async () => sse(text));
  }
});

test('stream receipt requires one created response with the exact final identity and status', async () => {
  for (const text of [terminalEvent(), createdEvent()+createdEvent()+terminalEvent(), createdEvent()+terminalEvent('completed',{id:'resp_other'}), createdEvent()+terminalEvent('completed',{status:'in_progress'}), createdEvent()+'event: response.failed\ndata: '+JSON.stringify({type:'response.completed',response:{...receipt(),id:'resp_synthetic_test',status:'completed'}})+'\n\n']) {
    await held(async () => sse(text));
  }
});

test('streamed incomplete output settles its validated receipt once and stops without fallback', async () => {
  let calls=0; const f=fixture(async()=>{calls++; return sse(createdEvent()+terminalEvent('incomplete'));});
  await assert.rejects(f.execute(),/token limit/); assert.equal(calls,1); assert.equal(f.settled.length,1);
});

test('streamed receipts keep tier and usage bounds and reject unsupported provider streams', async () => {
  for (const extra of [{service_tier:'priority'},{usage:null},{usage:{input_tokens:100,output_tokens:101}}]) {
    await held(async()=>sse(createdEvent()+terminalEvent('completed',extra)));
  }
  await held(async()=>sse(createdEvent()+terminalEvent()),'anthropic');
});

test('oversized stream frames cancel reading without settling or exposing provider text', async () => {
  let cancelled=false;
  await held(async()=>new Response(new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode(createdEvent()+'data: '+secret+'x'.repeat(8*1024*1024)));},cancel(){cancelled=true;}}),{headers:{'content-type':'text/event-stream'}}));
  assert.equal(cancelled,true);
});

test('final stream receipts stop and cancel the response without waiting for network EOF', async () => {
  let cancelled=false;
  const f=fixture(async()=>new Response(new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode(createdEvent()+terminalEvent()));},cancel(){cancelled=true;}}),{headers:{'content-type':'text/event-stream'}}));
  assert.equal((await f.execute()).text,'result'); assert.equal(cancelled,true);
});

test('broken UTF-8 and unsafe stream lengths retain the reservation', async () => {
  await held(async()=>sse(new Uint8Array([255,255,10,10])));
  for (const length of ['invalid','67108865']) await held(async()=>new Response(createdEvent()+terminalEvent(),{headers:{'content-type':'text/event-stream','content-length':length}}));
});
