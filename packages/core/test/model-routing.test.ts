import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ModelGateway, type ModelCatalog, type ModelDefinition } from '../src/models.js';

const now = new Date('2026-10-12T15:00:00Z');
const request = { stage: 'review' as const, jobId: 'synthetic-job', system: 's', prompt: 'p', maxOutputTokens: 10 };
const inputBound = Buffer.byteLength('sp{}', 'utf8') + 2048;
const model = (id: string, rate: number, maxInputTokens = 90000): ModelDefinition => ({ id, provider: 'openai', tier: 'strong', inputUsdPerMillion: rate, outputUsdPerMillion: rate, cachedInputUsdPerMillion: rate, cacheWriteUsdPerMillion: rate, effort: 'high', qualified: true, maxInputTokens, maxOutputTokens: 100 });
const small = [model('small-1', 1, 2048), model('small-2', 2, 2048), model('small-3', 3, 2048)];
const receipt = (usage = { input_tokens: 10, output_tokens: 1 }) => ({ service_tier: 'default', usage, output: [{ type: 'message', content: [{ type: 'output_text', text: 'synthetic output' }] }] });
function fixture(models: ModelDefinition[], response: (body: Record<string, unknown>) => Response) {
  const selected: string[] = [], reserved: number[] = [], settled: number[] = [];
  const catalog: ModelCatalog = { schemaVersion: 1, pricesVerifiedAt: now.toISOString(), sources: ['https://developers.openai.com/api/docs/guides/model-selection'], models };
  const gateway = new ModelGateway({ catalog, now: () => now, apiKeys: { openai: 'synthetic-key', anthropic: 'synthetic-key' }, fetch: async (_url, init) => { const body = JSON.parse(String(init?.body)); selected.push(body.model); return response(body); } });
  const run = (input = request) => gateway.complete(input, { reserve: async cost => { reserved.push(cost); return `r-${reserved.length}`; }, settle: async (_id, cost) => { settled.push(cost); } });
  return { run, selected, reserved, settled };
}

test('three cheaper undersized models cannot hide the cheapest qualified model that fits', async () => {
  const f = fixture([...small, model('fits-more-expensive', 5), model('fits-cheapest', 4)], () => Response.json(receipt()));
  assert.equal((await f.run()).model, 'fits-cheapest');
  assert.deepEqual(f.selected, ['fits-cheapest']); assert.equal(f.reserved.length, 1);
});

test('context ineligibility is rejected before any reservation or provider dispatch', async () => {
  const f = fixture([model('big-catalog', 1, 120000)], () => { throw new Error('must not dispatch'); });
  await assert.rejects(f.run({ ...request, prompt: 'a'.repeat(90000) }), /approved context limit/);
  assert.deepEqual(f.selected, []); assert.deepEqual(f.reserved, []); assert.deepEqual(f.settled, []);
});

test('three confirmed refusals consume only eligible fallback attempts and never call a fourth', async () => {
  const f = fixture([...small, ...[4, 5, 6, 7].map(rate => model(`eligible-${rate}`, rate))], () => new Response(null, { status: 429 }));
  await assert.rejects(f.run(), /HTTP 429/);
  assert.deepEqual(f.selected, ['eligible-4', 'eligible-5', 'eligible-6']);
  assert.equal(f.reserved.length, 3); assert.deepEqual(f.settled, [0, 0, 0]);
});

test('OpenAI input usage exceeding this reservation retains its cost and cannot trigger fallback', async () => {
  const f = fixture([model('first', 1), model('next', 2)], () => Response.json(receipt({ input_tokens: inputBound + 1, output_tokens: 1 })));
  await assert.rejects(f.run(), /reservation remains held/);
  assert.deepEqual(f.selected, ['first']); assert.equal(f.reserved.length, 1); assert.deepEqual(f.settled, []);
});

test('Claude total cached and uncached input must fit the actual reservation', async () => {
  const f = fixture([{ ...model('claude', 1), provider: 'anthropic' }], () => Response.json({ usage: { service_tier: 'standard', input_tokens: 1, output_tokens: 1, cache_read_input_tokens: 1, cache_creation_input_tokens: inputBound - 1 }, content: [{ type: 'text', text: 'synthetic output' }] }));
  await assert.rejects(f.run(), /reservation remains held/);
  assert.deepEqual(f.selected, ['claude']); assert.equal(f.reserved.length, 1); assert.deepEqual(f.settled, []);
});

test('exact reserved input boundary is accepted for both provider accounting formats', async () => {
  for (const provider of ['openai', 'anthropic'] as const) {
    const f = fixture([{ ...model(provider, 1), provider }], () => Response.json(provider === 'openai' ? receipt({ input_tokens: inputBound, output_tokens: 1 }) : { usage: { service_tier: 'standard', input_tokens: 1, output_tokens: 1, cache_read_input_tokens: 1, cache_creation_input_tokens: inputBound - 2 }, content: [{ type: 'text', text: 'synthetic output' }] }));
    assert.equal((await f.run()).text, 'synthetic output'); assert.equal(f.settled.length, 1); assert.ok(f.settled[0]! <= f.reserved[0]!);
  }
});

test('context filtering never grants qualification or lowers the required reasoning tier', async () => {
  const f = fixture([{ ...model('unqualified', .1), qualified: false }, { ...model('wrong-tier', .2), tier: 'economy' }, model('qualified-strong', 3)], () => Response.json(receipt()));
  assert.equal((await f.run()).model, 'qualified-strong'); assert.deepEqual(f.selected, ['qualified-strong']);
});
