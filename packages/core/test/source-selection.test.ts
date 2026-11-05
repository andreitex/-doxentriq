import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { selectPreviousSource, selectedPreviousFiles, validatedPreviousSourceSelection, previousSourceInventory, unreviewedExistingChanges, unreviewedExistingArtifactChanges, type SourceSelectionInput } from '../src/source-selection.ts';
import { createGenerationService, ModelGateway, type ModelCatalog } from '../src/models.ts';
import { stages, type Generation } from '../src/schemas.ts';
import type { AppRecord, JobRecord } from '../src/types.ts';

const input = (changes: Partial<SourceSelectionInput> = {}): SourceSelectionInput => ({ appId: 'source-app', jobId: 'source-job', attempt: 0, baseReleaseId: 'release-one', request: 'Change the upload form in web/main.jsx', files: [
  { path: 'server.mjs', content: 'server authorization health '.repeat(900) },
  { path: 'src/auth.mjs', content: 'authorization permissions '.repeat(900) },
  { path: 'web/main.jsx', content: '<form>upload department metadata</form>'.repeat(300) },
  { path: 'package-lock.json', content: '{"lockfileVersion":3}' }
], ...changes });

test('explicit frontend target precedes generic authorization/server context without exceeding 48000 bytes', () => {
  const f = input(), record = selectPreviousSource(f);
  assert.equal(record.selected[0]?.path, 'web/main.jsx'); assert.equal(record.selected[0]?.reason, 'requested');
  assert.equal(selectedPreviousFiles(record, f)[0]?.content, f.files![2]!.content);
  assert.ok(record.selectedBytes <= 48000); assert.ok(record.truncated); assert.equal(record.questions.length, 0);
  assert.equal(record.omitted.find(file => file.path === 'package-lock.json')?.reason, 'excluded');
});
test('business request and acceptance criteria identify the upload page without a technical filename', () => {
  const record = selectPreviousSource(input({ request: 'Add project metadata next to Department on the upload form', acceptanceCriteria: ['Upload department metadata remains searchable'] }));
  assert.ok(record.selected.some(file => file.path === 'web/main.jsx' && file.reason === 'relevant')); assert.equal(record.questions.length, 0);
});
test('acceptance criteria can request an exact existing target before generic files', () => {
  const record = selectPreviousSource(input({ request: 'Change the document form', acceptanceCriteria: ['The upload form in web/main.jsx has a Project code field'] }));
  assert.equal(record.selected[0]?.path, 'web/main.jsx'); assert.deepEqual(record.requestedPaths, ['web/main.jsx']);
});

test('preserving named lockfiles is a constraint, never an editable source request', () => {
  const f = input({ acceptanceCriteria: ['Keep package-lock.json unchanged.', 'All other inventory files remain byte-identical, including src/*.mjs, server.mjs, package-lock.json, and existing test files.'] });
  const record = selectPreviousSource(f);
  assert.equal(record.questions.length, 0);
  assert.deepEqual(record.requestedPaths, ['web/main.jsx']);
  assert.equal(record.omitted.find(file => file.path === 'package-lock.json')?.reason, 'excluded');
  assert.ok(!record.selected.some(file => file.path === 'package-lock.json'));
  assert.deepEqual(unreviewedExistingArtifactChanges(f.files!.map(file => file.path === 'package-lock.json' ? { ...file, content: 'changed lock' } : file), f.files!, record), ['package-lock.json']);
  assert.deepEqual(unreviewedExistingArtifactChanges(f.files!.filter(file => file.path !== 'package-lock.json'), f.files!, record), ['package-lock.json']);
});

test('real DMS acceptance names the UI target while explicitly excluding package and lock changes', () => {
  const record = selectPreviousSource(input({ acceptanceCriteria: ['Only web/main.jsx is modified, plus at most one new narrowly scoped project-code UI test file that uses synthetic data and requires no new dependency or package.json/package-lock.json change.'] }));
  assert.equal(record.questions.length, 0);
  assert.deepEqual(record.requestedPaths, ['web/main.jsx']);
});

test('actual and mixed dependency-lock rewrite requests still pause before provider work', () => {
  for (const request of ['Rewrite package-lock.json', 'Regenerate package-lock.json', 'Keep package-lock.json unchanged but update it', 'Keep package-lock.json unchanged and regenerate it', 'The test requires no new dependencies but rewrite package-lock.json', 'The test requires no package changes and replace package-lock.json', 'The test requires no dependency change, rewrite package-lock.json', 'The test requires no dependencies then overwrite package-lock.json']) {
    const record = selectPreviousSource(input({ request }));
    assert.ok(record.questions.length > 0, request);
    assert.ok(!record.selected.some(file => file.path === 'package-lock.json'), request);
  }
});
test('relative import neighborhood stays within the supplied application snapshot and never executes content', () => {
  const f = input({ files: [{ path: 'web/main.jsx', content: "import {helper} from './helper.js'; import '../../outside.js'; upload metadata department" }, { path: 'web/helper.ts', content: 'export const helper = 1;' }] });
  const record = selectPreviousSource(f); assert.ok(record.selected.some(file => file.path === 'web/helper.ts' && file.reason === 'neighbor'));
  assert.ok(!record.selected.some(file => file.path.includes('outside')));
});
test('whole requested file at the byte ceiling is admitted and one byte above pauses without partial content', () => {
  for (const bytes of [48000, 48001]) {
    const f = input({ files: [{ path: 'web/main.jsx', content: 'x'.repeat(bytes) }] }), record = selectPreviousSource(f);
    assert.equal(record.selectedBytes, bytes === 48000 ? bytes : 0);
    assert.equal(record.questions.length > 0, bytes === 48001);
    if (bytes === 48001) { assert.equal(record.omitted[0]?.reason, 'requested_over_limit'); assert.deepEqual(selectedPreviousFiles(record, f), []); }
  }
});
test('multiple explicit targets are never silently replaced by generic files when their combined size is too large', () => {
  const record = selectPreviousSource(input({ request: 'Update web/main.jsx and web/style.css', files: [{ path: 'web/main.jsx', content: 'x'.repeat(30000) }, { path: 'web/style.css', content: 'y'.repeat(30000) }, { path: 'server.mjs', content: 'z'.repeat(1000) }] }));
  assert.equal(record.questions.length, 1); assert.ok(record.omitted.some(file => file.reason === 'requested_over_limit')); assert.deepEqual(record.requestedPaths, ['web/main.jsx', 'web/style.css']);
});
test('selection accounts for UTF8 bytes and stays deterministic across snapshot enumeration order', () => {
  const f = input({ files: [{ path: 'web/main.jsx', content: 'é'.repeat(24001) }, { path: 'server.mjs', content: 'health' }] }), first = selectPreviousSource(f), second = selectPreviousSource({ ...f, files: [...f.files!].reverse() });
  assert.equal(first.omitted.find(file => file.path === 'web/main.jsx')?.bytes, 48002); assert.deepEqual(first, second);
});
test('traversal, absolute host paths, hidden infrastructure and case-folded duplicate source cannot enter selection', () => {
  for (const path of ['../foreign/server.mjs', '/etc/config.json', 'C:\\host\\file.ts', 'web/.env.secret', '.git/config']) assert.throws(() => selectPreviousSource(input({ files: [{ path, content: 'x' }] })), /invalid/);
  assert.throws(() => selectPreviousSource(input({ files: [{ path: 'web/main.jsx', content: 'one' }, { path: 'WEB/main.jsx', content: 'two' }] })), /duplicate/);
  assert.ok(selectPreviousSource(input({ request: 'Change ../foreign/server.mjs' })).questions.length);
});
test('copied, stale, altered and extra-field selection evidence cannot authorize another application or starting release', () => {
  const f = input(), record = selectPreviousSource(f);
  for (const change of [{ appId: 'other-app' }, { jobId: 'other-job' }, { baseReleaseId: 'release-two' }, { request: 'different request' }, { attempt: 1 }]) assert.throws(() => validatedPreviousSourceSelection(record, { ...f, ...change }));
  assert.throws(() => validatedPreviousSourceSelection({ ...record, selectedBytes: 1 }, f));
  assert.throws(() => validatedPreviousSourceSelection({ ...record, executionAuthorized: true }, f));
});
test('missing and ambiguous named targets clarify, while an explicitly requested new file may be created', () => {
  assert.ok(selectPreviousSource(input({ request: 'Change missing.jsx' })).questions.length);
  assert.ok(selectPreviousSource(input({ request: 'Change main.jsx', files: [{ path: 'one/main.jsx', content: 'x' }, { path: 'two/main.jsx', content: 'x' }] })).questions.length);
  assert.equal(selectPreviousSource(input({ request: 'Change missing.jsx', answer: 'This is a new file for a new business page.', files: [{ path: 'server.mjs', content: 'health' }] })).questions.length, 0);
});
test('requirements inventory is bounded while persisted evidence retains every selected and omitted hash', () => {
  const files = Array.from({ length: 500 }, (_, i) => ({ path: `features/${String(i).padStart(3, '0')}-${'x'.repeat(180)}.tsx`, content: 'x' }));
  const record = selectPreviousSource(input({ request: 'Create a new feature', files })), inventory = previousSourceInventory(record);
  assert.equal(record.selected.length + record.omitted.length, 500); assert.ok(inventory.files.length < 500); assert.equal(inventory.omittedCount, 500 - inventory.files.length);
  assert.ok(inventory.files.reduce((sum, row) => sum + Buffer.byteLength(JSON.stringify(row)), 0) <= 12000);
});
test('omitted existing source may only be re-emitted identically; new scoped source is independent', () => {
  const f = input(), record = selectPreviousSource(f), omitted = record.omitted.find(file => file.reason === 'limit')!;
  const old = f.files!.find(file => file.path === omitted.path)!;
  assert.deepEqual(unreviewedExistingChanges([old, { path: 'web/new.jsx', content: 'new page' }], f.files!, record), []);
  assert.deepEqual(unreviewedExistingChanges([{ ...old, content: 'replacement' }], f.files!, record), [old.path]);
});

const now = new Date().toISOString();
const app: AppRecord = { id: 'source-app', slug: 'source-app', name: 'Documents', description: 'Keep document versions', kind: 'web', status: 'published', activeReleaseId: 'release-one', createdAt: now, updatedAt: now, url: null, previewUrl: null };
const job: JobRecord = { id: 'source-job', appId: app.id, request: input().request, stage: 'specification', baseReleaseId: app.activeReleaseId, costUsd: 0, budgetUsd: 10, attempts: 0, createdAt: now, updatedAt: now };
const plan = { title: 'Project code', summary: 'Add upload metadata', acceptanceCriteria: ['The upload form in web/main.jsx has optional Project code metadata'], questions: [] };
const generated = (files: { path: string; content: string }[]): Generation => ({ specification: plan, summary: 'Update the upload form', manifest: { schemaVersion: 1, id: app.id, slug: app.slug, name: app.name, kind: 'web', template: 'node-web', auth: 'sso', permissions: [], connections: [], resources: { cpu: 1, memoryMb: 256, pids: 64 }, health: { path: '/healthz', port: 8080 }, storage: [] }, pipeline: { schemaVersion: 1, template: 'node-web', stages: stages.map(name => ({ name, commands: [], timeoutSeconds: 60 })) }, migrations: [], files });
function service(outputs: unknown[], qualified = true) {
  const bodies: any[] = [], catalog: ModelCatalog = { schemaVersion: 1, pricesVerifiedAt: now, sources: [], models: [{ id: 'injected-source-model', provider: 'openai', tier: 'strong', inputUsdPerMillion: 1, outputUsdPerMillion: 1, cachedInputUsdPerMillion: 0, cacheWriteUsdPerMillion: 1, effort: 'high', qualified, maxInputTokens: 90000, maxOutputTokens: 32768 }] };
  const gateway = new ModelGateway({ catalog, apiKeys: { openai: 'synthetic-source-key' }, fetch: async (_url, init) => { bodies.push(JSON.parse(String(init?.body))); return Response.json({ status: 'completed', service_tier: 'default', usage: { input_tokens: 1, output_tokens: 1 }, output: [{ type: 'message', content: [{ type: 'output_text', text: JSON.stringify(outputs[bodies.length - 1]) }] }] }); } });
  return { run: createGenerationService({ gateway }), bodies, budget: { reserve: async () => 'synthetic-source-reservation', settle: async () => undefined } };
}
test('actual generation gateway receives the full frontend target and preserves omitted bytes in the merged application', async () => {
  const f = input(), s = service([plan, generated([{ path: 'web/main.jsx', content: '<form>project code</form>' }]), { approved: true, issues: [] }]);
  const out = await s.run({ app, job, context: { previousFiles: f.files }, budgetRemainingUsd: 10 }, s.budget);
  const prompt = JSON.parse(s.bodies[1].input);
  assert.equal(prompt.previousFiles[0].path, 'web/main.jsx'); assert.equal(prompt.previousFiles[0].content, f.files![2]!.content);
  assert.ok(JSON.parse(s.bodies[0].input).sourceInventory.files.some((file: any) => file.path === 'web/main.jsx'));
  for (const file of f.files!.filter(file => file.path !== 'web/main.jsx')) assert.equal(out.files.find(item => item.path === file.path)?.content, file.content);
});
test('actual generation pauses before independent review or merge when a model rewrites an omitted existing file', async () => {
  const f = input(), selection = selectPreviousSource({ ...f, acceptanceCriteria: plan.acceptanceCriteria }), path = selection.omitted.find(file => file.reason === 'limit')!.path;
  const s = service([plan, generated([{ path, content: 'blind replacement' }])]);
  const out = await s.run({ app, job, context: { previousFiles: f.files }, budgetRemainingUsd: 10 }, s.budget);
  assert.equal(s.bodies.length, 2); assert.deepEqual(out.files, []); assert.ok(out.specification.questions.length);
});
test('oversized exact target clarifies without a provider request and qualification remains required for generation', async () => {
  const blocked = service([]), f = input({ files: [{ path: 'web/main.jsx', content: 'x'.repeat(48001) }] });
  const out = await blocked.run({ app, job, context: { previousFiles: f.files }, budgetRemainingUsd: 10 }, blocked.budget);
  assert.equal(blocked.bodies.length, 0); assert.ok(out.specification.questions.length); assert.deepEqual(out.files, []);
  const unqualified = service([], false); await assert.rejects(unqualified.run({ app, job, context: { previousFiles: input().files }, budgetRemainingUsd: 10 }, unqualified.budget), /qualified/); assert.equal(unqualified.bodies.length, 0);
});
test('the real DMS frontend is selected for its business upload request with the original byte ceiling', async () => {
  const files = await Promise.all(['server.mjs', 'src/auth.mjs', 'src/http.mjs', 'src/domain.mjs', 'src/mysql.mjs', 'src/storage.mjs', 'src/mcp.mjs', 'src/connector.mjs', 'web/main.jsx', 'web/auth.js', 'web/style.css', 'migrations/001_documents.sql'].map(async path => ({ path, content: await readFile(`templates/dms/${path}`, 'utf8') })));
  const record = selectPreviousSource(input({ request: 'Add an optional Project code field next to Department when uploading a document and search this metadata', files }));
  assert.ok(record.selected.some(file => file.path === 'web/main.jsx')); assert.ok(record.selectedBytes <= 48000); assert.ok(record.truncated);
});

function fullFrontendSnapshot() {
  const unchanged = generated([]), migration = { id: '001_documents', sql: 'CREATE TABLE documents (id BIGINT PRIMARY KEY)', destructive: false, impact: 'Keep existing documents.' };
  // Key order, indentation and trailing newlines deliberately differ from model serialization.
  const manifest = Object.fromEntries(Object.entries(unchanged.manifest).reverse()), pipeline = Object.fromEntries(Object.entries(unchanged.pipeline).reverse());
  return {
    migration, files: [
      { path: 'web/main.jsx', content: 'x'.repeat(48000) },
      { path: 'app.manifest.json', content: JSON.stringify(manifest, null, 4) + '\r\n' },
      { path: 'pipeline.json', content: JSON.stringify(pipeline) + '\n' },
      { path: 'migrations.json', content: JSON.stringify([migration], null, 4) + '\n' }
    ]
  };
}
async function generateFullFrontend(overrides: Record<string, unknown> = {}, verdict = { approved: true, issues: [] as string[] }) {
  const snapshot = fullFrontendSnapshot(), proposed = { ...generated([{ path: 'web/main.jsx', content: '<form>project code</form>' }]), ...overrides };
  const s = service([plan, proposed, verdict]);
  return { s, snapshot, run: () => s.run({ app, job, context: { previousFiles: snapshot.files }, budgetRemainingUsd: 10 }, s.budget) };
}

test('complete artifact guard rejects deletion of unseen existing files, including excluded dependency locks', () => {
  const f = input({ files: [{ path: 'web/main.jsx', content: 'x'.repeat(48000) }, { path: 'package-lock.json', content: '{"lockfileVersion":3}' }] }), selection = selectPreviousSource(f);
  assert.equal(selection.selectedBytes, 48000); assert.equal(selection.omitted[0]?.path, 'package-lock.json');
  assert.deepEqual(unreviewedExistingArtifactChanges([f.files![0]!], f.files!, selection), ['package-lock.json']);
  assert.deepEqual(unreviewedExistingArtifactChanges(f.files!, f.files!, selection), []);
});
test('exact 48000-byte frontend target cannot blindly change omitted manifest authentication', async () => {
  const candidate = await generateFullFrontend({ manifest: { ...generated([]).manifest, auth: 'public' } }), out = await candidate.run();
  const prompt = JSON.parse(candidate.s.bodies[1].input);
  assert.equal(prompt.previousFiles.length, 1); assert.equal(Buffer.byteLength(prompt.previousFiles[0].content), 48000);
  assert.equal(candidate.s.bodies.length, 2); assert.deepEqual(out.files, []); assert.equal(out.pipeline, null); assert.ok(out.specification.questions.length);
});
test('exact 48000-byte frontend target cannot blindly change omitted manifest permissions or resources', async () => {
  const candidate = await generateFullFrontend({ manifest: { ...generated([]).manifest, permissions: ['documents.write'], resources: { cpu: 2, memoryMb: 512, pids: 128 } } }), out = await candidate.run();
  assert.equal(candidate.s.bodies.length, 2); assert.deepEqual(out.files, []); assert.ok(out.specification.questions.length);
});
test('exact 48000-byte frontend target cannot blindly replace an omitted custom pipeline', async () => {
  const pipeline = generated([]).pipeline; pipeline.stages.find(stage => stage.name === 'build')!.commands = ['npm run build'];
  const candidate = await generateFullFrontend({ pipeline }), out = await candidate.run();
  assert.equal(candidate.s.bodies.length, 2); assert.deepEqual(out.files, []); assert.ok(out.specification.questions.length);
});
test('exact 48000-byte frontend target cannot append an additive migration to an unseen ledger', async () => {
  const candidate = await generateFullFrontend({ migrations: [{ id: '002_project_code', sql: 'ALTER TABLE documents ADD project_code VARCHAR(64) NULL', destructive: false, impact: 'Add optional project metadata.' }] }), out = await candidate.run();
  assert.equal(candidate.s.bodies.length, 2); assert.deepEqual(out.files, []); assert.ok(out.specification.questions.length);
});
test('semantically unchanged omitted contracts retain their exact noncanonical bytes in the final application', async () => {
  const candidate = await generateFullFrontend(), out = await candidate.run();
  assert.equal(candidate.s.bodies.length, 3); assert.equal(out.files.find(file => file.path === 'web/main.jsx')?.content, '<form>project code</form>');
  for (const file of candidate.snapshot.files.filter(file => file.path !== 'web/main.jsx')) assert.equal(out.files.find(item => item.path === file.path)?.content, file.content, `Preserve exact ${file.path}`);
  assert.deepEqual(JSON.parse(out.files.find(file => file.path === 'migrations.json')!.content), [candidate.snapshot.migration]);
});
test('failed independent review preserves the fully guarded contract map for subsequent job recovery', async () => {
  const candidate = await generateFullFrontend({}, { approved: false, issues: ['Project metadata handling needs a business correction.'] });
  await assert.rejects(candidate.run(), (error: any) => {
    assert.match(error.message, /Independent code review needs changes/);
    for (const file of candidate.snapshot.files.filter(file => file.path !== 'web/main.jsx')) assert.equal(error.partialGeneration.files.find((item: any) => item.path === file.path)?.content, file.content);
    return true;
  });
  assert.equal(candidate.s.bodies.length, 3);
});
test('fully reviewed structured contracts can change within the same byte ceiling', async () => {
  const snapshot = fullFrontendSnapshot(); snapshot.files[0]!.content = '<form>department</form>';
  const proposed: Generation = generated([{ path: 'web/main.jsx', content: '<form>project code</form>' }]); proposed.manifest.resources.memoryMb = 512;
  proposed.pipeline.stages.find(stage => stage.name === 'application_tests')!.commands = ['npm test'];
  proposed.migrations = [{ id: '002_project_code', sql: 'ALTER TABLE documents ADD project_code VARCHAR(64) NULL', destructive: false, impact: 'Add optional project metadata.' }];
  const s = service([plan, proposed, { approved: true, issues: [] }]), out = await s.run({ app, job, context: { previousFiles: snapshot.files }, budgetRemainingUsd: 10 }, s.budget);
  assert.equal(s.bodies.length, 3); assert.equal(JSON.parse(out.files.find(file => file.path === 'app.manifest.json')!.content).resources.memoryMb, 512);
  assert.deepEqual(JSON.parse(out.files.find(file => file.path === 'migrations.json')!.content).map((item: any) => item.id), ['001_documents', '002_project_code']);
});
test('legacy merge cannot silently remove an omitted pipeline alias from a supplied application snapshot', async () => {
  const snapshot = fullFrontendSnapshot(); snapshot.files.push({ path: 'autosoft.pipeline.json', content: snapshot.files.find(file => file.path === 'pipeline.json')!.content });
  const s = service([plan, generated([{ path: 'web/main.jsx', content: '<form>project code</form>' }])]), out = await s.run({ app, job, context: { previousFiles: snapshot.files }, budgetRemainingUsd: 10 }, s.budget);
  assert.equal(s.bodies.length, 2); assert.deepEqual(out.files, []); assert.ok(out.specification.questions.length);
});
