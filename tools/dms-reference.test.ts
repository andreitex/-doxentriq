import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { build } from 'vite';
import { ModelGateway, createGenerationService, type ModelCatalog } from '../packages/core/src/models.ts';
import { generationSchema, pipelineSchema, appManifestSchema } from '../packages/core/src/schemas.ts';
import type { AppRecord, JobRecord } from '../packages/core/src/types.ts';
import { writeScopedFiles } from '../apps/control/src/engine.ts';
import { QualificationBudget } from './qualify-models.ts';

const root = resolve('templates/dms'), require = createRequire(import.meta.url);
const hash = (content: string) => createHash('sha256').update(content).digest('hex');
const referenceManifest = appManifestSchema.parse(JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8')));
const pipeline = pipelineSchema.parse(JSON.parse(await readFile(join(root, 'pipeline.json'), 'utf8')));
const requestFixture = JSON.parse(await readFile(join(root, 'chat-update.json'), 'utf8')) as { request: string; answeredBusinessContext: string; acceptance: string[] };
const migration = { id: '001_documents', sql: await readFile(join(root, 'migrations/001_documents.sql'), 'utf8'), destructive: false, impact: 'Add document metadata, immutable versions, folders and audit tables; existing records are retained.' };
const specification = { title: 'Optional project code metadata', summary: requestFixture.request, acceptanceCriteria: requestFixture.acceptance, questions: [] };
const now = new Date().toISOString();
const app: AppRecord = { id: referenceManifest.id, slug: referenceManifest.slug, name: referenceManifest.name, description: 'Deterministic DMS reference fixture', kind: 'web', status: 'published', activeReleaseId: 'fixture-baseline', url: null, previewUrl: null, createdAt: now, updatedAt: now };
const job: JobRecord = { id: 'fixture-chat-update', appId: app.id, request: requestFixture.request, stage: 'queued', baseReleaseId: app.activeReleaseId, budgetUsd: 1, costUsd: 0, attempts: 0, createdAt: now, updatedAt: now };
const catalog: ModelCatalog = { schemaVersion: 1, pricesVerifiedAt: now, sources: ['https://example.com/injected-provider-fixture'], models: [{ id: 'deterministic-provider-fixture', provider: 'openai', tier: 'strong', effort: 'high', qualified: true, inputUsdPerMillion: 1, outputUsdPerMillion: 1, cachedInputUsdPerMillion: 0, cacheWriteUsdPerMillion: 1, maxInputTokens: 200000, maxOutputTokens: 32768 }] };

async function baselineFiles() {
  const files: { path: string; content: string }[] = [];
  const walk = async (directory: string) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (['dist', 'node_modules', 'scripts', 'README.md', 'manifest.json', 'pipeline.json', 'golden-request.json', 'chat-update.json'].includes(entry.name)) continue;
      const path = join(directory, entry.name); if (entry.isDirectory()) await walk(path); else if (entry.isFile()) files.push({ path: relative(root, path).split('\\').join('/'), content: await readFile(path, 'utf8') });
    }
  };
  await walk(root);
  // Focus the bounded model context on the file being changed; all omitted contents
  // remain in the local source snapshot and must survive the real merge operation.
  files.sort((a, b) => Number(b.path === 'web/main.jsx') - Number(a.path === 'web/main.jsx'));
  return [...files, { path: 'app.manifest.json', content: JSON.stringify(referenceManifest) }, { path: 'pipeline.json', content: JSON.stringify(pipeline) }, { path: 'migrations.json', content: JSON.stringify([migration]) }];
}
function updateCode(original: string) {
  const before = "metadata: form.elements.department?.value ? { department: form.elements.department.value } : {}";
  assert.ok(original.includes(before));
  return original.replace(before, "metadata: { ...(form.elements.department?.value ? { department: form.elements.department.value } : {}), ...(form.elements.projectCode?.value ? { projectCode: form.elements.projectCode.value } : {}) }")
    .replace('<label>File<input name="file" type="file" required /></label>', '<label>Project code<input name="projectCode" maxLength={256} /></label><label>File<input name="file" type="file" required /></label>');
}
async function generate(previousFiles: Awaited<ReturnType<typeof baselineFiles>>, override: Record<string, unknown> = {}, expectedCalls = 3) {
  let calls = 0; const source = previousFiles.find(file => file.path === 'web/main.jsx')!;
  const proposed = generationSchema.parse({ specification, summary: 'Add optional project code metadata without changing data or permissions.', manifest: referenceManifest, pipeline, migrations: [], files: [{ path: 'web/main.jsx', content: updateCode(source.content) }], ...override });
  const fetchFixture = (async (_url: unknown, options?: RequestInit) => {
    const body = JSON.parse(String(options?.body)); const step = calls++;
    assert.equal(body.model, catalog.models[0]!.id); assert.equal(body.reasoning.effort, 'high');
    if (step === 1) {
      const context = JSON.parse(body.input); assert.ok(context.previousFiles.some((file: { path: string }) => file.path === 'web/main.jsx'));
      assert.ok(context.previousFileIndex.some((file: { path: string }) => file.path === 'package-lock.json'));
      assert.ok(!context.previousFiles.some((file: { path: string }) => file.path === 'package-lock.json'));
    }
    const value = step === 0 ? specification : step === 1 ? proposed : { approved: true, issues: [] };
    assert.ok(step < 3);
    return new Response(JSON.stringify({ status: 'completed', service_tier: 'default', usage: { input_tokens: 10, output_tokens: 10 }, output: [{ type: 'message', content: [{ type: 'output_text', text: JSON.stringify(value) }] }] }), { status: 200 });
  }) as typeof fetch;
  const service = createGenerationService({ gateway: new ModelGateway({ catalog, apiKeys: { openai: 'synthetic-fixture-provider-key' }, fetch: fetchFixture }), templateRoot: resolve('templates') });
  const result = await service({ app, job, context: { previousSpecification: { title: 'DMS reference', questions: [] }, previousFiles, answer: requestFixture.answeredBusinessContext }, budgetRemainingUsd: 1 }, new QualificationBudget(1, 1).hooks('dms-source-fixture'));
  assert.equal(calls, expectedCalls); return result;
}

test('DMS chat update contract preserves source and migrations and builds the resulting React application', async () => {
  const baseline = await baselineFiles(), result = await generate(baseline), files = new Map(result.files.map(file => [file.path, file.content]));
  for (const file of baseline) if (!['web/main.jsx', 'app.manifest.json', 'pipeline.json', 'migrations.json'].includes(file.path)) assert.equal(hash(files.get(file.path)!), hash(file.content), `Preserve ${file.path}`);
  assert.match(files.get('web/main.jsx')!, /name="projectCode"/); assert.match(files.get('web/main.jsx')!, /projectCode: form.elements.projectCode.value/);
  assert.deepEqual(JSON.parse(files.get('migrations.json')!), [migration]);
  const directory = await mkdtemp(join(tmpdir(), 'autosoft-dms-chat-'));
  try {
    await writeScopedFiles(directory, result.files);
    await build({ configFile: false, root: directory, logLevel: 'silent', resolve: { alias: [{ find: /^react$/, replacement: require.resolve('react') }, { find: /^react\/jsx-runtime$/, replacement: require.resolve('react/jsx-runtime') }, { find: /^react\/jsx-dev-runtime$/, replacement: require.resolve('react/jsx-dev-runtime') }, { find: /^react-dom\/client$/, replacement: require.resolve('react-dom/client') }] }, build: { outDir: 'dist', emptyOutDir: true } });
    assert.match(await readFile(join(directory, 'dist/index.html'), 'utf8'), /\/assets\/index-.*\.js/);
    // The restored backend is byte-identical company source. Execute its business
    // behavior with test-only repositories, never arbitrary model-proposed code.
    const { DmsService } = await import(pathToFileURL(join(directory, 'src/domain.mjs')).href);
    const { MemoryRepository, MemoryStorage } = await import(pathToFileURL(join(directory, 'test/support.mjs')).href);
    const service = new DmsService({ appId: app.id, repository: new MemoryRepository(), storage: new MemoryStorage() });
    const writer = { id: 'editor', appId: app.id, roles: ['dms.read', 'dms.search', 'dms.write'] };
    const doc = await service.upload(writer, { title: 'Existing contract', metadata: { department: 'Finance', projectCode: 'PROJECT-42' }, content: Buffer.from('original preserved bytes') });
    assert.equal((await service.search(writer, 'PROJECT-42'))[0].id, doc.id);
    await service.upload(writer, { content: Buffer.from('a new version') }, doc.id);
    await service.restore(writer, doc.id, doc.version.id);
    assert.equal((await service.content(writer, doc.id, doc.version.id)).content.toString(), 'original preserved bytes');
    await assert.rejects(service.document({ id: 'platform-owner', appId: app.id, roles: ['platform.owner'] }, doc.id));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test('DMS generation rejects another app identity, protected infrastructure and rewriting a recorded migration', async () => {
  const baseline = await baselineFiles();
  await assert.rejects(generate(baseline, { manifest: { ...referenceManifest, id: 'another-app' } }), /identity/);
  await assert.rejects(generate(baseline, { files: [{ path: 'Dockerfile', content: 'FROM unwanted' }] }), /protected infrastructure/);
  await assert.rejects(generate(baseline, { migrations: [{ ...migration, sql: 'DROP TABLE documents' }] }), /recorded migration was modified/);
});
test('DMS dependency changes pause before blindly discarding an excluded lock and retain mandatory independent test stages', async () => {
  const baseline = await baselineFiles(), existing = JSON.parse(baseline.find(file => file.path === 'package.json')!.content);
  const result = await generate(baseline, { files: [{ path: 'package.json', content: JSON.stringify({ ...existing, dependencies: { ...existing.dependencies, jose: '0.0.0' } }) }] }, 2);
  assert.deepEqual(result.files, []); assert.ok(result.specification.questions.length); assert.equal(result.pipeline, null);
  assert.ok(pipeline.stages.find(stage => stage.name === 'build')!.commands.includes('npm run build'));
  assert.ok(pipeline.stages.find(stage => stage.name === 'application_tests')!.commands.includes('npm test'));
  assert.ok(pipeline.stages.find(stage => stage.name === 'acceptance')!.commands.includes('npm test'));
  assert.match(existing.scripts.test, /node --test test\/\*\.test\.mjs/);
});
