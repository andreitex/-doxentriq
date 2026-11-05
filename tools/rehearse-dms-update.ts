import { createHash, randomUUID } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ModelGateway, createGenerationService, modelCatalogSchema, readSecretEnvironment, type ModelCatalog } from '../packages/core/src/models.ts';
import { appManifestSchema, pipelineSchema, generationSchema } from '../packages/core/src/schemas.ts';
import type { AppRecord, JobRecord } from '../packages/core/src/types.ts';
import { QualificationBudget } from './qualification-budget.ts';

const hash = (content: string) => createHash('sha256').update(content).digest('hex');
type SourceFile = { path: string; content: string };

export async function referenceFiles(root: string): Promise<SourceFile[]> {
  const files: SourceFile[] = [];
  const walk = async (directory: string) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (['dist', 'node_modules', 'scripts', 'README.md', 'manifest.json', 'pipeline.json', 'golden-request.json', 'chat-update.json', 'rehearsal-answers.txt'].includes(entry.name)) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) {
        const content = await readFile(path, 'utf8');
        if (content.length > 500000 || files.length >= 125) throw new Error('Reference source exceeded its bound');
        files.push({ path: relative(root, path).split('\\').join('/'), content });
      } else throw new Error('Reference source must contain only ordinary files and directories');
    }
  };
  await walk(root);
  const manifest = appManifestSchema.parse(JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8')));
  const pipeline = pipelineSchema.parse(JSON.parse(await readFile(join(root, 'pipeline.json'), 'utf8')));
  const migration = { id: '001_documents', sql: await readFile(join(root, 'migrations/001_documents.sql'), 'utf8'), destructive: false, impact: 'Add document metadata, immutable versions, folders and audit tables; existing records are retained.' };
  files.sort((a, b) => Number(b.path === 'web/main.jsx') - Number(a.path === 'web/main.jsx') || a.path.localeCompare(b.path));
  return [...files, { path: 'app.manifest.json', content: JSON.stringify(manifest, null, 2) }, { path: 'pipeline.json', content: JSON.stringify(pipeline, null, 2) }, { path: 'migrations.json', content: JSON.stringify([migration], null, 2) }];
}

export function inspectCandidate(before: SourceFile[], after: SourceFile[]) {
  const original = new Map(before.map(file => [file.path, file.content]));
  const proposed = new Map(after.map(file => [file.path, file.content]));
  if (proposed.size !== after.length) throw new Error('Duplicate candidate paths');
  const changed = [...new Set([...original.keys(), ...proposed.keys()])].filter(path => original.get(path) !== proposed.get(path));
  const checks = [
    { id: 'change-confined-to-upload-form-and-focused-tests', passed: changed.includes('web/main.jsx') && changed.every(path => path === 'web/main.jsx' || !original.has(path) && /^test\/project-code(?:-[a-z0-9-]+)?\.test\.mjs$/.test(path)) },
    { id: 'project-code-input-present', passed: /name\s*=\s*["']projectCode["']/.test(proposed.get('web/main.jsx') ?? '') },
    { id: 'project-code-metadata-present', passed: /projectCode/.test(proposed.get('web/main.jsx') ?? '') && /form\.elements\.projectCode/.test(proposed.get('web/main.jsx') ?? '') },
    { id: 'authorization-storage-lock-migrations-preserved', passed: before.filter(file => file.path !== 'web/main.jsx').every(file => proposed.get(file.path) === file.content) }
  ];
  return { changed, checks };
}

export async function rehearse(config: { reference: string; templateRoot: string; catalog: ModelCatalog; maxUsd: number; suiteMaxUsd: number; requestMaxUsd: number; keys: { openai?: string; anthropic?: string }; answer?: string; request?: typeof fetch }) {
  const previousFiles = await referenceFiles(config.reference);
  const manifest = appManifestSchema.parse(JSON.parse(previousFiles.find(file => file.path === 'app.manifest.json')!.content));
  const fixture = JSON.parse(await readFile(join(config.reference, 'chat-update.json'), 'utf8')) as { request: string; answeredBusinessContext: string; acceptance: string[] };
  const now = new Date().toISOString(), suite = 'dms-reference-update';
  const app: AppRecord = { id: manifest.id, slug: manifest.slug, name: manifest.name, description: 'Synthetic company DMS reference, not a published customer release', kind: 'web', status: 'draft', activeReleaseId: 'synthetic-reference-baseline', databaseSchemaVersion: 1, url: null, previewUrl: null, createdAt: now, updatedAt: now };
  const job: JobRecord = { id: 'dms-rehearsal-' + randomUUID(), appId: app.id, request: fixture.request, stage: 'queued', baseReleaseId: app.activeReleaseId, budgetUsd: config.maxUsd, costUsd: 0, attempts: 0, createdAt: now, updatedAt: now };
  const budget = new QualificationBudget(config.maxUsd, config.suiteMaxUsd, config.requestMaxUsd);
  const selectedCalls: { provider: string; model: string; effort: string }[] = [];
  const transport: typeof fetch = async (input, init) => {
    const body = JSON.parse(String(init?.body));
    selectedCalls.push({ provider: String(input).startsWith('https://api.openai.com/') ? 'openai' : 'anthropic', model: body.model, effort: body.reasoning?.effort ?? body.output_config?.effort });
    return (config.request ?? fetch)(input, init);
  };
  const gateway = new ModelGateway({ catalog: config.catalog, apiKeys: config.keys, fetch: transport });
  const service = createGenerationService({ gateway, templateRoot: config.templateRoot });
  let files: SourceFile[] = [], checks: { id: string; passed: boolean }[] = [], summary = '', specification: unknown, partial = false;
  try {
    const generated = await service({ app, job, context: { previousFiles, answer: [fixture.answeredBusinessContext, config.answer].filter(Boolean).join('\n'), previousSpecification: { title: 'Company DMS reference', summary: 'Preserve existing role-bound document management', acceptanceCriteria: fixture.acceptance, questions: [] } }, budgetRemainingUsd: config.maxUsd }, budget.hooks(suite));
    specification = generated.specification;
    files = generated.files;
    summary = generated.summary;
    const inspected = inspectCandidate(previousFiles, files);
    checks = [{ id: 'generation-and-independent-model-review', passed: files.length > 0 && generated.specification.questions.length === 0 }, ...inspected.checks];
  } catch (failure) {
    const retained = failure && typeof failure === 'object' ? (failure as { partialGeneration?: unknown }).partialGeneration : undefined;
    const candidate = retained && typeof retained === 'object' ? retained as { files?: unknown; specification?: unknown; summary?: unknown } : undefined;
    const safeFiles = generationSchema.shape.files.safeParse(candidate?.files);
    if (safeFiles.success) { files = safeFiles.data; specification = candidate?.specification; summary = 'Independent model review requested changes; candidate retained for separate examination'; partial = true; }
    checks = [{ id: 'generation-and-independent-model-review', passed: false }];
  }
  const totals = budget.totals(suite), passed = checks.every(check => check.passed) && totals.heldUsd === 0;
  const clarificationCount = specification && typeof specification === 'object' && 'questions' in specification && Array.isArray(specification.questions) ? specification.questions.length : 0;
  const artifact = files.length || specification ? { schemaVersion: 1, rehearsalOnly: true, appId: app.id, referenceReleaseId: app.activeReleaseId, partial, summary, specification, files, baselineHashes: Object.fromEntries(previousFiles.map(file => [file.path, hash(file.content)])), changedPaths: files.length ? inspectCandidate(previousFiles, files).changed : [] } : undefined;
  return { schemaVersion: 1, checkedAt: new Date().toISOString(), aggregateLimitUsd: config.maxUsd, perSuiteLimitUsd: config.suiteMaxUsd, perRequestLimitUsd: config.requestMaxUsd, ...totals,
    results: [{ entry: suite, qualified: passed, ...totals, cases: checks.map((check, index) => ({ ...check, detail: check.passed ? 'Source contract passed; generated code has not executed' : 'Source contract needs attention; candidate is not eligible for publication', costUsd: index === 0 ? totals.spentUsd : 0 })) }],
    selectedCalls, requests: budget.requestRecords(), generationRequests: selectedCalls.length, clarificationCount, sourceFileCount: previousFiles.length,
    artifacts: artifact ? { 'dms-candidate.json': artifact } : {},
    note: 'Actual generation service with synthetic reference source. No generated code execution, build, dependency scan, database change, deployment, release approval, or live document access. File checks do not replace sandbox acceptance.' };
}

export async function main(args = process.argv.slice(2)) {
  const values = new Map<string, string>();
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i]!, value = args[i + 1];
    if (!['--catalog', '--reference', '--template-root', '--max-usd', '--suite-max-usd', '--request-max-usd'].includes(key) || !value || values.has(key)) throw new Error('Invalid rehearsal options');
    values.set(key, value);
  }
  const dollar = (key: string) => { const n = Number(values.get(key)); if (!Number.isFinite(n) || n <= 0) throw new Error('Explicit positive test caps required'); return n; };
  const catalog = modelCatalogSchema.parse(JSON.parse(await readFile(resolve(values.get('--catalog')!), 'utf8')));
  const reference = resolve(values.get('--reference') ?? '/opt/autosoft-model-test/dms');
  const answer = await readFile(join(reference, 'rehearsal-answers.txt'), 'utf8').catch(error => { if (error.code === 'ENOENT') return undefined; throw error; });
  if (answer !== undefined && (answer.length > 16000 || !answer.trim())) throw new Error('Bounded synthetic business answers required');
  const report = await rehearse({ catalog, reference, templateRoot: resolve(values.get('--template-root') ?? '/opt/autosoft-model-test'), maxUsd: dollar('--max-usd'), suiteMaxUsd: dollar('--suite-max-usd'), requestMaxUsd: dollar('--request-max-usd'), ...(answer ? { answer } : {}), keys: { openai: await readSecretEnvironment('OPENAI_API_KEY'), anthropic: await readSecretEnvironment('ANTHROPIC_API_KEY') } });
  process.stdout.write(JSON.stringify(report) + '\n');
  return report.results.every(result => result.qualified) ? 0 : 1;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  void main().then(code => { process.exitCode = code; }).catch(() => { process.stderr.write('DMS rehearsal stopped without a complete report; preserve its monthly reservation.\n'); process.exitCode = 1; });
}
