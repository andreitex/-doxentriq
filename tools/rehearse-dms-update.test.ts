import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { inspectCandidate, referenceFiles, rehearse } from './rehearse-dms-update.ts';
import { modelCatalogSchema } from '../packages/core/src/models.ts';

const root = resolve('templates/dms');

test('rehearsal preserves existing auth, storage and locks and allows only focused new tests', () => {
  const before = [{ path: 'src/auth.mjs', content: 'protected auth' }, { path: 'web/main.jsx', content: 'old UI' }];
  const ui = { path: 'web/main.jsx', content: '<input name="projectCode" />; { projectCode: form.elements.projectCode.value }' };
  const after = [before[0]!, ui, { path: 'test/project-code-form.test.mjs', content: 'synthetic test source' }];
  assert.ok(inspectCandidate(before, after).checks.every(check => check.passed));
  assert.ok(inspectCandidate(before, [...after, { path: 'server.mjs', content: 'unexpected backend' }]).checks.some(check => !check.passed));
  assert.ok(inspectCandidate(before, [{ ...before[0]!, content: 'changed auth' }, ui]).checks.some(check => !check.passed));
  assert.throws(() => inspectCandidate(before, [...after, ui]), /Duplicate/);
});

test('actual generation orchestration produces a retained artifact without executing model source', async () => {
  const baseline = await referenceFiles(root);
  const catalog = modelCatalogSchema.parse(JSON.parse(await readFile('models/catalog.json', 'utf8')));
  const ui = baseline.find(file => file.path === 'web/main.jsx')!.content;
  const before = "metadata: form.elements.department?.value ? { department: form.elements.department.value } : {}";
  assert.ok(ui.includes(before));
  const changed = ui.replace(before, "metadata: { department: form.elements.department.value, projectCode: form.elements.projectCode.value }")
    .replace('<label>File<input name="file" type="file" required /></label>', '<label>Project code<input name="projectCode" maxLength={256} /></label><label>File<input name="file" type="file" required /></label>');
  const specification = { title: 'Optional Project code', summary: 'Preserve documents and add optional metadata', acceptanceCriteria: ['Project code is searchable'], questions: [] };
  const generated = { specification, summary: 'Optional metadata only', manifest: JSON.parse(baseline.find(file => file.path === 'app.manifest.json')!.content), pipeline: JSON.parse(baseline.find(file => file.path === 'pipeline.json')!.content), migrations: [], files: [{ path: 'web/main.jsx', content: changed }] };
  let calls = 0;
  const request: typeof fetch = async (url, options) => {
    const body = JSON.parse(String(options?.body)), index = calls++;
    assert.ok(index < 3);
    if (index === 0) assert.ok(JSON.stringify(body).includes('explicit synthetic business answers'));
    if (index === 1) {
      const context=JSON.parse(String(body.input ?? body.messages[0].content));
      assert.equal(context.previousFiles.find((file:{path:string})=>file.path==='web/main.jsx').content,ui);
    }
    const text = JSON.stringify(index === 0 ? specification : index === 1 ? generated : { approved: true, issues: [] });
    return String(url).includes('api.openai.com') ? Response.json({ model: body.model, status: 'completed', service_tier: 'default', usage: { input_tokens: 100, output_tokens: 100 }, output: [{ type: 'message', content: [{ type: 'output_text', text }] }] }) : Response.json({ model: body.model, usage: { service_tier: 'standard', input_tokens: 100, output_tokens: 100 }, content: [{ type: 'text', text }] });
  };
  const result = await rehearse({ reference: root, templateRoot: resolve('templates'), catalog, maxUsd: 2, suiteMaxUsd: 2, requestMaxUsd: .65, keys: { openai: 'synthetic-openai-key', anthropic: 'synthetic-anthropic-key' }, answer: 'explicit synthetic business answers', request });
  assert.equal(calls, 3);
  assert.equal(result.results[0]!.qualified, true, JSON.stringify(result.results));
  assert.equal(result.heldUsd, 0);
  assert.deepEqual(result.artifacts['dms-candidate.json']!.changedPaths, ['web/main.jsx']);
  assert.equal(result.artifacts['dms-candidate.json']!.rehearsalOnly, true);
  assert.equal(JSON.stringify(result).includes('synthetic-openai-key'), false);
});

test('implementation business questions retain the specification and stop before paid review', async () => {
  const baseline=await referenceFiles(root);
  const catalog=modelCatalogSchema.parse(JSON.parse(await readFile('models/catalog.json','utf8')));
  const specification={title:'Project code',summary:'Initial upload only',acceptanceCriteria:['Preserve documents'],questions:[] as string[]};
  const generated={specification:{...specification,questions:['Which business scope should change?']},summary:'Clarification needed',manifest:JSON.parse(baseline.find(f=>f.path==='app.manifest.json')!.content),pipeline:JSON.parse(baseline.find(f=>f.path==='pipeline.json')!.content),migrations:[],files:[{path:'web/main.jsx',content:'Unreviewed implementation must not execute'}]};
  let calls=0;
  const request:typeof fetch=async(url)=>{
    assert.ok(calls<2,'Clarification must not trigger a code-review request');
    const text=JSON.stringify(calls++===0?specification:generated);
    return String(url).includes('api.openai.com')?Response.json({service_tier:'default',usage:{input_tokens:100,output_tokens:100},output:[{type:'message',content:[{type:'output_text',text}]}]}):Response.json({usage:{service_tier:'standard',input_tokens:100,output_tokens:100},content:[{type:'text',text}]});
  };
  const result=await rehearse({reference:root,templateRoot:resolve('templates'),catalog,maxUsd:2,suiteMaxUsd:2,requestMaxUsd:.65,keys:{anthropic:'synthetic-anthropic-key',openai:'synthetic-openai-key'},request});
  assert.equal(calls,2); assert.equal(result.heldUsd,0); assert.equal(result.clarificationCount,1);
  assert.deepEqual(result.artifacts['dms-candidate.json']!.files,[]);
});

test('clarification pauses after one billed call and retains the specification without a source rewrite', async () => {
  const catalog = modelCatalogSchema.parse(JSON.parse(await readFile('models/catalog.json', 'utf8')));
  let calls = 0;
  const request: typeof fetch = async () => {
    calls++;
    const text = JSON.stringify({ title: 'Project code', summary: 'Await business answer', acceptanceCriteria: ['Preserve documents'], questions: ['Which project code format should be used?'] });
    return Response.json({ usage: { service_tier: 'standard', input_tokens: 100, output_tokens: 100 }, content: [{ type: 'text', text }] });
  };
  const result = await rehearse({ reference: root, templateRoot: resolve('templates'), catalog, maxUsd: 2, suiteMaxUsd: 2, requestMaxUsd: .65, keys: { anthropic: 'synthetic-anthropic-key' }, request });
  assert.equal(calls, 1);
  assert.equal(result.results[0]!.qualified, false);
  assert.equal(result.clarificationCount, 1);
  assert.deepEqual(result.artifacts['dms-candidate.json']!.files, []);
  assert.deepEqual(result.artifacts['dms-candidate.json']!.changedPaths, []);
});
