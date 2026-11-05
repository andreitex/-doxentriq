/** Run on the installed Linux VM with Node 24, Docker access and the quota-helper token.
 * ACCEPTANCE_TOOLCHAIN_IMAGE must be an already-present company-approved Node image digest.
 * This creates only uniquely named synthetic containers, workspaces and a 32 MiB quota.
 * Missing prerequisites are recorded as unavailable and return exit code 2, never success.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { chown, mkdir, mkdtemp, readFile, realpath, rm, statfs, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { request } from 'node:http';

const execute = promisify(execFile);
type Result = { name: string; status: 'passed' | 'failed' | 'unavailable'; detail: string };
const results: Result[] = [];
const id = randomUUID(); const prefix = `as-acceptance-${id.slice(0, 8)}`; const containers = new Set<string>();
const image = process.env.ACCEPTANCE_TOOLCHAIN_IMAGE ?? '';
const runtime = process.env.RUNSC_RUNTIME ?? 'runsc';
let workspace: string | undefined; let dataDir: string | undefined;
const outputPath = resolve(process.env.ACCEPTANCE_REPORT ?? join('artifacts', `runtime-containment-${id}.json`));
const names = ['sandbox availability', 'filesystem containment', 'unauthorized networking', 'PID exhaustion', 'temporary disk exhaustion', 'persistent storage hard quota', 'bounded build mount'];

async function docker(args: string[], timeout = 45000) {
  try { const value = await execute('docker', args, { timeout, maxBuffer: 2 * 1024 * 1024, windowsHide: true }); return { code: 0, stdout: value.stdout, stderr: value.stderr }; }
  catch (error) { const value = error as { code?: number | string; stdout?: string; stderr?: string; message?: string; killed?: boolean }; return { code: typeof value.code === 'number' ? value.code : -1, stdout: value.stdout ?? '', stderr: String(value.stderr ?? value.message ?? 'Command unavailable').slice(0, 2000) }; }
}
async function sandbox(name: string, code: string, options: { mount?: string; tmpSize?: string } = {}) {
  const container = `${prefix}-${name}`; containers.add(container);
  const args = ['run', '--name', container, '--label', `io.autosoft.acceptance=${id}`, '--runtime', runtime, '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '1g', '--cpus', '2', '--network', 'none', '--tmpfs', `/tmp:rw,nosuid,nodev,size=${options.tmpSize ?? '64m'},mode=1777`];
  if (options.mount) args.push('--mount', `type=bind,src=${options.mount},dst=/workspace`);
  const result = await docker([...args, image, 'node', '--input-type=module', '-e', code]);
  await docker(['rm', '-f', container], 10000); containers.delete(container); return result;
}
async function check(name: string, action: () => Promise<string>): Promise<void> {
  try { results.push({ name, status: 'passed', detail: await action() }); }
  catch (error) { results.push({ name, status: 'failed', detail: String(error instanceof Error ? error.message : error).slice(0, 2000) }); }
}
function requireSuccess(result: Awaited<ReturnType<typeof docker>>, marker: string): void {
  if (result.code !== 0 || !result.stdout.includes(marker)) throw new Error(`Containment assertion failed (exit ${result.code}): ${result.stderr || result.stdout}`);
}
async function quotaRequest(body: unknown): Promise<{ hostPath: string; sizeMb: number; quotaEnforced: boolean }> {
  if (!dataDir) throw new Error('Installed encrypted data directory unavailable.');
  const token = (await readFile(process.env.QUOTA_HELPER_TOKEN_FILE ?? join(dataDir, 'secrets/runtime/quota-token'), 'utf8')).trim();
  const content = JSON.stringify(body);
  return new Promise((accept, reject) => {
    const call = request({ socketPath: process.env.QUOTA_HELPER_SOCKET_FILE ?? '/run/autosoft/quota.sock', path: '/v1/storage', method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(content) }, timeout: 10000 }, response => {
      let value = ''; response.on('data', part => { value += part; if (value.length > 65536) call.destroy(new Error('Quota response exceeds bound.')); });
      response.on('end', () => { if (response.statusCode !== 200) reject(new Error('Quota helper did not enforce the test quota.')); else { try { accept(JSON.parse(value)); } catch { reject(new Error('Invalid quota helper response.')); } } });
    });
    call.on('error', reject); call.on('timeout', () => call.destroy(new Error('Quota helper unavailable.'))); call.end(content);
  });
}
try {
  if (process.platform !== 'linux') throw new Error('Containment acceptance requires the installed Linux VM; no Docker/runsc checks were executed.');
  if (!/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(image) || runtime !== 'runsc') throw new Error('An approved digest-pinned Node toolchain and the runsc runtime are required.');
  const info = await docker(['info', '--format', '{{json .Runtimes}}'], 10000);
  if (info.code !== 0 || !Object.hasOwn(JSON.parse(info.stdout), 'runsc')) throw new Error('Docker with registered runsc runtime is unavailable.');
  if ((await docker(['image', 'inspect', image], 10000)).code !== 0) throw new Error('Approved toolchain image is not locally installed. The harness does not pull unreviewed images.');
  try { const installation = JSON.parse(await readFile('/etc/autosoft/installation.json', 'utf8')) as { data_dir?: string }; if (installation.data_dir) dataDir = await realpath(installation.data_dir); } catch { /* Unavailable installed storage is reported independently below. */ }
  const root = process.env.ACCEPTANCE_WORKSPACE_ROOT ?? (dataDir ? join(dataDir, 'runtime/builds') : tmpdir());
  workspace = await mkdtemp(join(root, `${prefix}-`)); const mount = join(workspace, 'source'); await mkdir(mount, { mode: 0o700 }); await chown(mount, 10001, 10001);
  const marker = join(workspace, 'host-only.txt'); await writeFile(marker, 'host sentinel', { mode: 0o600 }); await symlink(marker, join(mount, 'outside-link')); await chown(join(mount, 'outside-link'), 10001, 10001).catch(() => undefined);
  await check('sandbox availability', async () => { requireSuccess(await sandbox('probe', 'console.log("RUNSC_EXECUTED")'), 'RUNSC_EXECUTED'); return 'Pinned Node image executed through Docker runsc with enforced resource and privilege limits.'; });
  await check('filesystem containment', async () => {
    const code = `import fs from 'node:fs'; import assert from 'node:assert/strict';
      for(const file of ['/run/docker.sock','/var/run/docker.sock',${JSON.stringify(marker)},'/workspace/outside-link','/workspace/../host-only.txt','/run/app-secrets/mysql-password']) assert.throws(()=>fs.readFileSync(file));
      assert.throws(()=>fs.writeFileSync('/workspace/../host-only.txt','changed')); assert.throws(()=>fs.writeFileSync('/etc/acceptance-write','changed')); console.log('CONTAINED');`;
    requireSuccess(await sandbox('files', code, { mount }), 'CONTAINED'); if (await readFile(marker, 'utf8') !== 'host sentinel') throw new Error('Host sentinel changed.'); return 'Traversal, symlink escape, host secrets, Docker socket and writable root access were denied; host sentinel preserved.';
  });
  await check('unauthorized networking', async () => {
    const code = `import os from 'node:os';import net from 'node:net';import assert from 'node:assert/strict';
      assert.equal(Object.values(os.networkInterfaces()).flat().filter(v=>v&&!v.internal).length,0);
      await new Promise((ok,fail)=>{const socket=net.createConnection({host:'198.18.0.1',port:80});socket.once('connect',()=>{socket.destroy();fail(new Error('Unapproved egress succeeded'));});socket.once('error',()=>ok());socket.setTimeout(3000,()=>{socket.destroy();ok();});});console.log('NETWORK_DENIED');`;
    requireSuccess(await sandbox('network', code), 'NETWORK_DENIED'); return 'The sandbox has no external network interface and cannot reach a non-loopback test endpoint.';
  });
  await check('PID exhaustion', async () => {
    const code = `import {spawn} from 'node:child_process';import assert from 'node:assert/strict';const children=[];let denied=0;let unexpected='';
      for(let i=0;i<384;i++) await new Promise(ok=>{const child=spawn('/bin/sleep',['20'],{stdio:'ignore'});child.once('spawn',()=>{children.push(child);ok();});child.once('error',e=>{if(['EAGAIN','ENOMEM'].includes(e.code))denied++;else unexpected=e.code;ok();});});
      for(const child of children)child.kill('SIGKILL');assert.equal(unexpected,'');assert.ok(denied>0,'PID cap did not reject synthetic children');console.log('PIDS_DENIED');`;
    requireSuccess(await sandbox('pids', code), 'PIDS_DENIED'); return 'A bounded synthetic fork attempt hit the 128-PID cap and all test children were terminated.';
  });
  await check('temporary disk exhaustion', async () => {
    const code = `import fs from 'node:fs';import assert from 'node:assert/strict';const fd=fs.openSync('/tmp/acceptance-fill','w');let stopped=false;
      try{for(let i=0;i<64;i++)fs.writeSync(fd,Buffer.alloc(1024*1024));}catch(e){assert.ok(['ENOSPC','EDQUOT'].includes(e.code));stopped=true;}finally{fs.closeSync(fd);}assert.ok(stopped);console.log('TMPFS_DENIED');`;
    requireSuccess(await sandbox('tmpfs', code, { tmpSize: '32m' }), 'TMPFS_DENIED'); return 'A 32 MiB tmpfs rejected further writes during a bounded 64 MiB attempt.';
  });
  if (!dataDir) results.push({ name: 'persistent storage hard quota', status: 'unavailable', detail: 'Installed data directory and quota helper are unavailable.' });
  else await check('persistent storage hard quota', async () => {
    const quota = await quotaRequest({ appId: id, name: 'acceptance', sizeMb: 32 }); const expected = join(dataDir!, 'runtime/storage', id, 'acceptance');
    if (!quota.quotaEnforced || quota.sizeMb !== 32 || quota.hostPath !== expected || await realpath(quota.hostPath) !== expected) throw new Error('Quota receipt did not match the exact synthetic storage scope.');
    const code = `import fs from 'node:fs';import assert from 'node:assert/strict';let denied=false;const fd=fs.openSync('/workspace/acceptance-fill','w');
      try{for(let i=0;i<64;i++)fs.writeSync(fd,Buffer.alloc(1024*1024));}catch(e){assert.ok(['EDQUOT','ENOSPC'].includes(e.code));denied=true;}finally{fs.closeSync(fd);}assert.ok(denied);console.log('QUOTA_DENIED');`;
    try { requireSuccess(await sandbox('quota', code, { mount: quota.hostPath }), 'QUOTA_DENIED'); } finally { await rm(join(expected, 'acceptance-fill'), { force: true }); }
    return `Exact 32 MiB XFS project quota rejected excess writes. Empty synthetic quota ${id}/acceptance remains registered for audit.`;
  });
  if (!dataDir) results.push({ name: 'bounded build mount', status: 'unavailable', detail: 'Installed build mount unavailable.' });
  else await check('bounded build mount', async () => {
    const value = await statfs(join(dataDir!, 'runtime/builds')); if (Number(value.type) !== 0x01021994 || value.blocks * value.bsize > 2 * 1024 ** 3) throw new Error('Generated builds are not on the expected bounded 2 GiB tmpfs.');
    return 'The actual generated-build root is tmpfs with at most 2 GiB aggregate capacity.';
  });
} catch (error) {
  const detail = String(error instanceof Error ? error.message : error); for (const name of names) if (!results.some(value => value.name === name)) results.push({ name, status: 'unavailable', detail });
} finally {
  for (const container of containers) await docker(['rm', '-f', container], 10000);
  if (workspace) { const actual = await realpath(workspace).catch(() => ''); if (actual && basename(actual).startsWith(`${prefix}-`)) await rm(actual, { recursive: true, force: true }); }
  const status = results.some(value => value.status === 'failed') ? 'failed' : results.some(value => value.status === 'unavailable') ? 'unavailable' : 'passed';
  const report = { schemaVersion: 1, id, checkedAt: new Date().toISOString(), status, toolchainImage: image || null, runtime, results };
  await mkdir(dirname(outputPath), { recursive: true }); await writeFile(outputPath, JSON.stringify(report, null, 2), { mode: 0o600, flag: 'wx' }); console.log(JSON.stringify({ ...report, reportPath: outputPath }, null, 2)); process.exitCode = status === 'passed' ? 0 : status === 'failed' ? 1 : 2;
}
