// Trusted company image construction only. This is never given to app builds.
import { strict as assert } from 'node:assert';
import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve } from 'node:path';

const config = JSON.parse(readFileSync('/tmp/npm-toolchain-security-updates.json', 'utf8'));
const temporary = '/tmp/autosoft-reviewed-npm-updates', target = '/usr/local/lib/node_modules/npm';
assert.equal(config.schemaVersion, 1);
assert.equal(config.npmVersion, '12.2.0');
assert.equal(config.packages.length, 5);
assert.equal(JSON.parse(readFileSync(join(target, 'package.json'))).version, config.npmVersion);
const approved = new Map(config.packages.map(p => [p.name, p]));
assert.equal(approved.size, 5);
for (const p of approved.values()) {
  assert.match(p.name, /^[a-z][a-z0-9-]+$/);
  assert.match(p.version, /^\d+\.\d+\.\d+$/);
  assert.match(p.previous, /^\d+\.\d+\.\d+$/);
  assert.match(p.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/);
}
const mode = process.argv[2];
if (mode === 'prepare') {
  assert(!existsSync(temporary));
  mkdirSync(temporary, { mode: 0o700 });
  writeFileSync(join(temporary, 'package.json'), JSON.stringify({ private: true, dependencies: Object.fromEntries(config.packages.map(p => [p.name, p.version])) }));
} else {
  assert.equal(mode, 'apply');
  const lockRaw = readFileSync(join(temporary, 'package-lock.json'));
  const lock = JSON.parse(lockRaw);
  assert.equal(lock.lockfileVersion, 3);
  const allowed = new Set([...approved.keys(), ...config.additionalPublicPackages]);
  for (const [path, p] of Object.entries(lock.packages)) {
    if (!path) continue;
    const name = path.split('node_modules/').at(-1);
    assert(allowed.has(name), 'Unreviewed transitive update');
    assert.equal(p.resolved, `https://registry.npmjs.org/${name}/-/${name}-${p.version}.tgz`);
    assert.match(p.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/);
    assert(!p.link && !p.hasInstallScript);
    if (path === `node_modules/${name}` && approved.has(name)) {
      assert.equal(p.version, approved.get(name).version);
      assert.equal(p.integrity, approved.get(name).integrity);
    }
  }
  const replacements = [];
  function visit(directory) {
    assert(replacements.length < 64);
    for (const row of readdirSync(directory, { withFileTypes: true })) {
      if (!row.isDirectory() || row.isSymbolicLink()) continue;
      const path = join(directory, row.name), manifest = join(path, 'package.json');
      if (existsSync(manifest)) {
        assert(lstatSync(manifest).isFile() && !lstatSync(manifest).isSymbolicLink());
        const p = JSON.parse(readFileSync(manifest));
        if (approved.has(p.name)) {
          assert.equal(p.version, approved.get(p.name).previous);
          replacements.push({ path, name: p.name, previous: p.version, version: approved.get(p.name).version });
          continue;
        }
      }
      visit(path);
    }
  }
  visit(join(target, 'node_modules'));
  assert.equal(new Set(replacements.map(p => p.name)).size, approved.size);
  function validateTree(directory, base, count = { n: 0 }) {
    for (const row of readdirSync(directory, { withFileTypes: true })) {
      assert(++count.n < 20000);
      const path = join(directory, row.name), metadata = lstatSync(path);
      if (metadata.isSymbolicLink()) {
        const resolved = realpathSync(path);
        assert(resolved.startsWith(`${base}/`), 'Dependency link escapes its nested closure');
      } else if (metadata.isDirectory()) validateTree(path, base, count);
      else assert(metadata.isFile() && metadata.nlink === 1 && metadata.size < 8 * 1024 ** 2);
    }
  }
  for (const replacement of replacements) {
    const from = join(temporary, 'node_modules', replacement.name);
    assert.equal(JSON.parse(readFileSync(join(from, 'package.json'))).version, replacement.version);
    validateTree(from, from);
    assert(replacement.path.startsWith(`${target}/node_modules/`) && realpathSync(dirname(replacement.path)).startsWith(`${target}/`));
    assert(!relative(target, replacement.path).startsWith('..'));
    rmSync(replacement.path, { recursive: true });
    cpSync(from, replacement.path, { recursive: true, verbatimSymlinks: true });
  }
  const evidence = '/usr/local/share/autosoft/node-toolchain';
  mkdirSync(evidence, { recursive: true });
  writeFileSync(join(evidence, 'package-lock.json'), lockRaw);
  writeFileSync(join(evidence, 'updates.json'), JSON.stringify({ schemaVersion: 1, npmVersion: config.npmVersion, companyModified: true, lockSha256: createHash('sha256').update(lockRaw).digest('hex'), replacements: replacements.map(p => ({ ...p, path: relative(target, p.path) })), upstreamReview: config.upstreamReview }, null, 2));
  console.log(`Updated ${replacements.length} reviewed npm dependency copies; company scan and DMS qualification remain required.`);
}
