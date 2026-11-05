import { readFile, writeFile } from 'node:fs/promises';

// Company maintenance helper: extract exact, integrity-pinned dependencies from the
// already-resolved platform lock without contacting a registry or installing packages.
const source = JSON.parse(await readFile(new URL('../../../package-lock.json', import.meta.url), 'utf8'));
const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const packages = { '': { name: manifest.name, version: manifest.version, dependencies: manifest.dependencies, devDependencies: manifest.devDependencies, engines: manifest.engines } };
const visited = new Map();
function location(name, from = '') {
  let parent = from;
  for (;;) {
    const candidate = parent ? `${parent}/node_modules/${name}` : `node_modules/${name}`;
    if (source.packages[candidate]) return candidate;
    const cut = parent.lastIndexOf('/node_modules/');
    if (cut >= 0) { parent = parent.slice(0, cut); continue; }
    if (parent) { parent = ''; continue; } return null;
  }
}
function collect(name, expected, development, from = '') {
  const path = location(name, from); if (!path) throw new Error(`Dependency missing from the existing lock: ${name}`);
  const entry = source.packages[path]; if (from === '' && entry.version !== expected) throw new Error(`Exact dependency mismatch: ${name}`);
  if (visited.get(path) === false || visited.get(path) === development) return;
  visited.set(path, development); const copy = structuredClone(entry); if (development) copy.dev = true; else delete copy.dev; packages[path] = copy;
  for (const [dependency, version] of Object.entries({ ...entry.dependencies, ...entry.optionalDependencies })) {
    if (!location(dependency, path) && entry.optionalDependencies?.[dependency]) continue;
    collect(dependency, version, development, path);
  }
  for (const [dependency, version] of Object.entries(entry.peerDependencies ?? {})) if (location(dependency, path)) collect(dependency, version, development, path);
}
for (const [name, version] of Object.entries(manifest.devDependencies ?? {})) collect(name, version, true);
for (const [name, version] of Object.entries(manifest.dependencies)) collect(name, version, false);
await writeFile(new URL('../package-lock.json', import.meta.url), JSON.stringify({ name: manifest.name, version: manifest.version, lockfileVersion: 3, requires: true, packages }, null, 2) + '\n');
process.stdout.write(`DMS independent lock contains ${Object.keys(packages).length - 1} exact dependency entries.\n`);
