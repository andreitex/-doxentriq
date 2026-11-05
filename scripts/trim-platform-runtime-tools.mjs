// Company image construction only. The API/worker executes Node directly.
import { lstatSync, realpathSync, readdirSync, rmSync, unlinkSync } from 'node:fs';
import { strict as assert } from 'node:assert';

const directories = ['/usr/local/lib/node_modules/npm', '/usr/local/lib/node_modules/corepack', '/opt/yarn-v1.22.22'];
function present(path) {
  try { return lstatSync(path); } catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
}
const links = [];
for (const name of ['npm', 'npx', 'yarn', 'yarnpkg', 'corepack']) {
  const path = `/usr/local/bin/${name}`, metadata = present(path);
  if (!metadata) continue;
  assert(metadata.isSymbolicLink(), `Unexpected package-manager executable: ${name}`);
  const target = realpathSync(path);
  assert(directories.some(directory => target.startsWith(`${directory}/`)), `Unreviewed package-manager target: ${name}`);
  links.push(path);
}
for (const path of links) unlinkSync(path);
for (const directory of directories) {
  const metadata = present(directory);
  if (!metadata) continue;
  assert(metadata.isDirectory() && !metadata.isSymbolicLink(), 'An ordinary reviewed tool directory is required.');
  assert(readdirSync(directory).includes('package.json'), 'The reviewed tool package manifest is missing.');
  rmSync(directory, { recursive: true });
}
for (const name of ['npm', 'npx', 'yarn', 'yarnpkg', 'corepack']) assert(!present(`/usr/local/bin/${name}`));
console.log('Removed reviewed package-manager tools from the platform runtime image.');
