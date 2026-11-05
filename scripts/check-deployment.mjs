import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { parse } from 'yaml';
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const compose = parse(readFileSync(resolve(root,'deploy/compose.yaml'),'utf8'), {merge:true});
for (const file of readdirSync(resolve(root,'deploy/config'))) {
  if (/\.ya?ml$/.test(file)) parse(readFileSync(resolve(root,'deploy/config',file),'utf8'));
}
for (const [name,service] of Object.entries(compose.services)) {
  assert.match(service.image, /^\$\{[A-Z_]+_IMAGE:\?[^}]*\}$/, `${name} must require a company digest lock`);
  if (name !== 'broker') assert.ok(!(service.volumes ?? []).some(value=>value.includes('/var/run/docker.sock')), `${name} must not receive the Docker socket`);
  assert.equal(service.logging.driver,'journald',`${name} logs must reside in the encrypted seven-day journal`);
  for (const mount of service.tmpfs ?? []) assert.match(mount,/^\/[A-Za-z0-9/_-]+(?::(?:size=[1-9][0-9]*[mg]|mode=[0-7]{4})(?:,(?:size=[1-9][0-9]*[mg]|mode=[0-7]{4}))*)?$/,`${name} tmpfs options must be one absolute-path string; YAML commas must not split mounts`);
}
for (const [name,network] of Object.entries(compose.networks)) {
  if(!['outbound','ingress'].includes(name)) assert.equal(network.internal,true,`${name} must have no external routing`);
}
assert.deepEqual(Object.entries(compose.services).filter(([,service])=>(service.networks??[]).includes('ingress')).map(([name])=>name).sort(),['caddy','registry'],'Only the two trusted ingress services may publish through the ingress bridge');
assert.deepEqual(compose.services.registry.ports,['127.0.0.1:5000:5000'],'Authenticated registry publishing must remain host loopback only');
assert.equal(compose.services.control.environment.BROKER_URL,'https://broker:8090');
assert.equal(compose.services.broker.environment.PACKAGER_URL,'https://packager:8091');
assert.equal(compose.services.control.environment.CONTROL_TLS_KEY_FILE,'/etc/autosoft/tls/control.key');
assert.equal(compose.services.broker.environment.APP_TLS_CA_KEY_FILE,'/run/secrets/app-issuer.key');
assert.ok(!compose.services.packager.volumes.some(value=>value.includes('secrets/runtime')),'Packager must not receive issuer, vault or publication signing keys');
assert.ok(!compose.services.packager.volumes.some(value=>/\/runtime:\/data\/runtime/.test(value)),'Packager must not receive app or connector secret directories');
assert.ok(compose.services.packager.volumes.some(value=>value.includes('/runtime/artifacts:/data/runtime/artifacts:ro')),'Packager must receive only read-only artifacts');
assert.ok(!compose.services.worker.volumes.some(value=>value.includes('secrets/control')),'Worker must not receive security-report or metrics bearer tokens');
assert.ok(compose.services.worker.volumes.some(value=>value.includes('/config/models.json:/etc/autosoft/models.json:ro,z')),'The control and worker model catalog must use a shared SELinux label');
assert.ok(compose.services.otel.volumes.includes('${DATA_DIR:?}/otel-offsets:/var/lib/otel:Z'),'Collector offsets must persist in encrypted writable collector-only storage');
const bootstrap = readFileSync(resolve(root,'scripts/bootstrap.py'),'utf8');
const caddyAdapt = bootstrap.split('\n').find(value=>value.includes('adapted = json.loads(subprocess.check_output'));
assert.ok(caddyAdapt?.includes('"--cap-drop=ALL", "--cap-add=NET_BIND_SERVICE", "--security-opt=no-new-privileges"'),'Official Caddy adapt must retain only its executable file capability under no-new-privileges');
assert.match(bootstrap,/@private path \/metrics \/internal\/\*\s+handle @private \{\{\s+respond 403/,'The private administrative guard must be a matched handle before the catch-all handle');
assert.equal(compose.services.broker.environment.STORAGE_QUOTA_ENFORCED,'1');
const rabbit = readFileSync(resolve(root,'deploy/config/rabbitmq.conf'),'utf8');
assert.ok(!/^management\.tcp\./m.test(rabbit),'Production RabbitMQ must configure only its verified HTTPS management listener; tcp.port=none is invalid');
assert.match(rabbit,/^management\.ssl\.port\s*=\s*15671$/m);
assert.match(rabbit,/^listeners\.tcp\s*=\s*none$/m);
assert.match(rabbit,/^listeners\.ssl\.default\s*=\s*5671$/m);
console.log(`Validated ${Object.keys(compose.services).length} services, TLS boundaries, private networks and secret isolation; Docker/VM execution remains separate.`);
