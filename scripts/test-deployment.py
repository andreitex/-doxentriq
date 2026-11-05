#!/usr/bin/env python3
"""Host-independent negative tests for release trust and resource containment."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


images = module('resolve-images')
quotas = module('quota-helper')
releases = module('verify-release')
maintenance = module('maintenance')
bootstrap = module('bootstrap')
OPENSSL = shutil.which('openssl') or (r'C:\Program Files\Git\mingw64\bin\openssl.exe' if os.name == 'nt' and Path(r'C:\Program Files\Git\mingw64\bin\openssl.exe').exists() else None)
BASH = (r'C:\Program Files\Git\bin\bash.exe' if os.name == 'nt' and Path(r'C:\Program Files\Git\bin\bash.exe').exists() else shutil.which('bash'))


class DeploymentPolicy(unittest.TestCase):
    def test_mysql_system_tablespace_encryption_is_only_in_fresh_initializer(self):
        tree = ast.parse((ROOT / 'bootstrap.py').read_text())
        writes = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'write' and len(node.args) >= 2 and isinstance(node.args[0], ast.BinOp) and isinstance(node.args[0].right, ast.Constant) and node.args[0].right.value == 'config/mysql-init.sql']
        self.assertEqual(len(writes), 1)
        value = writes[0].args[1]
        self.assertIsInstance(value, ast.JoinedStr)
        approved = {'mysql_platform', 'mysql_keycloak', 'mysql_provisioner'}
        for item in value.values:
            if isinstance(item, ast.FormattedValue):
                self.assertIsInstance(item.value, ast.Name)
                self.assertIn(item.value.id, approved)
        sql = eval(compile(ast.Expression(value), '<fresh-mysql-init>', 'eval'), {'__builtins__': {}}, {name: 'synthetic-only' for name in approved})
        self.assertEqual(sql.splitlines()[0], "ALTER TABLESPACE mysql ENCRYPTION='Y';")
        self.assertEqual(sql.count('ALTER TABLESPACE mysql'), 1)
        self.assertIn("CREATE DATABASE IF NOT EXISTS platform DEFAULT ENCRYPTION='Y'", sql)
        self.assertIn("CREATE DATABASE IF NOT EXISTS keycloak DEFAULT ENCRYPTION='Y'", sql)
        self.assertFalse(any(word in sql for word in ('DROP ', 'TRUNCATE ', 'REVOKE ', 'ALTER USER ')))
        compose = (ROOT.parent / 'deploy/compose.yaml').read_text()
        self.assertIn('${DATA_DIR:?}/config/mysql-init.sql:/docker-entrypoint-initdb.d/01-autosoft.sql:ro,Z', compose)
        # SQL is generated into the original fresh-datadir hook; no host command
        # or existing-store startup/reconciliation ALTER is added by this change.
        literal_nodes = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str) and 'ALTER TABLESPACE mysql' in node.value]
        self.assertEqual(len(literal_nodes), 1)

    @unittest.skipUnless(BASH, 'Bash not available')
    def test_host_capacity_guard_before_installation(self):
        def check(mode, memory, cpus):
            return subprocess.run([BASH,'-c','source ./scripts/lib.sh; require_host_capacity "$@"','capacity-test',mode,str(memory),str(cpus)],cwd=ROOT.parent,capture_output=True,text=True)
        self.assertEqual(check('full',15*1024**2,4).returncode,0)
        for memory,cpus in ((15*1024**2-1,4),(11*1024**2,4),(16*1024**2,3),('unknown',4),(-1,4)):
            self.assertNotEqual(check('full',memory,cpus).returncode,0)
        self.assertIn('15 GiB MemTotal',check('full',11*1024**2,4).stderr)
        self.assertEqual(check('--foundation-only',4*1024**2,1).returncode,0)
        self.assertNotEqual(check('--foundation-only',4*1024**2-1,4).returncode,0)

    def test_version_tags_are_not_digest_locks(self):
        for value in ('mysql:latest', 'mysql:8.4', 'mysql@sha256:' + 'a'*63, 'mysql@sha256:'+'A'*64, 'mysql@sha256:'+'a'*64+';id'):
            lock = {name: 'example/'+name+'@sha256:'+'a'*64 for name in images.KEYS}
            lock['mysql'] = value
            with self.assertRaises(ValueError):
                images.validate(lock)

    def test_missing_and_additional_service_images_are_rejected(self):
        lock = {name: 'example/'+name+'@sha256:'+'a'*64 for name in images.KEYS}
        images.validate(lock)
        for candidate in ({**lock, 'unapproved': lock['mysql']}, {name:value for name,value in lock.items() if name != 'trivy'}):
            with self.assertRaises(ValueError):
                images.validate(candidate)

    def test_floating_resolver_tags_are_rejected_before_network(self):
        with patch.object(images.subprocess, 'run') as run:
            for value in ('node:latest', 'node:nightly', 'node', 'evil/main'):
                with self.assertRaises(ValueError):
                    images.resolve({'node':value}, complete=False)
            run.assert_not_called()

    def test_private_registry_mirrors_match_only_exact_signed_runtime_images(self):
        base = 'company.example/base-node@sha256:' + 'a'*64
        private = 'registry:5000/base/node@sha256:' + 'a'*64
        connector = 'company.example/samba@sha256:' + 'b'*64
        connector_private = 'registry:5000/connectors/samba@sha256:' + 'b'*64
        manifest = {'templates': {'node-web': {'toolchainImage':base, 'runtimeImage':private}}, 'connectors': {'samba': {'image':connector_private}}}
        lock = {'samba_connector':connector}
        mirrors = [{'sourceImage':base, 'targetImage':private}, {'sourceImage':connector, 'targetImage':connector_private}]
        bootstrap.validate_mirrors(mirrors,manifest,lock)
        for candidate in (mirrors[:1], mirrors+[mirrors[0]], [mirrors[0], {'sourceImage':connector,'targetImage':'registry:5000/connectors/other@sha256:'+'b'*64}], [mirrors[0], {'sourceImage':'other.example/samba@sha256:'+'b'*64,'targetImage':connector_private}], [mirrors[0], {**mirrors[1], 'unapproved':True}]):
            with self.assertRaises(ValueError): bootstrap.validate_mirrors(candidate,manifest,lock)
        with self.assertRaises(ValueError): bootstrap.validate_mirrors(mirrors,manifest,{'samba_connector':'company.example/samba@sha256:'+'c'*64})

    def mirror_fixture(self, folder):
        base='company.example/base-node@sha256:'+'a'*64
        private='registry:5000/base/node@sha256:'+'a'*64
        (folder/'config').mkdir();(folder/'secrets/runtime').mkdir(parents=True)
        (folder/'config/approved-mirrors.json').write_text(json.dumps([dict(sourceImage=base,targetImage=private)]))
        (folder/'config/runtime-manifest.json').write_text(json.dumps(dict(templates={'node-web':dict(toolchainImage=base,runtimeImage=private)})))
        (folder/'config/images.lock.json').write_text('{}')
        (folder/'secrets/runtime/registry.json').write_text(json.dumps(dict(username='fixture',password='synthetic-only')))
        return private

    def test_runtime_mirror_requires_actual_target_proof_not_repo_digests(self):
        with tempfile.TemporaryDirectory(prefix='autosoft-mirror-') as path:
            folder=Path(path);target=self.mirror_fixture(folder)
            with patch.object(bootstrap.subprocess,'run'),patch.object(bootstrap.subprocess,'check_output') as legacy,patch.object(bootstrap,'qualify_registry_manifest',return_value=dict(reference=target,verifiedTLS=True)) as qualify:
                bootstrap.mirror_bases(folder,ROOT.parent)
            legacy.assert_not_called()
            qualify.assert_called_once_with('registry:5000/base/node:approved-'+'a'*16)
            proof=json.loads((folder/'config/runtime-mirror-proof.json').read_text())
            self.assertEqual(proof['images'][0]['reference'],target)

    def test_runtime_mirror_changed_target_proof_blocks_activation(self):
        with tempfile.TemporaryDirectory(prefix='autosoft-mirror-') as path:
            folder=Path(path);self.mirror_fixture(folder)
            with patch.object(bootstrap.subprocess,'run'),patch.object(bootstrap,'qualify_registry_manifest',return_value=dict(reference='registry:5000/base/node@sha256:'+'b'*64)):
                with self.assertRaisesRegex(ValueError,'signed manifest digest'):bootstrap.mirror_bases(folder,ROOT.parent)
            self.assertFalse((folder/'config/runtime-mirror-proof.json').exists())

    def test_collector_offsets_preserve_foreign_file_or_unsafe_directory(self):
        for kind in ('file','directory'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix='autosoft-offsets-') as path:
                folder=Path(path);offsets=folder/'otel-offsets'
                if kind=='file':offsets.write_text('existing-state-must-remain')
                else:offsets.mkdir(mode=0o777)
                before=offsets.stat()
                with patch.object(bootstrap.subprocess,'run') as run:
                    with self.assertRaisesRegex(ValueError,'unsafe existing collector'):bootstrap.render(folder,ROOT.parent)
                    run.assert_not_called()
                after=offsets.stat()
                self.assertEqual((before.st_mode,before.st_uid,before.st_gid),(after.st_mode,after.st_uid,after.st_gid))
                if kind=='file':self.assertEqual(offsets.read_text(),'existing-state-must-remain')

    def test_storage_boundary_rejects_paths_oversize_and_noninteger(self):
        valid = {'appId':'3eb98ff3-5855-4933-aa59-3c7399949839', 'name':'documents', 'sizeMb':512}
        self.assertEqual(quotas.validate_request(valid), valid)
        for change in ({'appId':'../../secrets'}, {'name':'../../mysql'}, {'name':'a/b'}, {'sizeMb':0}, {'sizeMb':32769}, {'sizeMb':True}, {'sizeMb':1.5}, {'hostPath':'/'}):
            with self.assertRaises((ValueError, TypeError, AttributeError)):
                quotas.validate_request({**valid, **change})

    def test_filesystem_and_samba_mirrors_cannot_cross_connector_or_image_scope(self):
        base='company.example/node@sha256:'+'a'*64
        samba='company.example/samba@sha256:'+'b'*64
        filesystem='company.example/filesystem@sha256:'+'c'*64
        manifest={'templates':{'node-web':{'toolchainImage':base,'runtimeImage':'registry:5000/base/node@sha256:'+'a'*64}},'connectors':{'samba':{'image':'registry:5000/connectors/samba@sha256:'+'b'*64},'filesystem':{'image':'registry:5000/connectors/filesystem@sha256:'+'c'*64}}}
        lock={'samba_connector':samba,'filesystem_connector':filesystem}
        mirrors=[{'sourceImage':base,'targetImage':manifest['templates']['node-web']['runtimeImage']},{'sourceImage':samba,'targetImage':manifest['connectors']['samba']['image']},{'sourceImage':filesystem,'targetImage':manifest['connectors']['filesystem']['image']}]
        bootstrap.validate_mirrors(mirrors,manifest,lock)
        for candidate in (mirrors[:2],mirrors+[mirrors[-1]],[*mirrors[:2],{'sourceImage':filesystem,'targetImage':'registry:5000/connectors/samba@sha256:'+'c'*64}]):
            with self.assertRaises(ValueError):bootstrap.validate_mirrors(candidate,manifest,lock)
        for invalid in ({**lock,'filesystem_connector':samba},{**lock,'filesystem_connector':None}):
            with self.assertRaises(ValueError):bootstrap.validate_mirrors(mirrors,manifest,invalid)
        for connectors in ({**manifest['connectors'],'unreviewed':manifest['connectors']['filesystem']},[]):
            with self.assertRaises(ValueError):bootstrap.validate_mirrors(mirrors,{**manifest,'connectors':connectors},lock)

    def test_only_medium_and_higher_package_findings_are_reported(self):
        report = {'Results':[{'Vulnerabilities':[{'VulnerabilityID':'TEST-'+severity,'Severity':severity,'PkgName':'fixture','InstalledVersion':'1','FixedVersion':'2','PrimaryURL':'https://vendor.invalid/advisory'} for severity in ('LOW','MEDIUM','HIGH','CRITICAL')]}]}
        self.assertEqual([item['severity'] for item in maintenance.Maintenance.findings(report)], ['MEDIUM','HIGH','CRITICAL'])

    def image_gate(self, severity):
        """Exercise the real daily gate without Docker or external advisories."""
        with tempfile.TemporaryDirectory(prefix='policy-test-', dir=ROOT) as temporary:
            task = maintenance.Maintenance.__new__(maintenance.Maintenance)
            task.data = Path(temporary)
            (task.data / 'config').mkdir()
            image = 'example/runtime@sha256:' + 'a'*64
            task.images = {'platform': image}
            (task.data / 'config/runtime-manifest.json').write_text(json.dumps({'scannerImage': image, 'templates': {}}))
            (task.data / 'config/approved-mirrors.json').write_text('[]')
            finding = dict(VulnerabilityID='TEST-UNCLASSIFIED', PkgName='fixture', InstalledVersion='1')
            if severity != 'missing-field':
                finding['Severity'] = severity
            task.feed = lambda: '2026-10-11T00:00:00Z'
            task.scan_image = lambda _: {'Results': [{'Vulnerabilities': [finding]}], 'Metadata': {'OS': {'Family': 'alpine'}}}
            task.scan_host_packages = lambda: {'Results': [{'Vulnerabilities': []}], 'Metadata': {'OS': {'Family': 'rocky'}}}
            reports = []
            with patch.object(maintenance, 'run', return_value=subprocess.CompletedProcess([], 0)), \
                 patch.object(maintenance, 'check_running_kernel', return_value={'coverage': {'name': 'host-running-kernel-vendor-advisories', 'status': 'passed'}, 'findings': []}), \
                 patch.object(maintenance, 'write', side_effect=lambda path, value: reports.append((path, value))), \
                 patch('builtins.print'):
                try:
                    task.security('--gate')
                    blocked = False
                except ValueError as error:
                    self.assertIn('Initial security gate failed', str(error))
                    blocked = True
            report = next(value for path, value in reports if path.name == 'latest-host.json')
            image_coverage = next(item for item in report['coverage'] if item['name'].startswith('image:'))
            return blocked, image_coverage

    def test_daily_image_gate_blocks_any_unclassified_advisory_severity(self):
        for severity in ('UNKNOWN', 'UNRATED', '', None, 'missing-field'):
            with self.subTest(severity=severity):
                blocked, coverage = self.image_gate(severity)
                self.assertTrue(blocked)
                self.assertEqual(coverage['status'], 'unavailable')
                self.assertIn('incomplete', coverage['detail'])

    def test_daily_image_gate_allows_low_only_and_blocks_medium_or_higher(self):
        blocked, coverage = self.image_gate('LOW')
        self.assertFalse(blocked)
        self.assertEqual(coverage['status'], 'passed')
        for severity in ('MEDIUM', 'HIGH', 'CRITICAL'):
            with self.subTest(severity=severity):
                blocked, coverage = self.image_gate(severity)
                self.assertTrue(blocked)
                self.assertEqual(coverage['status'], 'failed')

    def test_kernel_advisory_query_is_fresh_scoped_and_rejects_other_paths(self):
        with tempfile.TemporaryDirectory(prefix='policy-test-', dir=ROOT) as temporary, patch.object(maintenance, 'scanner_input_directory', side_effect=lambda data, *, prefix: tempfile.TemporaryDirectory(dir=data/'security', prefix=prefix)):
            task = maintenance.Maintenance.__new__(maintenance.Maintenance)
            task.data = Path(temporary)
            (task.data/'security').mkdir()
            sentinel = task.data/'security/retained-package-inventory'
            sentinel.write_text('preserve original metadata')
            query = {'etc/os-release':'ID=debian\nVERSION_ID="12"\n', 'var/lib/dpkg/status':'Package: linux-image-fixture\nSource: linux (1)\n'}
            captured = []
            def scan(arguments, mounts):
                self.assertIn('--offline-scan', arguments)
                self.assertIn('--skip-db-update', arguments)
                self.assertIn('--skip-java-db-update', arguments)
                self.assertIn('--list-all-pkgs', arguments)
                self.assertEqual(len(mounts), 1)
                inventory, target = mounts[0]
                self.assertEqual(target, '/inventory')
                self.assertEqual(inventory.parent, task.data/'security')
                self.assertEqual({name: (inventory/name).read_text() for name in query}, query)
                captured.append(inventory)
                return '{"Results":[]}'
            task.scanner = scan
            self.assertEqual(task.scan_kernel_source(query), {'Results':[]})
            self.assertFalse(captured[0].exists())
            self.assertEqual(sentinel.read_text(), 'preserve original metadata')
            for invalid in ({'../status':'escape'}, {**query, '/etc/shadow':'forbidden'}, {**query, 'etc/os-release':'x'*16385}, {**query, 'var/lib/dpkg/status':None}):
                with self.subTest(invalid=list(invalid)), self.assertRaises(ValueError):
                    task.scan_kernel_source(invalid)
            self.assertEqual(len(captured), 1)

    def test_host_package_scan_uses_fresh_snapshot_and_rejects_uncertain_copy(self):
        with tempfile.TemporaryDirectory(prefix='policy-test-', dir=ROOT) as temporary, patch.object(maintenance, 'scanner_input_directory', side_effect=lambda data, *, prefix: tempfile.TemporaryDirectory(dir=data/'security', prefix=prefix)):
            folder = Path(temporary).resolve()
            (folder / 'security/history').mkdir(parents=True)
            stale = folder / 'security/host-inventory'
            stale.mkdir()
            (stale / 'sentinel').write_text('prior evidence stays unchanged')
            task = maintenance.Maintenance.__new__(maintenance.Maintenance)
            task.data = folder
            captured = []
            def snapshot(destination):
                self.assertEqual(destination.parent, folder / 'security')
                self.assertNotEqual(destination, stale)
                self.assertEqual(list(destination.iterdir()), [])
                (destination / 'fixed-metadata').write_text('synthetic inventory')
                captured.append(destination)
                return dict(distribution=dict(family='rocky', version='10.2'), files={}, fileCount=1, totalBytes=19)
            def scanner(arguments, mounts):
                self.assertEqual(mounts, [(captured[-1], '/inventory')])
                for option in ('--list-all-pkgs', '--skip-db-update', '--skip-java-db-update', '--offline-scan'):
                    self.assertIn(option, arguments)
                self.assertEqual((captured[-1] / 'fixed-metadata').read_text(), 'synthetic inventory')
                return json.dumps(dict(Results=[], fixtureOnly=True))
            with patch.object(maintenance, 'snapshot_host_packages', side_effect=snapshot) as copy, patch.object(task, 'scanner', side_effect=scanner) as scan:
                self.assertTrue(task.scan_host_packages()['fixtureOnly'])
                self.assertEqual(copy.call_count, 1)
                self.assertEqual(scan.call_count, 1)
            self.assertFalse(captured[0].exists())
            self.assertEqual((stale / 'sentinel').read_text(), 'prior evidence stays unchanged')
            history = list((folder / 'security/history').glob('host-inventory-*.json'))
            self.assertEqual(len(history), 1)
            self.assertEqual(json.loads(history[0].read_text())['distribution']['family'], 'rocky')
            with patch.object(maintenance, 'snapshot_host_packages', side_effect=ValueError('rpm-transaction-journal-replay-unavailable')), patch.object(task, 'scanner') as scan:
                with self.assertRaises(ValueError):
                    task.scan_host_packages()
                scan.assert_not_called()
            self.assertEqual(len(list((folder / 'security/history').glob('host-inventory-*.json'))), 1)

    def test_checkpoint_inventory_is_complete_and_tmpfs_scope_is_exact(self):
        self.assertTrue(maintenance.checkpoint_ephemeral('runtime/builds/job/source.mjs'))
        self.assertFalse(maintenance.checkpoint_ephemeral('workspaces/app/runtime/builds/source.mjs'))
        self.assertTrue(maintenance.checkpoint_ephemeral('mysql/mysql.sock'))
        self.assertFalse(maintenance.checkpoint_ephemeral('runtime/storage/app1/documents/mysql/mysql.sock'))
        with tempfile.TemporaryDirectory(prefix='policy-test-',dir=ROOT) as temporary:
            folder=Path(temporary)
            (folder/'manifest.json').write_text('{}')
            source=folder/'workspaces/app/runtime/builds/source.mjs'
            source.parent.mkdir(parents=True)
            source.write_text('reviewed source')
            expected={'workspaces/app/runtime/builds/source.mjs':hashlib.sha256(source.read_bytes()).hexdigest()}
            maintenance.verify_checkpoint_files(folder,expected)
            extra=folder/'unexpected'
            extra.write_text('unlisted')
            with self.assertRaises(ValueError): maintenance.verify_checkpoint_files(folder,expected)
            extra.unlink()
            source.write_text('changed')
            with self.assertRaises(ValueError): maintenance.verify_checkpoint_files(folder,expected)

    def test_daily_security_rejects_another_release_identity(self):
        task=maintenance.Maintenance.__new__(maintenance.Maintenance)
        task.data=Path('/encrypted')
        task.root=Path('/company-source')
        task.images={'platform':'example/platform@sha256:'+'a'*64}
        release=dict(appId='fixture-app',id='fixture-release',commit='a'*40,images=['example/app@sha256:'+'b'*64])
        returned=dict(subject='app',appId='other-app',releaseId=release['id'],status='passed')
        with patch.object(maintenance,'read_daily_security',return_value=json.dumps(returned).encode()) as capture, patch.object(maintenance,'run') as old_capture:
            with self.assertRaisesRegex(ValueError,'report identity mismatch'): task.app_security(release)
            self.assertEqual(capture.call_count,1)
            old_capture.assert_not_called()

    def test_signed_release_rejects_wrong_trust_root_and_tampered_payload(self):
        # Schema1 is an explicitly named inspection API, never source authority.
        spec = importlib.util.spec_from_file_location('signed_release_fixture', ROOT / 'test-company-release.py')
        fixture_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture_module)
        fixture = fixture_module.Fixture(releases)
        fixture.refresh(legacy=True)
        args = dict(expected_architecture='x86_64', files=fixture.files, crypto=fixture.crypto)
        with self.assertRaises(ValueError):
            releases.verify(fixture.bundle, fixture.public, fixture.fingerprint, source_root=fixture.sources, **args)
        result = releases.inspect_legacy_images(fixture.bundle, fixture.public, fixture.fingerprint, **args)
        self.assertEqual(result['status'], 'LEGACY_IMAGE_BUNDLE_INSPECTION_ONLY')
        self.assertIs(result['sourceAuthenticated'], False)
        self.assertIs(result['productionAuthorized'], False)
        with self.assertRaises(ValueError):
            releases.inspect_legacy_images(fixture.bundle, fixture.public, '0'*64, **args)
        (fixture.bundle/'runtime-manifest.json').write_bytes(b'{"tampered":true}')
        with self.assertRaises(ValueError):
            releases.inspect_legacy_images(fixture.bundle, fixture.public, fixture.fingerprint, **args)
        self.assertFalse(fixture.files.records)


if __name__ == '__main__':
    unittest.main()
