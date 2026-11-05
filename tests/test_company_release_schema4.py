"""Injected schema4 authentication/producer controls; no company signing or native."""
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name,path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec);sys.modules[name] = module
    spec.loader.exec_module(module);return module


T = load('schema4_legacy_fixture',ROOT/'scripts/test-company-release.py')


class Fixture(T.DeploymentFixture):
    def __init__(self,V,P):
        super().__init__(V);self.P = P
        self.values = {name:(self.sources/name).read_bytes() for name in (*V.COMPANY_SOURCES,*V.COMPANY_DEPLOYMENT)}
        for name in P.REQUIRED_ANCHORS: self.values.setdefault(name,b'inert platform fixture\n')
        for source_root in P.SOURCE_ROOTS:self.values.setdefault(source_root+'/schema4-fixture.txt',b'fixture\n')
        self.values['scripts/platform_source.py'] = (ROOT/'scripts/platform_source.py').read_bytes()
        self.values['docs/empty-fixture.txt'] = b''
        self.modes = {name:'100644' for name in self.values};self.modes['scripts/sign-company-release.sh'] = '100755'
        self.refresh_platform()
    def refresh_platform(self):
        tree = self.P._tree([(name,self.modes[name],self.P._blob(self.values[name])) for name in sorted(self.values)])
        self.captured = self.P._build('a'*40,tree,self.values,self.modes)
        for name,raw in self.values.items():
            path = self.sources/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        (self.bundle/'platform-sources.json').write_bytes(self.captured.manifest_bytes)
        (self.bundle/'platform-sources.tar.gz').write_bytes(self.captured.archive_bytes)
        # Rebuild54 manifests from exactly the bytes in the full artifact.
        (self.bundle/'company-sources.json').write_bytes(self.V.canonical(self.manifest()))
        (self.bundle/'company-deployment.json').write_bytes(self.V.canonical(self.deployment()))
        self.refresh_release()
    def refresh_release(self):
        entries = {}
        for name in self.V.SIGNED_PLATFORM_FILES:
            raw=(self.bundle/name).read_bytes();entries[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        self.release=dict(schemaVersion=4,version='fixture-4',architecture='x86_64',createdAt='2026-10-13T01:00:00Z',files=entries)
        self.write_release(self.release)
    def held(self,**kwargs):
        args=dict(expected_architecture='x86_64',source_root=self.sources,files=self.files,crypto=self.crypto)
        args.update(kwargs);return self.V.authenticated_platform_source(self.bundle,self.public,self.fingerprint,**args)
    def station(self):
        # Explicit already-trusted pure module injection; never source-path import.
        return SimpleNamespace(verify_archive=self.P.verify_archive,captured_source_bytes=self.values['scripts/platform_source.py'])


class Controls(unittest.TestCase):
    def setUp(self):
        self.V=load('schema4_verifier',ROOT/'scripts/verify-release.py')
        self.P=load('schema4_platform_source',ROOT/'scripts/platform_source.py')
        self.F=Fixture(self.V,self.P)
    def clean(self):self.assertFalse(self.F.files.records);self.assertFalse(self.F.files.dirs)
    def freeze_change(self,path):
        self.F.files.frozen[path]=self.F.files.lstat(path)
        raw=path.read_bytes();path.write_bytes(bytes([raw[0]^1])+raw[1:])
    def test_exact_signed_complete_archive_and_zero_byte_source(self):
        with self.F.held() as held:
            self.assertEqual(dict(held.files),self.F.values);self.assertEqual(dict(held.git_modes),self.F.modes)
            self.assertEqual(held.files['docs/empty-fixture.txt'],b'')
            self.assertEqual(set(held.configs),set(self.V.SIGNED_PLATFORM_FILES)-{'platform-sources.tar.gz'})
            self.assertEqual(held.metadata['fileCount'],len(self.F.values))
            for name in ('productionAuthorized','nativeAuthorized','installerActivated','producerCompletenessIndependentlyProven'):
                self.assertIs(held.metadata[name],False)
            self.assertEqual(held.provenance['release.json'],self.F.crypto.calls[0][0])
            self.assertEqual(held.provenance['release.sig'],self.F.crypto.calls[0][1])
        self.clean()
    def test_signature_failure_precedes_json_helper_and_archive(self):
        self.F.crypto.accept=False
        with patch.object(self.V,'decode',side_effect=AssertionError('parse before signature')),patch.object(self.V,'verified_platform_helper',side_effect=AssertionError('helper before signature')):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.F.held():self.fail('yield')
        opened=[e[1] for e in self.F.files.events if e[0]=='open' and not e[2]]
        self.assertNotIn(str(self.F.bundle/'platform-sources.tar.gz'),opened);self.clean()
    def test_fingerprint_and_architecture_refusal_before_helper(self):
        for kind in ('fingerprint','architecture'):
            self.F=Fixture(self.V,self.P)
            with patch.object(self.V,'verified_platform_helper',side_effect=AssertionError('helper')):
                with self.assertRaises(self.V.ReleaseUnavailable):
                    if kind=='fingerprint':
                        with self.V.authenticated_platform_source(self.F.bundle,self.F.public,'0'*64,expected_architecture='x86_64',source_root=self.F.sources,files=self.F.files,crypto=self.F.crypto):self.fail('yield')
                    else:
                        with self.F.held(expected_architecture='amd64'):self.fail('yield')
            self.clean()
    def test_exact_seven_roles_strict_types_no_schema_fallback(self):
        for mutate in (lambda r:r['files'].pop('platform-sources.tar.gz'),lambda r:r['files'].update(extra={'bytes':1,'sha256':'a'*64}),lambda r:r.update(schemaVersion=True),lambda r:r['files']['platform-sources.json'].update(bytes=True),lambda r:r.update(architecture='amd64')):
            r=copy.deepcopy(self.F.release);mutate(r)
            with self.assertRaises(self.V.ReleaseUnavailable):self.V.validate_platform_release(r,'x86_64')
        with self.assertRaises(self.V.ReleaseUnavailable):self.V.validate_release(self.F.release,'x86_64',schema=3)
    def test_signed_archive_hash_tamper_never_executes_helper(self):
        path=self.F.bundle/'platform-sources.tar.gz';raw=path.read_bytes();path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
        with patch.object(self.V,'verified_platform_helper',side_effect=AssertionError('helper')):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.F.held():self.fail('yield')
        self.clean()
    def test_archive_and_manifest_pin_disagreement_denied_before_helper(self):
        manifest=json.loads((self.F.bundle/'platform-sources.json').read_bytes());manifest['archive']['sha256']='0'*64
        (self.F.bundle/'platform-sources.json').write_bytes(self.V.canonical(manifest));self.F.refresh_release()
        with patch.object(self.V,'verified_platform_helper',side_effect=AssertionError('helper')):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.F.held():self.fail('yield')
        self.clean()
    def test_header_boolean_count_duplicate_case_and_traversal_refused(self):
        raw=self.F.captured.manifest_bytes
        for change in (lambda m:m.update(fileCount=True),lambda m:m.update(policyVersion=True),lambda m:m['files'][0].update(bytes=True),lambda m:m['files'][0].update(path='../escape'),lambda m:m['files'][1].update(path=m['files'][0]['path']),lambda m:m['files'][0].update(gitMode='120000'),lambda m:m.update(extra=1)):
            m=json.loads(raw);change(m)
            with self.assertRaises(self.V.ReleaseUnavailable):self.V.platform_manifest_header(self.V.canonical(m))
    def test_unsigned_canonical_json_and_missing_helper_refused(self):
        m=json.loads(self.F.captured.manifest_bytes);m['files']=[r for r in m['files'] if r['path']!='scripts/platform_source.py'];m['fileCount']=len(m['files']);m['totalBytes']=sum(r['bytes'] for r in m['files'])
        (self.F.bundle/'platform-sources.json').write_bytes(self.V.canonical(m));self.F.refresh_release()
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held():self.fail('yield')
        self.clean()
    def test_protected_helper_hash_and_git_mode_bind_before_exec(self):
        for kind in ('bytes','mode'):
            self.F=Fixture(self.V,self.P);path=self.F.sources/'scripts/platform_source.py'
            if kind=='bytes':path.write_bytes(path.read_bytes()+b'\n')
            else:self.F.files.changes[path]={'st_mode':stat.S_IFREG|0o755}
            with patch.object(self.V,'verified_platform_helper',side_effect=AssertionError('helper')):
                with self.assertRaises(self.V.ReleaseUnavailable):
                    with self.F.held():self.fail('yield')
            self.clean()
    def test_helper_candidate_sibling_import_is_refused(self):
        with self.assertRaises(self.V.ReleaseUnavailable):self.V.verified_platform_helper(b'import company_source\n')
        with self.assertRaises(self.V.ReleaseUnavailable):self.V.verified_platform_helper(b'from . import candidate\n')
    def test_host_and_template_cross_binding_cannot_be_redefined_by_archive(self):
        for name in ('scripts/bootstrap.py','deploy/compose.yaml'):
            self.F=Fixture(self.V,self.P)
            manifest_name='company-sources.json' if name.startswith('scripts/') else 'company-deployment.json'
            m=json.loads((self.F.bundle/manifest_name).read_bytes());next(r for r in m['files'] if r['path']==name)['sha256']='0'*64
            (self.F.bundle/manifest_name).write_bytes(self.V.canonical(m));self.F.refresh_release()
            with self.assertRaises((self.V.ReleaseUnavailable,ValueError)):
                with self.F.held():self.fail('yield')
            self.clean()
    def test_missing_nonhost_anchor_refused_by_authenticated_parser(self):
        self.F.values.pop('packages/core/package.json');self.F.modes.pop('packages/core/package.json')
        with self.assertRaises(ValueError):self.P._build('a'*40,'b'*40,self.F.values,self.F.modes)
    def test_getters_recheck_archive_content_with_unchanged_metadata(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held() as held:
                self.freeze_change(self.F.bundle/'platform-sources.tar.gz');held.files
        self.assertFalse(held.active);self.clean()
    def test_key_helper_and_bundle_drift_after_yield_denied(self):
        for name in ('key','helper','release'):
            self.F=Fixture(self.V,self.P)
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.F.held() as held:
                    path=self.F.public if name=='key' else self.F.sources/'scripts/platform_source.py' if name=='helper' else self.F.bundle/'release.json'
                    self.freeze_change(path);held.recheck()
            self.assertFalse(held.active);self.clean()
    def test_archive_inode_replacement_before_context_exit_denied(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held():
                path=self.F.bundle/'platform-sources.tar.gz';self.F.files.changes[path]={'st_ino':self.F.files.lstat(path).st_ino+1}
        self.clean()
    def test_capability_expires_normal_and_caller_exception(self):
        for fail in (False,True):
            self.F=Fixture(self.V,self.P)
            try:
                with self.F.held() as held:
                    if fail:raise RuntimeError('caller')
            except RuntimeError:self.assertTrue(fail)
            self.assertFalse(held.active)
            with self.assertRaises(self.V.ReleaseUnavailable):held.files
            self.clean()
    def test_immutable_deep_maps_and_no_mutable_alias(self):
        with self.F.held() as held:
            with self.assertRaises(TypeError):held.files['extra']=b'x'
            with self.assertRaises(TypeError):held.git_modes['docs/empty-fixture.txt']='100755'
            with self.assertRaises(TypeError):held.metadata['release']['files']['platform-sources.json']['bytes']=1
            with self.assertRaises(AttributeError):held.files={}
            values=dict(held.files);modes=dict(held.git_modes)
            metadata=dict(held.metadata);metadata['release']=json.loads(held.provenance['release.json'])
            cloned=self.V.HeldPlatformSource(values,modes,dict(held.configs),dict(held.provenance),metadata,lambda:None)
            values['extra']=b'x';modes['extra']='100755';self.assertNotIn('extra',cloned.files);cloned._expire()
        self.clean()
    def test_failed_close_latches_and_expires_capability(self):
        self.F.files.fail_close=self.F.bundle/'platform-sources.tar.gz'
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held() as held:pass
        self.assertFalse(held.active);self.assertTrue(self.V.UNRELEASED_HANDLES)
        with patch.object(self.F.files,'open',side_effect=AssertionError('new open after unknown')):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.F.held():self.fail('yield')
        # Test fixture cleanup only; no production retry of uncertain numeric FDs.
        for fd in tuple(self.F.files.records):os.close(fd)
        self.F.files.records.clear();self.V.UNRELEASED_HANDLES.clear()
    def test_dedicated_large_archive_cap_without_weakening_small_snapshot(self):
        path=self.F.bundle/'platform-sources.tar.gz';self.F.files.changes[path]={'st_size':self.V.PLATFORM_ARCHIVE_LIMIT+1}
        before=len([e for e in self.F.files.events if e[0]=='open' and not e[2]])
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.V.PlatformArchiveSnapshot(self.F.bundle,self.F.files,0,0) as large:large.read_archive()
        self.assertEqual(len([e for e in self.F.files.events if e[0]=='open' and not e[2]]),before)
        self.assertEqual(self.V.SOURCE_TOTAL_LIMIT,16*1024**2);self.clean()
    def test_unsigned_snapshot_retains_exact_eight_files_without_crypto(self):
        target=self.F.root/'unsigned-target';target.mkdir();self.F.files.changes[target]={'st_mode':stat.S_IFDIR|0o700}
        writer=T.FixtureWrites(self.F.files)
        with patch.object(self.V,'verified_platform_helper',side_effect=AssertionError('candidate helper execution')):
            self.V.platform_signing_snapshot(self.F.bundle,target,source_root=self.F.sources,platform_module=self.F.station(),files=self.F.files,writer=writer)
        self.assertEqual(set(os.listdir(target)),{'release.json',*self.V.SIGNED_PLATFORM_FILES})
        for name in os.listdir(target):self.assertEqual((target/name).read_bytes(),(self.F.bundle/name).read_bytes())
        self.assertEqual(self.F.crypto.calls,[]);self.clean()
    def test_unsigned_snapshot_sync_failure_preserves_partial(self):
        target=self.F.root/'unsigned-partial';target.mkdir();self.F.files.changes[target]={'st_mode':stat.S_IFDIR|0o700}
        writer=T.FixtureWrites(self.F.files);writer.fail_sync=True
        with self.assertRaises(OSError):self.V.platform_signing_snapshot(self.F.bundle,target,source_root=self.F.sources,platform_module=self.F.station(),files=self.F.files,writer=writer)
        self.assertTrue(os.listdir(target));self.clean()
        with self.assertRaises(self.V.ReleaseUnavailable):self.V.platform_signing_snapshot(self.F.bundle,target,source_root=self.F.sources,platform_module=self.F.station(),files=self.F.files,writer=T.FixtureWrites(self.F.files))
    def test_unsigned_module_requires_exact_trusted_station_capture(self):
        target=self.F.root/'unsigned-module';target.mkdir();self.F.files.changes[target]={'st_mode':stat.S_IFDIR|0o700}
        with self.assertRaises(self.V.ReleaseUnavailable):self.V.platform_signing_snapshot(self.F.bundle,target,source_root=self.F.sources,platform_module=SimpleNamespace(verify_archive=self.P.verify_archive,captured_source_bytes=b'foreign'),files=self.F.files,writer=T.FixtureWrites(self.F.files))
        self.assertEqual(os.listdir(target),[]);self.clean()
    def test_source_root_is_explicit_not_ambient_default(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held(source_root=None):self.fail('yield')
        self.assertEqual(self.F.files.events,[])
    def test_signer_selector_preserves_old_modes_and_no_current_repo_signing(self):
        raw=(ROOT/'scripts/sign-company-release.sh').read_text()
        self.assertIn('--complete-platform-source SOURCE_ROOT',raw);self.assertIn('--complete-deployment',raw)
        self.assertIn('SNAPSHOT_ARGS+=(--complete-platform-source --source-root "$SOURCE_ROOT")',raw)
        self.assertIn('"$SNAPSHOT/platform-sources.tar.gz"',raw)

    def test_readonly_directory_all_nine_fields_drift_expire_held_input(self):
        for field in ('st_size','st_nlink','st_mtime_ns','st_ctime_ns'):
            for role in ('bundle','key','helper','ancestor'):
                self.F=Fixture(self.V,self.P)
                path={'bundle':self.F.bundle,'key':self.F.keys,'helper':self.F.sources/'scripts','ancestor':self.F.root}[role]
                with self.assertRaises(self.V.ReleaseUnavailable):
                    with self.F.held() as held:
                        self.F.files.changes[path]={field:getattr(self.F.files.lstat(path),field)+1}
                        held.recheck()
                self.assertFalse(held.active);self.clean()

    def test_input_directory_close_failure_attempts_all_and_latches_unknown(self):
        self.F.files.fail_close=self.F.keys
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held() as held:pass
        self.assertFalse(held.active);self.assertFalse(self.F.files.records)
        self.assertEqual(len(self.F.files.dirs),1);self.assertTrue(self.V.UNRELEASED_HANDLES)
        with patch.object(self.F.files,'open',side_effect=AssertionError('open after unknown input close')):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.F.held():self.fail('yield')
        # Release only the injected fixture's synthetic retained directory token.
        self.F.files.dirs.clear();self.V.UNRELEASED_HANDLES.clear()

    def test_unsigned_output_extra_leaf_denied_and_partial_preserved(self):
        target=self.F.root/'unsigned-extra';target.mkdir();self.F.files.changes[target]={'st_mode':stat.S_IFDIR|0o700}
        writer=T.FixtureWrites(self.F.files);written=[]
        def extra(fd,raw):
            if not written:
                (target/'unknown').write_bytes(b'inert unexpected fixture');written.append(True)
        writer.on_write=extra
        with self.assertRaises(self.V.ReleaseUnavailable):
            self.V.platform_signing_snapshot(self.F.bundle,target,source_root=self.F.sources,platform_module=self.F.station(),files=self.F.files,writer=writer)
        self.assertEqual(set(os.listdir(target)),{'release.json','unknown'});self.clean()

    def test_unsigned_output_inventory_duplicate_and_unknown_types_denied(self):
        for bad in (['release.json','release.json'],[True],['unknown']):
            self.F=Fixture(self.V,self.P)
            target=self.F.root/'unsigned-inventory';target.mkdir();self.F.files.changes[target]={'st_mode':stat.S_IFDIR|0o700}
            writer=T.FixtureWrites(self.F.files);actual=writer.inventory;calls=[]
            def inventory(parent):
                calls.append(True)
                return actual(parent) if len(calls)==1 else bad
            writer.inventory=inventory
            with self.assertRaises(self.V.ReleaseUnavailable):
                self.V.platform_signing_snapshot(self.F.bundle,target,source_root=self.F.sources,platform_module=self.F.station(),files=self.F.files,writer=writer)
            self.assertEqual(os.listdir(target),[]);self.clean()


class ProducerControls(unittest.TestCase):
    setUp = Controls.setUp
    # Keep only producer controls in this class; inherited consumer controls are
    # collected exactly once by the explicit suite below.
    def producer(self,callback=None):
        B=load('schema4_producer',ROOT/'scripts/release-manifest.py');events=[]
        P=self.P;captured=self.F.captured
        @contextmanager
        def capture(root,revision,**kwargs):
            events.append(('capture',root,revision,kwargs))
            yield SimpleNamespace(files=captured.files,git_modes=captured.git_modes,manifest_bytes=captured.manifest_bytes,archive_bytes=captured.archive_bytes,recheck=lambda:events.append(('recheck',)))
        platform=SimpleNamespace(capture_git_revision=capture,verify_archive=P.verify_archive)
        def measure(directory,*,paths,**kwargs):
            events.append(('config-measure',tuple(paths)))
            return {'files':[dict(path=name,bytes=len((directory/name).read_bytes()),sha256=hashlib.sha256((directory/name).read_bytes()).hexdigest()) for name in paths]}
        source=SimpleNamespace(INSTALLER_RUNTIME_SOURCES=B.PLATFORM_HOST_SOURCES,create=measure)
        directory=self.F.root/'producer';directory.mkdir()
        for name in self.V.DEPLOYMENT_FILES:(directory/name).write_bytes((self.F.bundle/name).read_bytes())
        kwargs=dict(revision='a'*40,git=object(),platform_module=platform,source_module=source,created_at='2026-10-13T01:00:00Z')
        return B,directory,events,kwargs
    def test_builder_derives_host_and_template_rows_from_one_capture(self):
        B,directory,events,kwargs=self.producer()
        payload=B.prepare_platform_payload(directory,self.F.sources,'fixture-4','x86_64',**kwargs)
        self.assertEqual(payload['schemaVersion'],4);self.assertEqual(set(payload['files']),set(self.V.SIGNED_PLATFORM_FILES))
        self.assertEqual(len([e for e in events if e[0]=='capture']),1)
        self.assertEqual([e[1] for e in events if e[0]=='config-measure'],[('images.lock.json','runtime-manifest.json','approved-mirrors.json')])
        self.assertEqual((directory/'platform-sources.tar.gz').read_bytes(),self.F.captured.archive_bytes)
        self.assertEqual(json.loads((directory/'company-sources.json').read_bytes())['files'],self.F.manifest()['files'])
    def test_builder_refuses_missing_revision_adapter_and_wrong_catalog_before_output(self):
        for kind in ('revision','git','catalog'):
            self.F=Fixture(self.V,self.P)
            B,directory,events,kwargs=self.producer()
            if kind=='revision':kwargs['revision']='latest'
            if kind=='git':kwargs['git']=None
            if kind=='catalog':kwargs['source_module'].INSTALLER_RUNTIME_SOURCES=()
            with self.assertRaises(ValueError):B.prepare_platform_payload(directory,self.F.sources,'fixture-4','x86_64',**kwargs)
            self.assertEqual(set(os.listdir(directory)),set(self.V.DEPLOYMENT_FILES))
    def test_builder_existing_partial_artifact_preserved_before_capture(self):
        B,directory,events,kwargs=self.producer();(directory/'platform-sources.tar.gz').write_bytes(b'partial')
        with self.assertRaises(ValueError):B.prepare_platform_payload(directory,self.F.sources,'fixture-4','x86_64',**kwargs)
        self.assertEqual((directory/'platform-sources.tar.gz').read_bytes(),b'partial');self.assertEqual(events,[])
    def test_builder_lost_output_ack_preserves_partial_without_retry(self):
        B,directory,events,kwargs=self.producer();original=B._exclusive
        def write(path,raw):
            original(path,raw)
            if path.name=='platform-sources.json':raise OSError('lost-ack')
        with patch.object(B,'_exclusive',side_effect=write):
            with self.assertRaises(OSError):B.prepare_platform_payload(directory,self.F.sources,'fixture-4','x86_64',**kwargs)
        self.assertTrue((directory/'platform-sources.json').is_file())
        prior=list(events)
        with self.assertRaises(ValueError):B.prepare_platform_payload(directory,self.F.sources,'fixture-4','x86_64',**kwargs)
        self.assertEqual(events,prior)


def suite():
    output=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    for name in ProducerControls.__dict__:
        if name.startswith('test_'):output.addTest(ProducerControls(name))
    return output


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(suite());sys.exit(not result.wasSuccessful())
